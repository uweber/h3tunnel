//go:build client
package main

import (
	"bytes"
	"strconv"
	"net"
	"net/netip"
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

var BUILD_TYPE = "client"

func main() {
	get_client_config()

	if cfg.hostname == "" {
		cfg.hostname = read_stdin("Hostname")
	}
	if cfg.username == "" {
		cfg.username = read_stdin("Username")
	}
	if cfg.password == "" {
		cfg.password = read_stdin("Password")
	}

	if cfg.benchmark {
		go benchmark_server(cfg.netns)
	}

	log_info("Connecting to %s:%d", cfg.hostname, cfg.port);
	Client(cfg.hostname, cfg.port)

	log_info("Waiting for all threads to stop")
	wg.Wait()
	log_info("Exiting")
}

func Client(hostname string, port int) {
	dev := create_tun()

	rt := &http3.RoundTripper{
		QuicConfig: quic_cfg,
		EnableDatagrams: true,
		TLSClientConfig: generateTLSConfig(true),
	}

	reqHdr := http.Header{}
	reqHdr.Set("capsule-protocol", "?1")
	req := http.Request{
		Method: http.MethodConnect,
		Header: reqHdr,
		Proto: "connect-ip",
		URL: &url.URL{
			Host: net.JoinHostPort(hostname, strconv.Itoa(port)),
			Scheme: "https",
			Path: MASQUE_PATH,
		},
	}

	req.SetBasicAuth(cfg.username, cfg.password)

	client := &http.Client{
		Transport: rt,
	}

	datagrammer, respChan, err := client.Transport.(*http3.RoundTripper).RoundTripWithDatagrams(&req, http3.RoundTripOpt{DontCloseRequestStream: true})
	if err != nil { log_fatal("Cant connect: %s", err.Error()) }
	rsp := <-respChan
	if rsp.Err != nil { log_fatal("Failed to connect: %s", rsp.Err.Error()) }

	dump_response(rsp.Resp)
	if rsp.Resp.StatusCode != http.StatusOK {
		log_err("Failed HTTP request: %d %s", rsp.Resp.StatusCode, http.StatusText(rsp.Resp.StatusCode))
		return
	}

	str := rsp.Resp.Body.(http3.HTTPStreamer).HTTPStream()
	qconn := rsp.Resp.Body.(http3.Hijacker).StreamCreator()

	wg.Add(1)
	go setup_tunnel(str, dev, datagrammer, qconn.LocalAddr().(*net.UDPAddr).Port)

	<-cfg.done
	rt.Close()
	dev.Close()
}

func setup_tunnel(str http3.Stream, local http3.Datagrammer, remote http3.Datagrammer, port int) {
	defer wg.Done()
	log_info("Setting up VPN tunnel over stream %d from port %d", str.StreamID(), port)
	var request_id = 1
	var conn *Connection

	log_info("Requesting IP address with id %d", request_id)
	var buf bytes.Buffer
	err := RequestAddress(&buf, request_id, netip.MustParseAddr(cfg.iprequest))
	if err != nil { panic(err) }
	str.Write(buf.Bytes())

	str_reader := quicvarint.NewReader(str)
	for {
		capsule, err := parse_ip_capsule(str_reader)
		if err != nil { break }
		if capsule == nil { continue }

		switch capsule.typ {
		case ADDRESS_ASSIGN:
			AddConnection(local, capsule.address.Addr(), "")
			conn = AddConnection(remote, DEFAULT_IP, "")
			conn.port = port
			setup_ip(capsule.address)

		case ROUTE_ADVERTISEMENT:
			if conn == nil {
				log_err("Ignoring route advertisement without address assignment")
				continue;
			}
			conn.routes = append(conn.routes, capsule.address)
			setup_route("add", capsule.address, port)

		default:
			log_warn("Ignoring unsupported capsule %d", capsule.typ)
		}
	}

	if conn != nil {
		log_info("Shutting down VPN connection with rx %s / tx %s",
			get_byte_unit(conn.rx_bytes, 0), get_byte_unit(conn.tx_bytes, 0))
	}
}

