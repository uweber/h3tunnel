//go:build server
package main

import (
	"bytes"

	"fmt"
	"net/netip"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

var BUILD_TYPE = "server"

func main() {
	get_server_config()

	log_info("Listening on UDP port %d", cfg.port);
	cfg.local_ip = ipam_init(cfg.ippool)
	cfg.routes = append(cfg.routes, cfg.local_ip)
	for _, route := range strings.Fields(cfg.addroutes) {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			log_err("Failed to parse additional route %s: %s", route, err.Error())
		} else {
			log_debug("Adding additional route %s/%d", prefix.Addr(), prefix.Bits())
			cfg.routes = append(cfg.routes, prefix)
		}
	}
	Server(cfg.listen, cfg.port);

	log_info("Waiting for all threads to stop")
	wg.Wait()
	log_info("Exiting")
}

func Upgrade(w http.ResponseWriter, r *http.Request) error {
	log_info("Upgrading HTTP request")
	dump_request(r)

	if r.Method != http.MethodConnect {
		return fmt.Errorf("expected CONNECT request, got %s", r.Method)
	}
	if r.Proto != "connect-ip" {
		return fmt.Errorf("unexpected protocol: %s", r.Proto)
	}
	w.Header().Add("capsule-protocol", "?1")
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	return nil
}

func basic_auth(r *http.Request) string {
	username, password, ok := r.BasicAuth()
	if !ok { return "" }

	ok = authenticate(username, password)
	if !ok {
		log_info("Failed authentication for %s from %s", username, r.RemoteAddr)
		return ""
	}

	return username
}

func Server(listen string, port int) {
	dev := create_tun()
	AddConnection(dev, DEFAULT_IP, "")
	setup_ip(ipam.network)

	listen = fmt.Sprintf("%s:%d", listen, port)

	handler := http.NewServeMux()
	handler.HandleFunc(MASQUE_PATH, func(w http.ResponseWriter, r *http.Request) {
		username := ""

		if cfg.client_auth {
			username = GetTLSUser(r.TLS)
		} else {
			username = basic_auth(r)
		}

		if username == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		log_info("User %s authenticated from %s", username, r.RemoteAddr)

		err := Upgrade(w, r)
		if err != nil {
			log_err("Upgrading failed: %s", err.Error())
			w.WriteHeader(500)
			return
		}
		wg.Add(1)
		go setup_tunnel(r.Body.(http3.HTTPStreamer).HTTPStream(), w.(http3.Datagrammer), username)
	})

	server := http3.Server{
		Addr: listen,
		QuicConfig: quic_cfg,
		EnableDatagrams: true,
		TLSConfig: generateTLSConfig(true),
		Handler: handler,
	}

	// Terminate HTTP3 server on exit
	go func() {
		<-cfg.done
		server.Close()
	}()

	// Start HTTP3 server
	err := server.ListenAndServe()
	if (err != nil && err != http.ErrServerClosed) {
		log_fatal("Cant listen on %s: %s", listen, err.Error())
	}

	dev.Close()
}

func setup_tunnel(str http3.Stream, datagrammer http3.Datagrammer, username string) {
	defer wg.Done()
	log_info("Setting up VPN tunnel over stream %d for %s", str.StreamID(), username)
	address_requested := false
	var client_ip *netip.Addr

	for {
                capsule, err := parse_ip_capsule(quicvarint.NewReader(str))
		if err != nil { break }
		if capsule == nil { continue }

		switch capsule.typ {
		case ADDRESS_REQUEST:
			if address_requested {
				log_warn("Multiple address requests not supported")
				continue
			}
			address_requested = true

			client_ip = ipam_get(capsule.address.Addr())
			AddConnection(datagrammer, *client_ip, username)

			if cfg.benchmark {
				go benchmark_client(client_ip.String())
			}

			var buf bytes.Buffer
			err := AssignAddress(&buf, 0, *client_ip)
			if err != nil { panic(err) }
			str.Write(buf.Bytes())

			for _, route := range cfg.routes {
				buf.Reset()
				err = AddressRange(&buf, route)
				if err != nil { panic(err) }
				str.Write(buf.Bytes())
			}

		default:
			log_warn("Ignoring unsupported capsule %d", capsule.typ)
		}
	}

	ipam_free(client_ip)
}
