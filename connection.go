package main

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
	"github.com/quic-go/quic-go/http3"
)

type Connection struct {
	id int
	ip netip.Addr
	validate_src bool
	routes[] netip.Prefix
	port int

	user string
	time time.Time

	rx_bytes int
	tx_bytes int

	datagrammer http3.Datagrammer
	tx_queue chan []byte
}
var connection_ids int
var connections map[netip.Addr](Connection)
var connection_sync sync.RWMutex

var DEFAULT_IP = netip.MustParseAddr("0.0.0.0")

func init() {
	connections = make(map[netip.Addr](Connection))
}

func get_byte_unit(bytes int, time int) string {
	units := []string { "K", "M", "G", "T", "P" }
	unit := ""

	total := float64(bytes)
	if time != 0 {
		total = float64(bytes * 8 / time)
	}

	for i := 0; (i < len(units) && total >= 1000); i++ {
		total /= 1000
		unit = units[i]
	}

	if time == 0 {
		return fmt.Sprintf("%.2f %sB", total, unit)
	} else {
		return fmt.Sprintf("%.2f %sbit/s", total, unit)
	}
}

func get_connection_id () int {
	connection_ids += 1
	if (connection_ids == 0) { panic("Run out of connection IDs") }
	return connection_ids
}

func AddConnection(datagrammer http3.Datagrammer, addr netip.Addr, user string) *Connection {
	connection_sync.Lock()
	connection := Connection {
		id: get_connection_id(),
		ip: addr,
		user: user,
		time: time.Now(),
		datagrammer: datagrammer,
		tx_queue: make(chan []byte) }
	_, ok := connections[addr]
	if ok { panic("IP address "+addr.String()+" already in connection table") }
	connections[addr] = connection
	connection_sync.Unlock()
	if user != "" {
		log_info("User %s connected", user)
		connection.validate_src = true
	}

	wg.Add(2)
	go connection.Receive()
	go connection.Transmit()

	return &connection
}

func DelConnection(conn *Connection) {
	if conn.user != "" {
		log_info("User %s disconnected with rx %s / tx %s", conn.user, get_byte_unit(conn.rx_bytes, 0), get_byte_unit(conn.tx_bytes, 0))
	}
	connection_sync.Lock()
	delete(connections, conn.ip)
	connection_sync.Unlock()
	for _, route := range conn.routes {
		setup_route("del", route, conn.port)
	}
}

func (c *Connection) Receive() {
	defer wg.Done()

	log_debug("Starting loop for connection %d", c.id)
	ctx := context.Background()

	for {
		pkt, err := c.datagrammer.ReceiveMessage(ctx)
		if err != nil {
			log_err("Cant receive packet on connection %d: %s", c.id, err.Error());
			break
		}
		n := len(pkt)
		c.rx_bytes += n
		log_debug("Received packet on connection %d with len %d", c.id, n)

		// skip invalid packets, 20 is minimum for IPv4
		if n < 20 {
			log_err("Ignoring short packet with size %d", n)
			continue
		}

		var src_ip netip.Addr
		var dst_ip netip.Addr

		version := int(pkt[0] >> 4)
		if version == 4 {
			src_ip = netip.AddrFrom4(([4]byte)(pkt[12:]))
			dst_ip = netip.AddrFrom4(([4]byte)(pkt[16:]))
		} else if version == 6 {
			if n < 40 {
				log_err("Ignoring short IPv6 packet with size %d", n)
				return
			}
			src_ip = netip.AddrFrom16(([16]byte)(pkt[8:]))
			dst_ip = netip.AddrFrom16(([16]byte)(pkt[24:]))
		} else {
			log_err("Invalid packet received with IP version %d", version)
			return
		}

		if (c.validate_src && c.ip.Compare(src_ip) != 0) {
			log_debug("Dropping spoofed packet with SRC IP %s instead of %s", src_ip.String(), c.ip.String())
			continue
		}

		connection_sync.RLock()
		forward, ok := connections[dst_ip]
		if !ok {
			log_debug("Cant find route for %s using default", dst_ip.String())
			forward, ok = connections[DEFAULT_IP]
		}
		connection_sync.RUnlock()

		if !ok {
			log_debug("Cant find destination for packet")
		} else if forward.id == c.id {
			log_debug("Dropping packet with identical ingress and outgress route: %d", forward.id)
		} else {
			log_debug("Forwarding packet %s %d -> %s %d", src_ip, c.id, dst_ip, forward.id)
			forward.tx_queue <- pkt
		}
	}

	close(c.tx_queue)
}

func (c *Connection) Transmit() {
	defer wg.Done()

	for {
		data, running := <- c.tx_queue
		if !running {
			break
		}
		err := c.datagrammer.SendMessage(data)

		if err != nil {
			log_err("Cant send packet on connection %d with len %d - %s", c.id, len(data), err.Error())
			time.Sleep(1 * time.Second)
			continue
		}
		c.tx_bytes += len(data)
	}

	DelConnection(c)
}
