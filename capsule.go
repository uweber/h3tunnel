package main

import (
	"bytes"
	"errors"
	"io"
	"net/netip"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/gaissmai/extnetip"
)

const (
	DATAGRAM =		0x00
	ADDRESS_ASSIGN =	0x01
	ADDRESS_REQUEST =	0x02
	ROUTE_ADVERTISEMENT =	0x03
)

type capsule struct {
	typ http3.CapsuleType
	address netip.Prefix
	protocol int
}

/*
Assigned Address {
  Request ID (i),
  IP Version (8),
  IP Address (32..128),
  IP Prefix Length (8),
}

Requested Address {
  Request ID (i),
  IP Version (8),
  IP Address (32..128),
  IP Prefix Length (8),
}

IP Address Range {
  IP Version (8),
  Start IP Address (32..128),
  End IP Address (32..128),
  IP Protocol (8),
}
*/

func read_bytes(r io.Reader, buf []byte) error {
	want := len(buf)
	n, err := io.ReadFull(r, buf)
	if err != nil { return err }
	if n != want { errors.New("Invalid size read") }
	return nil
}

func parse_uint8(r io.Reader) (uint8, error) {
	buf := make([]byte, 1)
	err := read_bytes(r, buf)
	if err != nil { return 0, err }
	return buf[0], nil
}

func parse_addr4(r io.Reader) (netip.Addr, error) {
	buf := make([]byte, 4)
	err := read_bytes(r, buf)
	if err != nil { return DEFAULT_IP, err }
	addr, ok := netip.AddrFromSlice(buf)
	if !ok { return DEFAULT_IP, errors.New("Failed to parse IPv4 address") }
	return addr, nil
}

func parse_addr6(r io.Reader) (netip.Addr, error) {
	buf := make([]byte, 16)
	err := read_bytes(r, buf)
	if err != nil { return DEFAULT_IP, err }
	addr, ok := netip.AddrFromSlice(buf)
	if !ok { return DEFAULT_IP, errors.New("Failed to parse IPv6 address") }
	return addr, nil
}

func parse_address(r io.Reader) (netip.Prefix, error) {
	var addr_net netip.Prefix
	var addr netip.Addr
	var prefix uint8

	version, err := parse_uint8(r)
	if err != nil { return addr_net, err }

	switch version {
	case 4:
		addr, err = parse_addr4(r)
	case 6:
		addr, err = parse_addr6(r)
	default:
		err = errors.New("Unknown IP address version")
	}

	if err == nil {
		prefix, err = parse_uint8(r)
	}
	if err == nil {
		addr_net = netip.PrefixFrom(addr, int(prefix))
		if addr_net.Bits() == -1 {
			err = errors.New("Invalid prefix bit size")
		}
	}

	return addr_net, err
}

func parse_address_range(r io.Reader) (netip.Prefix, uint8, error) {
	var start, end netip.Addr
	var prefix netip.Prefix
	var proto uint8
	var ok bool

	version, err := parse_uint8(r)
	if err != nil { return prefix, proto, err }

	switch version {
	case 4:
		start, err = parse_addr4(r)
		if err != nil { return prefix, proto, err }
		end, err = parse_addr4(r)
		if err != nil { return prefix, proto, err }
	case 6:
		start, err = parse_addr6(r)
		if err != nil { return prefix, proto, err }
		end, err = parse_addr6(r)
		if err != nil { return prefix, proto, err }
	default:
		err = errors.New("Unknown IP address version")
		return prefix, proto, err
	}

	if err == nil {
		prefix, ok = extnetip.Prefix(start, end)
		if !ok {
			err = errors.New("Failed to get prefix from range "+start.String()+"-"+end.String())
			return prefix, proto, err
		}
		proto, err = parse_uint8(r)
	}

	return prefix, proto, err
}

func parse_ip_capsule(r quicvarint.Reader) (*capsule, error) {
	capsule_type, ior, err := http3.ParseCapsule(r)
	if err != nil { return nil, err }

	val, err := io.ReadAll(ior)
	log_debug("Parsing HTTP capsule with type %d and len %d", capsule_type, len(val))
	r = bytes.NewReader(val)

	switch capsule_type {
	case DATAGRAM:
		// nothing to do
	case ADDRESS_ASSIGN:
		reqid, err := quicvarint.Read(quicvarint.NewReader(r))
		if err != nil { return nil, err }
		addr, err := parse_address(r)
		if err != nil { return nil, err }
		log_debug("IP capsule: Assign %d %s", reqid, addr.String())
		return &capsule{ typ: capsule_type, address: addr }, nil
	case ADDRESS_REQUEST:
		reqid, err := quicvarint.Read(quicvarint.NewReader(r))
		if err != nil { return nil, err }
		addr, err := parse_address(r)
		if err != nil { return nil, err }
		log_debug("IP capsule: Request %d %s", reqid, addr.String())
		return &capsule{ typ: capsule_type, address: addr }, nil
	case ROUTE_ADVERTISEMENT:
		prefix, proto, err := parse_address_range(r)
		if err != nil { return nil, err }
		log_debug("IP capsule: Route %s %d", prefix.String(), proto)
		return &capsule{ typ: capsule_type, address: prefix }, nil
	default:
		log_warn("Unsupported capsule type receeived: %d", capsule_type)
	}

	return nil, nil
}

func get_family(addr netip.Addr) (uint8, uint8) {
	if addr.Is4() {
		return 4, 32
	} else if addr.Is6() {
		return 6, 128
	}
	panic("Invalid IP address")
}

func AssignAddress(w quicvarint.Writer, reqid int, addr netip.Addr) error {
	family, length := get_family(addr)

	b := quicvarint.Append(nil, uint64(reqid))
	b = append(b, family)
	b = append(b, addr.AsSlice()...)
	b = append(b, length)

	return http3.WriteCapsule(w, ADDRESS_ASSIGN, b)
}

func RequestAddress(w quicvarint.Writer, reqid int, addr netip.Addr) error {
	family, length := get_family(addr)
	if reqid == 0 { panic("RequestAddress ID must not be zero") }

	b := quicvarint.Append(nil, uint64(reqid))
	b = append(b, family)
	b = append(b, addr.AsSlice()...)
	b = append(b, length)

	return http3.WriteCapsule(w, ADDRESS_REQUEST, b)
}

func AddressRange(w quicvarint.Writer, prefix netip.Prefix) error {
	first, last := extnetip.Range(prefix)
	family, _ := get_family(first)

	b := make([]byte, 0)
	b = append(b, family)
	b = append(b, first.AsSlice()...)
	b = append(b, last.AsSlice()...)
	b = append(b, uint8(0))

	return http3.WriteCapsule(w, ROUTE_ADVERTISEMENT, b)
}
