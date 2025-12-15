package main

import (
	"net/netip"
	"time"
)

type ipam_addr struct {
	ipaddr netip.Addr
	time time.Time
	used bool
}

var ipam struct {
	network netip.Prefix
	pool[] ipam_addr
}

func ipam_init(prefix string) netip.Prefix {
	network := netip.MustParsePrefix(prefix)

	max := 0
	if network.Addr().Is4() {
		if network.Bits() > 30 {
			panic("IPv4 network size must be at least /30")
		}
		max = (1 << (32 - network.Bits())) - 3
	} else if network.Addr().Is6() {
		if network.Bits() > 126 {
			panic("IPv6 network size must be at least /126")
		}
		if network.Bits() > 96 {
			max = (1 << (128 - network.Bits())) - 3
		} else {
			max = (1 << 32) - 3
		}
	}

	if max > cfg.max_pool_size {
		max = cfg.max_pool_size
	}

	// Start leases from beginning and skip network address
	base := network.Masked().Addr()
	base = base.Next()

	ipam.pool = nil
	for i := 0; i < max; i++ {
		base = base.Next()
		if base.Compare(network.Addr()) == 0 {
			base = base.Next()
		}
		ipam.pool = append(ipam.pool, ipam_addr{ ipaddr: base })
	}

	ipam.network = network
	log_info("Initalized IP address pool %s with %d addresses", ipam.network.String(), len(ipam.pool))
	return ipam.network
}

func ipam_get(want netip.Addr) *netip.Addr {
	for i := 0; i < len(ipam.pool); i++  {
		if (ipam.pool[i].used || ipam.pool[i].ipaddr.Is4() != want.Is4()) {
			continue
		}
		ipam.pool[i].time = time.Now()
		ipam.pool[i].used = true
		return &ipam.pool[i].ipaddr;
	}
	log_err("Cant find free IP address for %s", want.String())
	return nil
}

func ipam_free(ipaddr *netip.Addr) {
	if ipaddr == nil { return }
	for i := 0; i < len(ipam.pool); i++  {
		if ipaddr.Compare(ipam.pool[i].ipaddr) == 0 {
			ipam.pool[i].used = false
			return
		}
	}
	log_err("Cant find IP %s to free", ipaddr.String())
}
