package main

import (
	"bytes"
	"context"

	"os"
	"os/exec"
	"syscall"
	"fmt"
	"strings"
	"unsafe"
	"net/netip"
	"golang.org/x/sys/unix"
)

const (
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
)

type ifReq struct {
	Name  [0x10] byte
	Flags uint16
	pad   [0x28 - 0x10 - 2] byte
}

type tunDev struct {
	f *os.File
	name string
	tx_queue chan []byte
}

func (dev *tunDev) ReceiveMessage(ctx context.Context) ([]byte, error) {
	buf := make([]byte, cfg.mtu)
	buf_len, err := dev.f.Read(buf)
	return buf[:buf_len], err
}

func (dev *tunDev) SendMessage(data []byte) error {
	_, err := dev.f.Write(data)
	return err
}

func run_cmd(format string, a ...any) {
	cmd_line := fmt.Sprintf(format, a...)
	args := strings.Fields(cmd_line)
	cmd := exec.Command(args[0], args[1:]...)
	err := cmd.Run()
	if err == nil {
		log_debug("Executed command: %s", cmd_line)
	} else if !strings.Contains(cmd_line, "route del") {
		log_err("Failed to run command %s: %s", cmd_line, err.Error())
	}
}

func run_cmd_netns(format string, a ...any) {
	if cfg.netns != "" {
		format = fmt.Sprintf("ip netns exec %s %s", cfg.netns, format)
	}
	run_cmd(format, a...)
}

func setup_ip(ipaddr netip.Prefix) {
	log_info("Setting IP address %s on dev %s", ipaddr.String(), cfg.dev)
	run_cmd_netns("ip link set dev %s mtu %d", cfg.dev, cfg.mtu)
	run_cmd_netns("ip link set dev %s up", cfg.dev)
	run_cmd_netns("ip addr add %s dev %s", ipaddr.String(), cfg.dev)
}

var route_map_name = map[string]string {"add": "Installing", "del": "Removing"}
var route_map_family = map[bool]string {true: "inet6", false: "inet"}

func setup_default_route(mode string, prefix netip.Prefix, udp_port int) {
	family := route_map_family[prefix.Addr().Is6()]

	table := 100
	rule_prio := 10000

	log_info("%s default %s route on dev %s in table %d", route_map_name[mode], family, cfg.dev, table)

	// route local generated VPN traffic from local port
	run_cmd_netns("ip -f %s rule %s pri %d table main iif lo ipproto udp sport %d", family, mode, rule_prio, udp_port)

	// route direct attached networks, but skip default route
	rule_prio += 1
	run_cmd_netns("ip -f %s rule %s pri %d table main suppress_prefixlength 0", family, mode, rule_prio)

	// route default traffic via VPN
	rule_prio += 1
	run_cmd_netns("ip -f %s rule %s pri %d table %d not iif lo ipproto udp sport %d",
			family, mode, rule_prio, table, udp_port)
	run_cmd_netns("ip -f %s route %s default table %d dev %s",
			family, mode, table, cfg.dev)
}

func setup_route(mode string, prefix netip.Prefix, udp_port int) {
	if prefix.Bits() == 0 {
		setup_default_route(mode, prefix, udp_port)
		return
	}

	log_info("%s route %s/%d on dev %s", route_map_name[mode], prefix.Addr().String(), prefix.Bits(), cfg.dev)
	run_cmd_netns("ip route %s %s/%d dev %s", mode, prefix.Addr().String(), prefix.Bits(), cfg.dev)
}

func disable_redirects(dev string) {
	filename := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/send_redirects", dev)

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil { return }
	f.Write([]byte("0"))
	f.Close()
}

func create_tun() *tunDev {
	file, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil { panic(err) }

	var req ifReq
	copy(req.Name[:], cfg.dev)
	req.Flags = IFF_TUN | IFF_NO_PI
	log_debug("Openning tun device")
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(file), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 { panic(errno) }

	name_raw := bytes.Trim(req.Name[:len(req.Name)-1], "\x00")
	cfg.dev = string(name_raw)

	log_info("Created tun device %s", cfg.dev)
	if cfg.netns != "" {
		log_info("Moving tun device %s to netns %s", cfg.dev, cfg.netns)
		run_cmd("ip link set %s netns %s", cfg.dev, cfg.netns)
	}
	disable_redirects(cfg.dev)

	unix.SetNonblock(file, true)
	dev := tunDev {
		f:      os.NewFile(uintptr(file), cfg.dev),
		name:	cfg.dev,
		tx_queue: make(chan []byte),
	}
	return &dev
}

func (dev *tunDev) Close() error {
	log_debug("Closing tun device")
	return dev.f.Close()
}
