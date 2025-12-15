package main

import (
	"bufio"
	"net"
	"runtime"
	"time"

	"github.com/vishvananda/netns"
)

const BENCHMARK_PORT = "9109"
const BUFFER_SIZE = 4096*1024
const RUN_TIME = 10

func handle_connection(conn net.Conn) {
	running := true
	rx_bytes := 0
	tx_bytes := 0

	go func() {
		reader := bufio.NewReaderSize(conn, BUFFER_SIZE)
		for running {
			n, err := reader.Discard(BUFFER_SIZE)
			if err != nil { break }
			rx_bytes += n
		}
	}()

	go func() {
		writer := bufio.NewWriterSize(conn, BUFFER_SIZE)
		buf := make([]byte, BUFFER_SIZE)
		for running {
			n, err := writer.Write(buf)
			if err != nil { break }
			tx_bytes += n
		}
	}()

	time.Sleep(RUN_TIME * time.Second)
	running = false

	log_info("Benchmark %s transmitted RX %s TX %s", conn.RemoteAddr().String(), get_byte_unit(rx_bytes, RUN_TIME), get_byte_unit(tx_bytes, RUN_TIME))
}

func benchmark_client(dest string) {
	time.Sleep(time.Second)
	log_info("Connecting to %s", dest)
	conn, err := net.Dial("tcp", dest+":"+BENCHMARK_PORT)
	if err != nil {
		log_err("Failed to run benchmark: %s", err.Error())
		return
	}
	handle_connection(conn)
}

func switch_netns(namespace string) {
	if namespace == "" { return }
	log_info("Switching benchmark thread to netns %s", namespace)
	ns, err := netns.GetFromName(namespace)
	if err != nil { panic(err) }

	runtime.LockOSThread()
	err = netns.Set(ns)
	if err != nil { panic(err) }
}

func benchmark_server(namespace string) {
	log_info("Starting server on %s", BENCHMARK_PORT)
	switch_netns(namespace)
	listen, err := net.Listen("tcp", ":"+BENCHMARK_PORT)
	if err != nil {
		log_err("Failed to run benchmark: %s", err.Error())
		return
	}
	for {
		conn, err := listen.Accept()
		if err != nil {
			log_err("Failed to accept benchmark socket: %s", err.Error())
			continue
		}
		log_info("New connection from %s", conn.RemoteAddr().String())
		go handle_connection(conn)
	}
}
