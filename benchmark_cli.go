//go:build benchmark
package main

import "os"

var BUILD_TYPE = "benchmark"

func main() {
	if len(os.Args) > 1 {
		benchmark_client(os.Args[1])
	} else {
		benchmark_server("")
	}
}
