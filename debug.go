package main

import (
	"net/http"
	"net/http/httputil"
)

func dump_request(req *http.Request) {
	b, err := httputil.DumpRequest(req, false)
	if err != nil { panic(err) }
	log_debug("HTTP Header Request: "+string(b))
}

func dump_response(rsp *http.Response) {
	b, err := httputil.DumpResponse(rsp, false)
	if err != nil { panic(err) }
	log_debug("HTTP Header Response: "+string(b))
}
