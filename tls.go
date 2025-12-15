package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"time"
	"github.com/quic-go/quic-go"
)

var QUIC_ALPN = []string{"h3"}

var quic_cfg = &quic.Config {
	EnableDatagrams: true,
	KeepAlivePeriod: 20 * time.Second,
}

func generateTLSConfig(server bool) *tls.Config {
	tls_config := tls.Config { NextProtos: QUIC_ALPN }

	if (cfg.tls_cert != "" || cfg.tls_key != "") {
		if cfg.tls_cert == "" {
			log_fatal("TLS certificate not configured")
		}
		if cfg.tls_key == "" {
			cfg.tls_key = cfg.tls_cert
		}
		cert, err := tls.LoadX509KeyPair(cfg.tls_cert, cfg.tls_key)
		if err != nil {
			log_fatal("Failed to load TLS certificates: %s", err.Error())
		}
		tls_config.Certificates = []tls.Certificate{cert}
	}

	if cfg.tls_ca == "ignore" {
		tls_config.InsecureSkipVerify = true
	} else if cfg.tls_ca != "" {
		ca_pem, err := ioutil.ReadFile(cfg.tls_ca)
		if err != nil {
			log_fatal("Failed to load CA certificate: %s", err.Error())
		}
		ca_der, _ := pem.Decode(ca_pem)
		ca_cert, err := x509.ParseCertificate(ca_der.Bytes)
		if err != nil {
			log_fatal("Failed to parse CA certificate: %s", err.Error())
		}
		ca_pool := x509.NewCertPool()
		ca_pool.AddCert(ca_cert)
		tls_config.RootCAs = ca_pool
	}

	if cfg.client_auth {
		tls_config.ClientAuth = tls.RequireAndVerifyClientCert
		if tls_config.RootCAs == nil {
			log_fatal("CA must be configured for mutual TLS")
		}
		tls_config.ClientCAs = tls_config.RootCAs
	}

	return &tls_config
}

func GetTLSUser(state *tls.ConnectionState) string {
	if (state == nil || len(state.PeerCertificates) == 0) {
		return ""
	}

	cert := state.PeerCertificates[0]
	if len(cert.EmailAddresses) == 0 {
		return ""
	}
	return cert.EmailAddresses[0]
}
