// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

var (
	adminSocket    string
	requestTimeout time.Duration
)

func init() {
	flag.StringVar(&adminSocket, "admin-socket", "", "Path to the envoy admin socket")
	flag.DurationVar(&requestTimeout, "request-timeout", 2*time.Second, "Envoy admin request timeout")
}

func fatalUsage(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	flag.Usage()
	os.Exit(1)
}

func main() {
	flag.Parse()

	if adminSocket == "" {
		fatalUsage("--admin-socket must be set")
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, "unix", adminSocket)
		},
	}
	defer transport.CloseIdleConnections()

	client := http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}

	resp, err := client.Get("http://envoy-admin/ready")
	if err != nil {
		log.Fatalf("Envoy ready request failed: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Envoy returned non-OK status code: %d", resp.StatusCode)
	}
}
