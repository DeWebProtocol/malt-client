//go:build windows

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
	clientdaemon "github.com/dewebprotocol/malt-client/internal/daemon"
)

type daemonEndpointIdentity struct{}

func daemonHTTPClient(endpoint string) (*http.Client, *http.Transport) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return winio.DialPipeContext(ctx, clientdaemon.PipeName(endpoint))
	}}
	return &http.Client{Transport: transport, Timeout: time.Second}, transport
}

func captureDaemonEndpointIdentity(string) (daemonEndpointIdentity, error) {
	return daemonEndpointIdentity{}, nil
}

func removeDaemonEndpointIfMatch(string, daemonEndpointIdentity) error { return nil }

// removeSocketIfMatch is retained only so the cross-platform lifecycle test
// package compiles under GOOS=windows. Named pipes have no filesystem socket
// entry to unlink.
func removeSocketIfMatch(string, os.FileInfo) error { return nil }
