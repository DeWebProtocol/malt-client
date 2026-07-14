//go:build !windows

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"time"
)

type daemonEndpointIdentity = os.FileInfo

func daemonHTTPClient(socketPath string) (*http.Client, *http.Transport) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socketPath)
	}}
	return &http.Client{Transport: transport, Timeout: time.Second}, transport
}

func captureDaemonEndpointIdentity(path string) (daemonEndpointIdentity, error) {
	return os.Lstat(path)
}

func removeDaemonEndpointIfMatch(path string, expected daemonEndpointIdentity) error {
	current, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if expected == nil || !os.SameFile(current, expected) {
		return nil
	}
	return os.Remove(path)
}

// removeSocketIfMatch keeps the v0.0.5 lifecycle helper available to existing
// package-level integrations while the common daemon code uses the portable
// endpoint spelling.
func removeSocketIfMatch(path string, expected os.FileInfo) error {
	return removeDaemonEndpointIfMatch(path, expected)
}
