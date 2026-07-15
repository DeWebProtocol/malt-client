package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	clientconfig "github.com/dewebprotocol/malt-client/internal/config"
)

func TestExplicitCIDContentCommandsDoNotOpenBrokenTrustStore(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"forced gateway failure"}`))
	}))
	defer server.Close()

	temp := t.TempDir()
	statePath := filepath.Join(temp, "roots.json")
	if err := os.WriteFile(statePath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(temp, "config.json")
	if err := clientconfig.Write(configPath, &clientconfig.Config{
		Gateway: clientconfig.GatewayConfig{BaseURL: server.URL},
		Daemon: clientconfig.DaemonConfig{
			SocketPath: filepath.Join(temp, "client.sock"),
			StatePath:  statePath,
		},
	}); err != nil {
		t.Fatal(err)
	}
	previousConfig := cfgFile
	cfgFile = configPath
	defer func() { cfgFile = previousConfig }()
	statCmd.SetContext(t.Context())
	catCmd.SetContext(t.Context())
	rmCmd.SetContext(t.Context())

	root := mustParseCID(t, "bafkqaaa").String()
	tests := []struct {
		name string
		run  func() error
	}{
		{name: "stat", run: func() error { return runStat(statCmd, []string{root}) }},
		{name: "cat", run: func() error { return runCat(catCmd, []string{root}) }},
		{name: "rm", run: func() error { return runRemove(rmCmd, []string{root, "old.txt"}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := requests.Load()
			err := test.run()
			if err == nil {
				t.Fatal("command unexpectedly succeeded")
			}
			if strings.Contains(err.Error(), "trust store") || strings.Contains(err.Error(), "invalid character") {
				t.Fatalf("explicit CID touched broken trust store: %v", err)
			}
			if requests.Load() <= before {
				t.Fatalf("command did not reach gateway: %v", err)
			}
		})
	}
}
