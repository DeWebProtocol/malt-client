//go:build darwin || linux || dragonfly || freebsd || netbsd || openbsd

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientconfig "github.com/dewebprotocol/malt-client/internal/config"
)

func TestDaemonLifecycleCommandsPreflightSocketPathBeforeFilesystemSideEffects(t *testing.T) {
	previousConfig := cfgFile
	defer func() { cfgFile = previousConfig }()

	commands := map[string]struct {
		run                func() error
		precreateSocketDir bool
	}{
		"serve":   {run: func() error { return runDaemonServe(nil, nil) }},
		"start":   {run: func() error { return runDaemonStart(nil, nil) }},
		"status":  {run: func() error { return daemonStatusCmd.RunE(nil, nil) }},
		"stop":    {run: func() error { return daemonStopCmd.RunE(nil, nil) }, precreateSocketDir: true},
		"restart": {run: func() error { return runDaemonRestart(nil, nil) }},
	}
	for name, command := range commands {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			socketDir := filepath.Join(root, strings.Repeat("d", 160))
			socketPath := filepath.Join(socketDir, "client.sock")
			stateDir := filepath.Join(root, "state")
			if command.precreateSocketDir {
				if err := os.MkdirAll(socketDir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			cfg := clientconfig.Config{
				Gateway: clientconfig.GatewayConfig{BaseURL: "http://127.0.0.1:8080"},
				Daemon: clientconfig.DaemonConfig{
					SocketPath: socketPath,
					StatePath:  filepath.Join(stateDir, "roots.json"),
				},
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(root, "config.json")
			if err := os.WriteFile(configPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			cfgFile = configPath

			err = command.run()
			if err == nil || !strings.Contains(err.Error(), "configure a shorter daemon.socket_path") {
				t.Errorf("daemon %s error = %v, want actionable socket path preflight error", name, err)
			}
			if !command.precreateSocketDir {
				if _, statErr := os.Stat(socketDir); !os.IsNotExist(statErr) {
					t.Fatalf("daemon %s created socket directory before preflight: %v", name, statErr)
				}
			}
			if _, statErr := os.Stat(lifecycleLockPath(socketPath)); !os.IsNotExist(statErr) {
				t.Fatalf("daemon %s created lifecycle lock before preflight: %v", name, statErr)
			}
			if _, statErr := os.Stat(stateDir); !os.IsNotExist(statErr) {
				t.Fatalf("daemon %s created trust-store state before preflight: %v", name, statErr)
			}
		})
	}
}
