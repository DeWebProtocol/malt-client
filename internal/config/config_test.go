package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndLoadPreserveClientBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := &Config{
		Gateway: GatewayConfig{BaseURL: "https://gateway.example.test/"},
		Daemon: DaemonConfig{
			SocketPath: filepath.Join(t.TempDir(), "client.sock"),
			StatePath:  filepath.Join(t.TempDir(), "roots.json"),
		},
	}
	if err := Write(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %#o, want 0600", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GatewayBaseURL() != "https://gateway.example.test" {
		t.Fatalf("gateway URL = %q", loaded.GatewayBaseURL())
	}
}

func TestLoadAppliesMissingDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"gateway":{"base_url":"http://127.0.0.1:9090"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Daemon.SocketPath == "" || loaded.Daemon.StatePath == "" {
		t.Fatalf("daemon defaults missing: %#v", loaded.Daemon)
	}
}
