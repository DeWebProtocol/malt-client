// Package config owns trusted-client process configuration. Server storage,
// ArcSet persistence, and proof-generation settings deliberately do not appear
// here.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultGatewayURL = "http://127.0.0.1:8080"
)

type Config struct {
	Gateway   GatewayConfig   `json:"gateway"`
	Daemon    DaemonConfig    `json:"daemon"`
	Workspace WorkspaceConfig `json:"workspace"`
}

type GatewayConfig struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key,omitempty"`
	Bucket  string `json:"bucket,omitempty"`
}

type WorkspaceConfig struct {
	StatePath string `json:"state_path"`
}

type DaemonConfig struct {
	SocketPath string `json:"socket_path"`
	StatePath  string `json:"state_path"`
}

func Default() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("determine home directory: %w", err)
	}
	root := filepath.Join(home, ".malt-client")
	return &Config{
		Gateway: GatewayConfig{BaseURL: defaultGatewayURL},
		Daemon: DaemonConfig{
			SocketPath: filepath.Join(root, "client.sock"),
			StatePath:  filepath.Join(root, "roots.json"),
		},
		Workspace: WorkspaceConfig{StatePath: filepath.Join(root, "buckets.json")},
	}, nil
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	return filepath.Join(home, ".malt-client", "config.json"), nil
}

func Load(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return nil, err
		}
	}
	defaults, err := Default()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return defaults, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read client config: %w", err)
	}
	if err := json.Unmarshal(data, defaults); err != nil {
		return nil, fmt.Errorf("decode client config: %w", err)
	}
	defaults.applyDefaults()
	if err := defaults.Validate(); err != nil {
		return nil, err
	}
	return defaults, nil
}

func Write(path string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("client config is nil")
	}
	if strings.TrimSpace(path) == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return err
		}
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create client config directory: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write client config: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure client config permissions: %w", err)
	}
	return nil
}

func (c *Config) applyDefaults() {
	defaults, _ := Default()
	if c.Gateway.BaseURL == "" {
		c.Gateway.BaseURL = defaults.Gateway.BaseURL
	}
	if c.Daemon.SocketPath == "" {
		c.Daemon.SocketPath = defaults.Daemon.SocketPath
	}
	if c.Daemon.StatePath == "" {
		c.Daemon.StatePath = defaults.Daemon.StatePath
	}
	if c.Workspace.StatePath == "" {
		c.Workspace.StatePath = defaults.Workspace.StatePath
	}
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.Gateway.BaseURL) == "" {
		return fmt.Errorf("gateway base URL is empty")
	}
	if c.Daemon.SocketPath == "" || c.Daemon.StatePath == "" {
		return fmt.Errorf("daemon socket and state paths are required")
	}
	if c.Workspace.StatePath == "" {
		return fmt.Errorf("Bucket workspace state path is required")
	}
	if strings.TrimSpace(c.Gateway.Bucket) != "" && strings.TrimSpace(c.Gateway.APIKey) == "" {
		return fmt.Errorf("gateway Bucket requires an API key")
	}
	return nil
}

func (c *Config) GatewayBaseURL() string { return strings.TrimRight(c.Gateway.BaseURL, "/") }
