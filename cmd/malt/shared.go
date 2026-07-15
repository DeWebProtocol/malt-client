package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/dewebprotocol/malt-client/application"
	clientconfig "github.com/dewebprotocol/malt-client/internal/config"
	client "github.com/dewebprotocol/malt-client/transport"
)

func loadRuntimeConfig() (*clientconfig.Config, error) {
	return clientconfig.Load(cfgFile)
}

func gatewayClient() (*client.Client, error) {
	cfg, err := loadRuntimeConfig()
	if err != nil {
		return nil, err
	}
	return client.New(client.Options{BaseURL: cfg.GatewayBaseURL()})
}

func daemonCommandError(err error) error {
	var apiErr *client.Error
	if errors.As(err, &apiErr) {
		return fmt.Errorf("gateway request failed: %w", err)
	}
	return err
}

// rootsForSelector keeps explicit CIDs independent from the optional alias
// store. Only a non-CID selector can trigger trust-store I/O.
func rootsForSelector(raw string) (*application.Roots, error) {
	explicit := application.NewExplicitRootSelector()
	if _, err := explicit.Select(raw); err == nil {
		return explicit, nil
	}
	store, _, err := openTrustStore()
	if err != nil {
		return nil, err
	}
	return application.NewRoots(store)
}

func printJSON(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}
