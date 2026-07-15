package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/dewebprotocol/malt-client/application"
	clientconfig "github.com/dewebprotocol/malt-client/internal/config"
	client "github.com/dewebprotocol/malt-client/transport"
	cid "github.com/ipfs/go-cid"
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

func resolveTrustedRoot(raw string) (cid.Cid, string, error) {
	store, _, storeErr := openTrustStore()
	if storeErr != nil {
		return cid.Undef, "", storeErr
	}
	roots, err := application.NewRoots(store)
	if err != nil {
		return cid.Undef, "", err
	}
	selected, err := roots.Select(raw)
	if err != nil {
		return cid.Undef, "", err
	}
	return selected.Root, selected.Alias, nil
}

func printJSON(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}
