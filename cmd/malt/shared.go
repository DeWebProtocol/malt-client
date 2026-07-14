package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	clientconfig "github.com/dewebprotocol/malt-client/internal/config"
	daemonclient "github.com/dewebprotocol/malt-client/internal/gateway"
)

func loadRuntimeConfig() (*clientconfig.Config, error) {
	return clientconfig.Load(cfgFile)
}

func gatewayClient() (*daemonclient.Client, error) {
	cfg, err := loadRuntimeConfig()
	if err != nil {
		return nil, err
	}
	return daemonclient.NewWithBaseURL(cfg.GatewayBaseURL()), nil
}

func daemonCommandError(err error) error {
	var apiErr *daemonclient.Error
	if errors.As(err, &apiErr) {
		return fmt.Errorf("gateway request failed: %w", err)
	}
	return err
}

func printJSON(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}
