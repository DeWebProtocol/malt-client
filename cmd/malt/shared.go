package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	client "github.com/dewebprotocol/malt-client/client"
	clientconfig "github.com/dewebprotocol/malt-client/internal/config"
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
	root, err := cid.Parse(raw)
	if err == nil {
		return root, "", nil
	}
	store, _, storeErr := openTrustStore()
	if storeErr != nil {
		return cid.Undef, "", storeErr
	}
	record, storeErr := store.Get(raw)
	if storeErr != nil {
		return cid.Undef, "", fmt.Errorf("%q is neither a CID nor a trusted-root alias: %w", raw, storeErr)
	}
	root, err = cid.Parse(record.AcceptedRoot)
	if err != nil {
		return cid.Undef, "", fmt.Errorf("trusted alias %q contains an invalid root: %w", raw, err)
	}
	return root, record.Alias, nil
}

func printJSON(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}
