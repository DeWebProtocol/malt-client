package main

import (
	"fmt"

	clientconfig "github.com/dewebprotocol/malt-client/internal/config"
	truststore "github.com/dewebprotocol/malt-client/trust"
	"github.com/spf13/cobra"
)

var rootGroupCmd = &cobra.Command{Use: "root", Short: "Manage locally accepted and candidate roots"}

var rootTrustCmd = &cobra.Command{
	Use:   "trust <alias> <root>",
	Short: "Explicitly trust a root for a local alias",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, cfg, err := openTrustStore()
		if err != nil {
			return err
		}
		profile, _ := cmd.Flags().GetString("profile")
		record, err := store.Trust(args[0], args[1], profile, cfg.GatewayBaseURL(), "explicit-cli")
		if err != nil {
			return err
		}
		printJSON(record)
		return nil
	},
}

var rootListCmd = &cobra.Command{
	Use:   "list",
	Short: "List trusted roots and unaccepted candidates",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, args []string) error {
		store, _, err := openTrustStore()
		if err != nil {
			return err
		}
		roots, err := store.List()
		if err != nil {
			return err
		}
		printJSON(map[string]any{"roots": roots})
		return nil
	},
}

var rootAcceptCmd = &cobra.Command{
	Use:   "accept <alias> <candidate-root>",
	Short: "Explicitly promote a recorded candidate root",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		store, _, err := openTrustStore()
		if err != nil {
			return err
		}
		record, err := store.AcceptCandidate(args[0], args[1], "explicit-cli")
		if err != nil {
			return err
		}
		printJSON(record)
		return nil
	},
}

func init() {
	rootTrustCmd.Flags().String("profile", "unixfs", "application profile associated with the root")
	rootGroupCmd.AddCommand(rootTrustCmd, rootListCmd, rootAcceptCmd)
	rootCmd.AddCommand(rootGroupCmd)
}

func openTrustStore() (*truststore.Store, *clientconfig.Config, error) {
	cfg, err := loadRuntimeConfig()
	if err != nil {
		return nil, nil, err
	}
	store, err := truststore.Open(cfg.Daemon.StatePath)
	if err != nil {
		return nil, nil, fmt.Errorf("open trust store: %w", err)
	}
	return store, cfg, nil
}
