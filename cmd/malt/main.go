package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:     "malt",
	Short:   "Trusted MALT client and UnixFS application",
	Version: version,
	Long: `malt is the trusted local client for MALT gateways.

It owns accepted roots, maps UnixFS paths into canonical MALT segments, verifies
resolve/read results locally, and binds returned payload bytes to authenticated
CIDs. Gateways and remote verify endpoints are never trust authorities.`,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "client config path")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
