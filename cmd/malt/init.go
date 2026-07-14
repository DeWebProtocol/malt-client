package main

import (
	"fmt"

	clientconfig "github.com/dewebprotocol/malt-client/internal/config"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create trusted-client configuration",
	Args:  cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		cfg, err := clientconfig.Default()
		if err != nil {
			return err
		}
		path := cfgFile
		if path == "" {
			path, err = clientconfig.DefaultPath()
			if err != nil {
				return err
			}
		}
		if err := clientconfig.Write(path, cfg); err != nil {
			return err
		}
		fmt.Printf("Initialized MALT client config: %s\n", path)
		return nil
	},
}

func init() { rootCmd.AddCommand(initCmd) }
