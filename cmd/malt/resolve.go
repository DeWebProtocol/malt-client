package main

import (
	"github.com/dewebprotocol/malt-client/application"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(resolveCmd)
}

var resolveCmd = &cobra.Command{
	Use:   "resolve <root> [path]",
	Short: "Resolve a path through a MALT structure",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runResolve,
}

func runResolve(cmd *cobra.Command, args []string) error {
	client, err := gatewayClient()
	if err != nil {
		return err
	}

	rawPath := ""
	if len(args) > 1 {
		rawPath = args[1]
	}
	reader, err := newUnixFSReader(client)
	if err != nil {
		return err
	}
	roots, err := rootsForSelector(args[0])
	if err != nil {
		return err
	}
	app, err := application.NewUnixFS(reader, nil, roots)
	if err != nil {
		return err
	}
	resolution, err := app.Resolve(cmd.Context(), args[0], rawPath)
	if err != nil {
		return daemonCommandError(err)
	}
	printJSON(&resolution.Result)
	return nil
}
