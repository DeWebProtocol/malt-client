package main

import (
	"fmt"

	malt "github.com/dewebprotocol/malt"
	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/protocol"
	clientverifier "github.com/dewebprotocol/malt/sdk/verifier"
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
	root, _, err := resolveTrustedRoot(args[0])
	if err != nil {
		return err
	}
	segments, err := unixfsmodel.ParsePath(rawPath)
	if err != nil {
		return err
	}
	request, err := protocol.NewResolveRequest(malt.ResolveRequest{Root: root, Segments: segments})
	if err != nil {
		return err
	}
	result, err := client.ResolveContract(cmd.Context(), request)
	if err != nil {
		return daemonCommandError(err)
	}
	verifier, err := clientverifier.NewDefault()
	if err != nil {
		return fmt.Errorf("initialize local verifier: %w", err)
	}
	if err := verifier.VerifyResolve(cmd.Context(), protocol.ResolveVerification{Request: request, Result: *result}); err != nil {
		return fmt.Errorf("verify resolve result locally: %w", err)
	}

	return printResolveResult(cmd, result)
}

func printResolveResult(cmd *cobra.Command, result *protocol.ResolveResult) error {
	printJSON(result)
	return nil
}
