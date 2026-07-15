package main

import (
	"fmt"

	"github.com/dewebprotocol/malt-client/application"
	client "github.com/dewebprotocol/malt-client/transport"
	unixfs "github.com/dewebprotocol/malt-client/unixfs"
	"github.com/spf13/cobra"
)

var statCmd = &cobra.Command{
	Use:   "stat <trusted-root|alias> [path]",
	Short: "Inspect a UnixFS path after local proof and payload verification",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runStat,
}

var catCmd = &cobra.Command{
	Use:   "cat <trusted-root|alias> [path]",
	Short: "Write locally verified UnixFS file bytes to stdout",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runCat,
}

var rmCmd = &cobra.Command{
	Use:   "rm <trusted-root|alias> <path>",
	Short: "Materialize an unaccepted root with one UnixFS path removed",
	Args:  cobra.ExactArgs(2),
	RunE:  runRemove,
}

func init() {
	catCmd.Flags().Uint64("offset", 0, "range start in bytes (requires --length)")
	catCmd.Flags().Uint64("length", 0, "range length in bytes (requires --offset)")
	rootCmd.AddCommand(statCmd, catCmd, rmCmd)
}

func newUnixFSReader(remote *client.Client) (unixfs.Reader, error) {
	return unixfs.NewReader(unixfs.ReaderOptions{Remote: remote, Blocks: remote})
}

func newUnixFSWriter(remote *client.Client) (unixfs.Writer, error) {
	lists, err := unixfs.NewGatewayMutationAdapter(remote)
	if err != nil {
		return nil, err
	}
	return unixfs.NewWriter(unixfs.WriterOptions{
		Remote: remote,
		Blocks: remote,
		Roots:  remote,
		Lists:  lists,
	})
}

func runStat(cmd *cobra.Command, args []string) error {
	remote, err := gatewayClient()
	if err != nil {
		return err
	}
	store, _, err := openTrustStore()
	if err != nil {
		return err
	}
	path := optionalPath(args)
	reader, err := newUnixFSReader(remote)
	if err != nil {
		return err
	}
	roots, err := application.NewRoots(store)
	if err != nil {
		return err
	}
	app, err := application.NewUnixFS(reader, nil, roots)
	if err != nil {
		return err
	}
	stat, err := app.Stat(cmd.Context(), args[0], path)
	if err != nil {
		return daemonCommandError(err)
	}
	printJSON(stat)
	return nil
}

func runCat(cmd *cobra.Command, args []string) error {
	offsetSet := cmd.Flags().Changed("offset")
	lengthSet := cmd.Flags().Changed("length")
	if offsetSet != lengthSet {
		return fmt.Errorf("--offset and --length must be provided together")
	}
	remote, err := gatewayClient()
	if err != nil {
		return err
	}
	store, _, err := openTrustStore()
	if err != nil {
		return err
	}
	reader, err := newUnixFSReader(remote)
	if err != nil {
		return err
	}
	roots, err := application.NewRoots(store)
	if err != nil {
		return err
	}
	app, err := application.NewUnixFS(reader, nil, roots)
	if err != nil {
		return err
	}
	var result *unixfs.ReadResult
	if offsetSet {
		offset, _ := cmd.Flags().GetUint64("offset")
		length, _ := cmd.Flags().GetUint64("length")
		result, err = app.ReadFileRange(cmd.Context(), args[0], optionalPath(args), offset, length)
	} else {
		result, err = app.ReadFile(cmd.Context(), args[0], optionalPath(args))
	}
	if err != nil {
		return daemonCommandError(err)
	}
	_, err = cmd.OutOrStdout().Write(result.Body)
	return err
}

func runRemove(cmd *cobra.Command, args []string) error {
	remote, err := gatewayClient()
	if err != nil {
		return err
	}
	store, _, err := openTrustStore()
	if err != nil {
		return err
	}
	writer, err := newUnixFSWriter(remote)
	if err != nil {
		return err
	}
	roots, err := application.NewRoots(store)
	if err != nil {
		return err
	}
	app, err := application.NewUnixFS(writer, writer, roots)
	if err != nil {
		return err
	}
	result, err := app.RemovePath(cmd.Context(), args[0], args[1])
	if err != nil {
		return daemonCommandError(err)
	}
	printJSON(result)
	return nil
}

func optionalPath(args []string) string {
	if len(args) > 1 {
		return args[1]
	}
	return ""
}
