package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dewebprotocol/malt-client/merkledag"
	cid "github.com/ipfs/go-cid"
	"github.com/spf13/cobra"
)

var merkleDAGCmd = &cobra.Command{
	Use:   "merkledag",
	Short: "Use IPFS-compatible Merkle DAG authentication",
	Long: `Use the gateway's Merkle DAG compatibility executor and replay all
CID/link evidence locally. These commands require an explicit Merkle DAG root
CID, never consult the MALT trust store, and never produce a ProofList.`,
}

var merkleDAGResolveCmd = &cobra.Command{
	Use:   "resolve <trusted-root-cid> [path]",
	Short: "Resolve and locally replay a Merkle DAG UnixFS path",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runMerkleDAGResolve,
}

var merkleDAGCatCmd = &cobra.Command{
	Use:   "cat <trusted-root-cid> [path]",
	Short: "Write locally replayed Merkle DAG UnixFS bytes to stdout",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runMerkleDAGCat,
}

func init() {
	merkleDAGCatCmd.Flags().Uint64("offset", 0, "range start in bytes (requires --length)")
	merkleDAGCatCmd.Flags().Uint64("length", 0, "range length in bytes (requires --offset)")
	merkleDAGCmd.AddCommand(merkleDAGResolveCmd, merkleDAGCatCmd)
	rootCmd.AddCommand(merkleDAGCmd)
}

func runMerkleDAGResolve(cmd *cobra.Command, args []string) error {
	root, segments, err := merkleDAGInputs(args)
	if err != nil {
		return err
	}
	remote, err := gatewayClient()
	if err != nil {
		return err
	}
	compatibility, err := merkledag.New(remote)
	if err != nil {
		return err
	}
	result, err := compatibility.ResolveMerkleDAGVerified(cmd.Context(), root, segments)
	if err != nil {
		return daemonCommandError(err)
	}
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func runMerkleDAGCat(cmd *cobra.Command, args []string) error {
	offsetSet := cmd.Flags().Changed("offset")
	lengthSet := cmd.Flags().Changed("length")
	if offsetSet != lengthSet {
		return fmt.Errorf("--offset and --length must be provided together")
	}
	root, segments, err := merkleDAGInputs(args)
	if err != nil {
		return err
	}
	remote, err := gatewayClient()
	if err != nil {
		return err
	}
	compatibility, err := merkledag.New(remote)
	if err != nil {
		return err
	}
	var offset, length *uint64
	if offsetSet {
		offsetValue, _ := cmd.Flags().GetUint64("offset")
		lengthValue, _ := cmd.Flags().GetUint64("length")
		offset, length = &offsetValue, &lengthValue
	}
	result, err := compatibility.ReadMerkleDAGVerified(cmd.Context(), root, segments, offset, length)
	if err != nil {
		return daemonCommandError(err)
	}
	_, err = cmd.OutOrStdout().Write(result.Data)
	return err
}

func merkleDAGInputs(args []string) (cid.Cid, []string, error) {
	root, err := cid.Parse(args[0])
	if err != nil {
		return cid.Undef, nil, fmt.Errorf("invalid caller-selected Merkle DAG root CID: %w", err)
	}
	rawPath := ""
	if len(args) > 1 {
		rawPath = args[1]
	}
	segments := []string{}
	if rawPath != "" {
		if strings.HasPrefix(rawPath, "/") || strings.HasSuffix(rawPath, "/") {
			return cid.Undef, nil, fmt.Errorf("Merkle DAG path must be relative and must not end with /")
		}
		segments = strings.Split(rawPath, "/")
		for _, segment := range segments {
			if segment == "" || segment == "." || segment == ".." || len(segment) > 1024 || strings.ContainsRune(segment, 0) {
				return cid.Undef, nil, fmt.Errorf("invalid Merkle DAG path segment %q", segment)
			}
		}
	}
	return root, segments, nil
}
