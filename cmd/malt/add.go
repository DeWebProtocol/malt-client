package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dewebprotocol/malt-client/application"
	gatewayclient "github.com/dewebprotocol/malt-client/transport"
	cid "github.com/ipfs/go-cid"
	"github.com/spf13/cobra"
)

var (
	addPrefixFlag       string
	addWrapFlag         bool
	addWrapNameFlag     string
	addTargetFlag       string
	addModelFlag        string
	addLayoutFlag       string
	addFileLayoutFlag   string
	addDirLayoutFlag    string
	addNoGitignoreFlag  bool
	addNoMaltignoreFlag bool
	addIgnoreFileFlags  []string
	addRootFlag         string
	addAliasFlag        string
	addJSONFlag         bool
)

func init() {
	rootCmd.AddCommand(addCmd)
	addCmd.Flags().StringVarP(&addPrefixFlag, "prefix", "p", "", "Prefix inside the result tree")
	addCmd.Flags().BoolVarP(&addWrapFlag, "wrap", "w", false, "Wrap all inputs under one directory")
	addCmd.Flags().StringVar(&addWrapNameFlag, "wrap-name", "", "Wrapper directory name (required for multi-input --wrap)")
	addCmd.Flags().StringVar(&addTargetFlag, "target", addTargetMALT, "Target substrate: malt or merkle-dag")
	addCmd.Flags().StringVar(&addModelFlag, "model", addModelUnixFS, "Source data model/schema")
	addCmd.Flags().StringVar(&addLayoutFlag, "layout", "", "MALT UnixFS materialization layout: hybrid")
	addCmd.Flags().StringVar(&addFileLayoutFlag, "file-layout", "", "Merkle DAG UnixFS file layout: balanced or trickle")
	addCmd.Flags().StringVar(&addDirLayoutFlag, "dir-layout", "", "Merkle DAG UnixFS directory layout: basic, hamt, or adaptive")
	addCmd.Flags().BoolVar(&addNoGitignoreFlag, "no-gitignore", false, "Do not read .gitignore files while adding directories")
	addCmd.Flags().BoolVar(&addNoMaltignoreFlag, "no-maltignore", false, "Do not read .maltignore files while adding directories")
	addCmd.Flags().StringArrayVar(&addIgnoreFileFlags, "ignore-file", nil, "Additional gitignore-style ignore file to apply while adding directories")
	addCmd.Flags().StringVar(&addRootFlag, "root", "", "Base root CID to add files under (creates a new root if empty)")
	addCmd.Flags().StringVar(&addAliasFlag, "alias", "", "Trusted-root alias to update; the result is recorded as an untrusted candidate")
	addCmd.Flags().BoolVar(&addJSONFlag, "json", false, "Emit the candidate-root summary as JSON")
}

var addCmd = &cobra.Command{
	Use:   "add <local-path> [<local-path>...]",
	Short: "Upload local files/directories from a base root to a result root",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runAdd,
}

type addSummary struct {
	Target           string `json:"target,omitempty"`
	Model            string `json:"model,omitempty"`
	Layout           string `json:"layout,omitempty"`
	FileLayout       string `json:"file_layout,omitempty"`
	DirLayout        string `json:"dir_layout,omitempty"`
	OldRoot          string `json:"old_root,omitempty"`
	NewRoot          string `json:"new_root"`
	Files            int    `json:"files_imported"`
	Bytes            int64  `json:"bytes_uploaded"`
	ImmutableObjects int    `json:"immutable_objects_written,omitempty"`
	MALTObjects      int    `json:"malt_objects_written,omitempty"`
	MALTMaps         int    `json:"malt_maps_written,omitempty"`
	MALTLists        int    `json:"malt_lists_written,omitempty"`
	ArcSets          int    `json:"arcsets_written,omitempty"`
	Arcs             int    `json:"arcs_written,omitempty"`
	SymlinkRoots     int    `json:"symlink_roots,omitempty"`
}

func runAdd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	opts, err := normalizeAddBuildOptions(addBuildOptions{
		Prefix:     addPrefixFlag,
		Wrap:       addWrapFlag,
		WrapName:   addWrapNameFlag,
		Target:     addTargetFlag,
		Model:      addModelFlag,
		Layout:     addLayoutFlag,
		FileLayout: addFileLayoutFlag,
		DirLayout:  addDirLayoutFlag,
		Ignore: addIgnoreOptions{
			NoGitignore:  addNoGitignoreFlag,
			NoMaltignore: addNoMaltignoreFlag,
			IgnoreFiles:  addIgnoreFileFlags,
		},
	})
	if err != nil {
		return err
	}
	casClient, err := makeCASClient()
	if err != nil {
		return err
	}

	var remote *gatewayclient.Client
	var roots *application.Roots
	workingRoot := strings.TrimSpace(addRootFlag)
	var candidateStoreAlias string
	if opts.Target == addTargetMerkleDAG && (workingRoot != "" || strings.TrimSpace(addAliasFlag) != "") {
		return fmt.Errorf("--root and --alias are only supported with --target malt")
	}
	if opts.Target == addTargetMALT && addAliasFlag != "" {
		if workingRoot != "" {
			return fmt.Errorf("--alias and --root cannot be used together")
		}
		store, _, err := openTrustStore()
		if err != nil {
			return err
		}
		roots, err = application.NewRoots(store)
		if err != nil {
			return err
		}
		selected, err := roots.Select(addAliasFlag)
		if err != nil {
			return err
		}
		workingRoot = selected.Root.String()
		candidateStoreAlias = selected.Alias
	}
	if opts.Target == addTargetMALT {
		remote, err = gatewayClient()
		if err != nil {
			return err
		}
	}

	result, err := addInputsWithUnixFS(ctx, remote, casClient, args, workingRoot, opts)
	if err != nil {
		var apiErr *gatewayclient.Error
		if errors.As(err, &apiErr) {
			return daemonCommandError(err)
		}
		return err
	}
	if result.NewRoot == "" {
		return fmt.Errorf("failed to materialize a new root")
	}
	if candidateStoreAlias != "" {
		candidate, err := cid.Parse(result.NewRoot)
		if err != nil {
			return fmt.Errorf("decode add candidate root: %w", err)
		}
		base, err := cid.Parse(workingRoot)
		if err != nil {
			return fmt.Errorf("decode add base root: %w", err)
		}
		if _, err := roots.RecordCandidate(candidateStoreAlias, candidate, base, "malt add"); err != nil {
			return fmt.Errorf("record candidate root: %w", err)
		}
	}

	summary := addSummary{
		Target:           opts.Target,
		Model:            opts.Model,
		Layout:           opts.Layout,
		FileLayout:       opts.FileLayout,
		DirLayout:        opts.DirLayout,
		OldRoot:          workingRoot,
		NewRoot:          result.NewRoot,
		Files:            result.Files,
		Bytes:            result.Bytes,
		ImmutableObjects: result.ImmutableObjects,
		MALTObjects:      result.MALTObjects,
		MALTMaps:         result.MALTMaps,
		MALTLists:        result.MALTLists,
		ArcSets:          result.ArcSets,
		Arcs:             result.Arcs,
		SymlinkRoots:     result.SymlinkRoots,
	}
	if addJSONFlag {
		printJSON(summary)
	} else {
		fmt.Print(formatAddSummary(summary))
	}
	return nil
}

func formatAddSummary(summary addSummary) string {
	var b strings.Builder
	if summary.Target == addTargetMerkleDAG {
		fmt.Fprintf(&b, "Imported %d files, %d bytes into Merkle DAG UnixFS\n", summary.Files, summary.Bytes)
		fmt.Fprintf(&b, "Result root: %s\n", summary.NewRoot)
		return b.String()
	}
	fmt.Fprintf(&b, "Uploaded %d immutable objects, %d bytes\n", summary.ImmutableObjects, summary.Bytes)
	fmt.Fprintf(&b, "Wrote %d MALT objects: %d maps, %d lists\n", summary.MALTObjects, summary.MALTMaps, summary.MALTLists)
	if summary.SymlinkRoots == 1 {
		fmt.Fprintf(&b, "Materialized 1 symlink root\n")
	} else if summary.SymlinkRoots > 1 {
		fmt.Fprintf(&b, "Materialized %d symlink roots\n", summary.SymlinkRoots)
	}
	fmt.Fprintf(&b, "Result root: %s\n", summary.NewRoot)
	return b.String()
}
