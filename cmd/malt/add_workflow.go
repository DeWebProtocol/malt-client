package main

import (
	"context"
	"fmt"
	"strings"

	daemonclient "github.com/dewebprotocol/malt-client/internal/gateway"
	"github.com/dewebprotocol/malt-client/unixfs/sdk"
	cid "github.com/ipfs/go-cid"
)

type addUnixFSResult struct {
	Files            int
	Bytes            int64
	NewRoot          string
	ImmutableObjects int
	MALTObjects      int
	MALTMaps         int
	MALTLists        int
	ArcSets          int
	Arcs             int
	SymlinkRoots     int
}

type addCASClient interface {
	Put(ctx context.Context, data []byte) (cid.Cid, error)
	PutWithCodec(ctx context.Context, data []byte, codec uint64) (cid.Cid, error)
	Get(ctx context.Context, c cid.Cid) ([]byte, error)
}

func addInputsWithUnixFS(ctx context.Context, daemon *daemonclient.Client, casClient addCASClient, rawInputs []string, root string, opts addBuildOptions) (*addUnixFSResult, error) {
	normalized, err := normalizeAddBuildOptions(opts)
	if err != nil {
		return nil, err
	}
	switch normalized.Layout {
	case addLayoutFlat:
		return addInputsWithMALTFlatUnixFS(ctx, daemon, casClient, rawInputs, root, normalized)
	case addLayoutHierarchical:
		return addInputsWithMALTHierarchicalUnixFS(ctx, daemon, casClient, rawInputs, root, normalized)
	}
	return nil, fmt.Errorf("unsupported add model/layout %q/%q", normalized.Model, normalized.Layout)
}

func addInputsWithMALTFlatUnixFS(ctx context.Context, daemon *daemonclient.Client, casClient addCASClient, rawInputs []string, root string, opts addBuildOptions) (*addUnixFSResult, error) {
	return addInputsWithMALTStagedUnixFS(ctx, daemon, casClient, rawInputs, root, opts)
}

func addInputsWithMALTHierarchicalUnixFS(ctx context.Context, daemon *daemonclient.Client, casClient addCASClient, rawInputs []string, root string, opts addBuildOptions) (*addUnixFSResult, error) {
	return addInputsWithMALTStagedUnixFS(ctx, daemon, casClient, rawInputs, root, opts)
}

func addInputsWithMALTStagedUnixFS(ctx context.Context, daemon *daemonclient.Client, casClient addCASClient, rawInputs []string, root string, opts addBuildOptions) (*addUnixFSResult, error) {
	if daemon == nil {
		return nil, fmt.Errorf("gateway client is required")
	}
	staged, err := buildAddStagingTree(ctx, casClient, daemon, rawInputs, opts)
	if err != nil {
		return nil, err
	}

	rootNode := staged.Root
	if strings.TrimSpace(root) != "" {
		existing, err := loadExistingCurrentTree(ctx, daemon, casClient, root)
		if err != nil {
			return nil, err
		}
		rootNode = unixfs.MergeStagedNodes(existing, staged.Root)
	}
	mat, err := materializeDirectory(ctx, daemon, casClient, rootNode)
	if err != nil {
		return nil, err
	}
	return &addUnixFSResult{
		Files:            staged.Files,
		Bytes:            staged.Bytes,
		NewRoot:          mat.Key.String(),
		ImmutableObjects: staged.ImmutableObjects + mat.ImmutableObjects,
		MALTObjects:      staged.MALTObjects + mat.MALTObjects,
		MALTMaps:         staged.MALTMaps + mat.MALTMaps,
		MALTLists:        staged.MALTLists + mat.MALTLists,
		ArcSets:          staged.ArcSets + mat.ArcSets,
		Arcs:             staged.Arcs + mat.Arcs,
		SymlinkRoots:     staged.SymlinkRoots,
	}, nil
}
