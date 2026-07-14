package main

import (
	"context"
	"fmt"
	"strings"

	gatewayclient "github.com/dewebprotocol/malt-client/client"
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

func addInputsWithUnixFS(ctx context.Context, remote *gatewayclient.Client, casClient addCASClient, rawInputs []string, root string, opts addBuildOptions) (*addUnixFSResult, error) {
	normalized, err := normalizeAddBuildOptions(opts)
	if err != nil {
		return nil, err
	}
	switch normalized.Target {
	case addTargetMALT:
		return addInputsWithMALTHybridUnixFS(ctx, remote, casClient, rawInputs, root, normalized)
	case addTargetMerkleDAG:
		return addInputsWithMerkleDAGUnixFS(ctx, casClient, rawInputs, normalized)
	}
	return nil, fmt.Errorf("unsupported add target/model/layout %q/%q/%q", normalized.Target, normalized.Model, normalized.Layout)
}

func addInputsWithMALTHybridUnixFS(ctx context.Context, remote *gatewayclient.Client, casClient addCASClient, rawInputs []string, root string, opts addBuildOptions) (*addUnixFSResult, error) {
	if remote == nil {
		return nil, fmt.Errorf("gateway client is required")
	}
	staged, err := buildAddStagingTree(ctx, casClient, remote, rawInputs, opts)
	if err != nil {
		return nil, err
	}

	rootNode := staged.Root
	if strings.TrimSpace(root) != "" {
		existing, err := loadExistingCurrentTree(ctx, remote, casClient, root)
		if err != nil {
			return nil, err
		}
		rootNode = unixfs.MergeStagedNodes(existing, staged.Root)
	}
	mat, err := materializeDirectory(ctx, remote, casClient, rootNode)
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
