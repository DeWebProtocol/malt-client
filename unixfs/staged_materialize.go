package unixfs

import (
	"context"
	"fmt"
	"path"
	"slices"

	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	cid "github.com/ipfs/go-cid"
)

// StagedMaterializeResult summarizes materialization of a staged UnixFS tree.
type StagedMaterializeResult struct {
	Key              cid.Cid
	ArcCount         int
	Descendants      map[string]cid.Cid
	ImmutableObjects int
	MALTObjects      int
	MALTMaps         int
	MALTLists        int
	ArcSets          int
	Arcs             int
}

// StagedRootCreator creates a map root from already serialized bindings.
type StagedRootCreator interface {
	CreateStagedRoot(ctx context.Context, bindings map[string]string) (cid.Cid, error)
}

// StagedBlockStore is the block subset needed by staged materialization.
type StagedBlockStore interface {
	Put(ctx context.Context, data []byte) (cid.Cid, error)
}

type stagedBlockFlusher interface {
	Flush(ctx context.Context) error
}

// AddStagedMaterializeStats aggregates staged materialization counters.
func AddStagedMaterializeStats(dst *StagedMaterializeResult, src *StagedMaterializeResult) {
	if dst == nil || src == nil {
		return
	}
	dst.ImmutableObjects += src.ImmutableObjects
	dst.MALTObjects += src.MALTObjects
	dst.MALTMaps += src.MALTMaps
	dst.MALTLists += src.MALTLists
	dst.ArcSets += src.ArcSets
	dst.Arcs += src.Arcs
	dst.ArcCount += src.ArcCount
}

// MaterializeStagedDirectory writes the changed portions of a staged UnixFS
// directory tree and returns its map root. Unchanged staged directories keep
// their existing Key while changed directories are committed bottom-up.
func MaterializeStagedDirectory(ctx context.Context, roots StagedRootCreator, blocks StagedBlockStore, node *StagedNode) (*StagedMaterializeResult, error) {
	if node == nil || node.Kind != StagedKindDirectory {
		return nil, fmt.Errorf("MaterializeStagedDirectory requires a directory node")
	}

	names := make([]string, 0, len(node.Children))
	for name := range node.Children {
		segments, err := ParseCanonicalStagedPath(name)
		if err != nil || len(segments) != 1 || segments[0] != name {
			if err == nil {
				err = fmt.Errorf("child name must be one losslessly canonical portable path segment")
			}
			return nil, fmt.Errorf("invalid staged directory child %q: %w", name, err)
		}
		names = append(names, name)
	}
	slices.Sort(names)

	desc := make(map[string]cid.Cid)
	childKeys := make(map[string]cid.Cid, len(node.Children))
	stats := &StagedMaterializeResult{}
	for _, name := range names {
		child := node.Children[name]
		if child == nil {
			continue
		}
		if child.Kind == StagedKindDirectory {
			mat, err := MaterializeStagedDirectory(ctx, roots, blocks, child)
			if err != nil {
				return nil, err
			}
			AddStagedMaterializeStats(stats, mat)
			child.Key = mat.Key
			child.Changed = false
			childKeys[name] = mat.Key
			desc[name] = mat.Key
			for rel, childKey := range mat.Descendants {
				desc[path.Join(name, rel)] = childKey
			}
			continue
		}
		childKeys[name] = child.Key
		desc[name] = child.Key
	}

	if !node.Changed && node.Key.Defined() {
		return &StagedMaterializeResult{
			Key:              node.Key,
			ArcCount:         stats.ArcCount,
			Descendants:      desc,
			ImmutableObjects: stats.ImmutableObjects,
			MALTObjects:      stats.MALTObjects,
			MALTMaps:         stats.MALTMaps,
			MALTLists:        stats.MALTLists,
			ArcSets:          stats.ArcSets,
			Arcs:             stats.Arcs,
		}, nil
	}

	payloadBytes, err := unixfsmodel.DirectoryManifestPayload(names)
	if err != nil {
		return nil, fmt.Errorf("marshal directory manifest: %w", err)
	}
	payloadCID, err := blocks.Put(ctx, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("upload directory manifest: %w", err)
	}
	if flusher, ok := blocks.(stagedBlockFlusher); ok {
		if err := flusher.Flush(ctx); err != nil {
			return nil, fmt.Errorf("flush directory manifest: %w", err)
		}
	}

	bindings := unixfsmodel.DirectoryRootBindings(payloadCID, childKeys, desc)
	rootCID, err := roots.CreateStagedRoot(ctx, bindings)
	if err != nil {
		return nil, err
	}
	node.Key = rootCID
	node.Changed = false
	node.StorageKind = "map"
	arcCount := unixfsmodel.CountDefinedBindings(bindings)
	return &StagedMaterializeResult{
		Key:              rootCID,
		ArcCount:         stats.ArcCount + arcCount,
		Descendants:      desc,
		ImmutableObjects: stats.ImmutableObjects + 1,
		MALTObjects:      stats.MALTObjects + 1,
		MALTMaps:         stats.MALTMaps + 1,
		MALTLists:        stats.MALTLists,
		ArcSets:          stats.ArcSets + 1,
		Arcs:             stats.Arcs + arcCount,
	}, nil
}
