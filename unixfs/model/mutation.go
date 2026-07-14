package unixfs

import (
	"fmt"
	"math"

	"github.com/dewebprotocol/malt/auth/arcset"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

// MutationPlan is the application-model projection of one UnixFS change. It
// contains no executor namespace, transport, CAS client, or root publication
// policy.
type MutationPlan struct {
	BaseRoot cid.Cid
	Deltas   []MutationDelta
}

type MutationDelta struct {
	Object       cid.Cid
	ExpectedRoot cid.Cid
	Kind         arcset.Kind
	Changes      *arcset.CanonicalArcDelta
	FixedList    *FixedListCommit
}

type FixedListCommit struct {
	TotalSize uint64
	ChunkSize uint64
}

// CoreMutation converts the UnixFS model plan into the portable MALT mutation
// contract consumed by a gateway/executor.
func (p *MutationPlan) CoreMutation(fallbackRoot cid.Cid) mutation.SemanticMutation {
	if p == nil {
		return mutation.SemanticMutation{BaseRoot: fallbackRoot}
	}
	baseRoot := p.BaseRoot
	if !baseRoot.Defined() {
		baseRoot = fallbackRoot
	}
	out := mutation.SemanticMutation{BaseRoot: baseRoot, Deltas: make([]mutation.ArcSetDelta, 0, len(p.Deltas))}
	for _, delta := range p.Deltas {
		coreDelta := mutation.ArcSetDelta{Object: delta.Object, ExpectedRoot: delta.ExpectedRoot, Kind: delta.Kind, Changes: delta.Changes}
		if delta.FixedList != nil {
			coreDelta.Commit.FixedList = &mutation.FixedListCommit{TotalSize: delta.FixedList.TotalSize, ChunkSize: delta.FixedList.ChunkSize}
		}
		out.Deltas = append(out.Deltas, coreDelta)
	}
	return out
}

// WriterMutation is a compatibility spelling for CoreMutation.
// Deprecated: use CoreMutation.
func (p *MutationPlan) WriterMutation(fallbackRoot cid.Cid) mutation.SemanticMutation {
	return p.CoreMutation(fallbackRoot)
}

// FixedListPayloadMutation builds a portable MALT mutation for a measured
// fixed-width list from already stored chunk CIDs.
func FixedListPayloadMutation(baseRoot cid.Cid, chunks []cid.Cid, totalSize, chunkSize uint64) (mutation.SemanticMutation, error) {
	if len(chunks) == 0 {
		return mutation.SemanticMutation{}, fmt.Errorf("chunks must not be empty")
	}
	if chunkSize == 0 {
		return mutation.SemanticMutation{}, fmt.Errorf("chunk size must be positive")
	}
	changes := make([]arcset.ArcChange, len(chunks))
	for i, chunk := range chunks {
		if !chunk.Defined() {
			return mutation.SemanticMutation{}, fmt.Errorf("chunk %d is undefined", i)
		}
		if uint64(i) > math.MaxInt64 {
			return mutation.SemanticMutation{}, fmt.Errorf("chunk index %d exceeds canonical coordinate range", i)
		}
		coordinate, err := arcset.NewListCoordinate(int64(i))
		if err != nil {
			return mutation.SemanticMutation{}, err
		}
		after := arcset.NewCASTarget(chunk)
		changes[i] = arcset.ArcChange{Coordinate: coordinate, After: &after}
	}
	delta, err := arcset.NewCanonicalArcDelta(arcset.KindList, changes)
	if err != nil {
		return mutation.SemanticMutation{}, err
	}
	return mutation.SemanticMutation{BaseRoot: baseRoot, Deltas: []mutation.ArcSetDelta{{Kind: arcset.KindList, Changes: delta, Commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{TotalSize: totalSize, ChunkSize: chunkSize}}}}}, nil
}
