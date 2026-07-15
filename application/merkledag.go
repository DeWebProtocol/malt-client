package application

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-client/merkledag"
	merkledagimport "github.com/dewebprotocol/malt-client/merkledag/importer"
	cid "github.com/ipfs/go-cid"
)

// MerkleDAGVerifiedClient is the fixed compatibility read capability consumed
// by the application layer. It has no arbitrary route method.
type MerkleDAGVerifiedClient interface {
	ResolveMerkleDAGVerified(context.Context, cid.Cid, []string) (*merkledag.MerkleDAGResolveResponse, error)
	ReadMerkleDAGVerified(context.Context, cid.Cid, []string, *uint64, *uint64) (*merkledag.MerkleDAGReadResponse, error)
}

// MerkleDAG composes IPFS-compatible import and caller-root-bound local replay.
// Merkle-DAG evidence is deliberately separate from MALT ProofLists.
type MerkleDAG struct {
	verified MerkleDAGVerifiedClient
	store    merkledagimport.Store
}

func NewMerkleDAG(verified MerkleDAGVerifiedClient, store merkledagimport.Store) (*MerkleDAG, error) {
	if verified == nil && store == nil {
		return nil, fmt.Errorf("Merkle-DAG application requires a verified client or import store")
	}
	return &MerkleDAG{verified: verified, store: store}, nil
}

func (a *MerkleDAG) Resolve(ctx context.Context, root cid.Cid, segments []string) (*merkledag.MerkleDAGResolveResponse, error) {
	if a == nil || a.verified == nil {
		return nil, fmt.Errorf("Merkle-DAG verified client is nil")
	}
	if !root.Defined() {
		return nil, fmt.Errorf("caller-selected Merkle-DAG root is undefined")
	}
	return a.verified.ResolveMerkleDAGVerified(ctx, root, cloneStrings(segments))
}

func (a *MerkleDAG) Read(ctx context.Context, root cid.Cid, segments []string, offset, length *uint64) (*merkledag.MerkleDAGReadResponse, error) {
	if a == nil || a.verified == nil {
		return nil, fmt.Errorf("Merkle-DAG verified client is nil")
	}
	if !root.Defined() {
		return nil, fmt.Errorf("caller-selected Merkle-DAG root is undefined")
	}
	return a.verified.ReadMerkleDAGVerified(ctx, root, cloneStrings(segments), cloneNumber(offset), cloneNumber(length))
}

func (a *MerkleDAG) ImportPath(ctx context.Context, localPath string, opts merkledagimport.Options) (*merkledagimport.Result, error) {
	if a == nil || a.store == nil {
		return nil, fmt.Errorf("Merkle-DAG import store is nil")
	}
	return merkledagimport.ImportPath(ctx, a.store, localPath, opts)
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}

func cloneNumber(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
