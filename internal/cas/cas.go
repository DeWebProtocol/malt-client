// Package cas provides Content Addressable Storage clients.
package cas

import (
	"context"
	"errors"
	"fmt"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// ErrNotFound reports that a requested CAS block is absent. Remote and local
// implementations wrap this sentinel so higher layers can distinguish absence
// from transport, cancellation, and corruption failures.
var ErrNotFound = errors.New("cas: block not found")

// Block is a CAS block to write. Codec 0 means cid.Raw.
type Block struct {
	Data  []byte
	Codec uint64
}

// PutStatus describes how a block write was handled.
type PutStatus string

const (
	PutStatusStored         PutStatus = "stored"
	PutStatusAlreadyPresent PutStatus = "already_present"
	PutStatusDuplicate      PutStatus = "duplicate"
)

// PutResult is the ordered result for a block write.
type PutResult struct {
	CID    cid.Cid
	Status PutStatus
}

// Reader provides read-side access to content-addressable storage.
type Reader interface {
	// Get retrieves a block by its CID.
	Get(ctx context.Context, c cid.Cid) ([]byte, error)

	// Has checks if a block exists.
	Has(ctx context.Context, c cid.Cid) (bool, error)
}

// Writer provides write-side access to content-addressable storage.
type Writer interface {
	// Put stores a block and returns its CID.
	Put(ctx context.Context, data []byte) (cid.Cid, error)
}

// TypedWriter stores blocks under an explicit CID codec.
type TypedWriter interface {
	PutWithCodec(ctx context.Context, data []byte, codec uint64) (cid.Cid, error)
}

// BatchReader provides batch existence checks.
type BatchReader interface {
	HasBatch(ctx context.Context, cids []cid.Cid) ([]bool, error)
}

// BatchWriter provides batch block writes.
type BatchWriter interface {
	PutBatch(ctx context.Context, blocks []Block) ([]PutResult, error)
}

// Client provides full read/write access to content-addressable storage.
type Client interface {
	Reader
	Writer
}

// NormalizeCodec returns the effective codec for a block.
func NormalizeCodec(codec uint64) uint64 {
	if codec == 0 {
		return cid.Raw
	}
	return codec
}

// CIDForBlock computes the CID for block bytes and codec.
func CIDForBlock(block Block) (cid.Cid, error) {
	mhash, err := mh.Sum(block.Data, mh.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(NormalizeCodec(block.Codec), mhash), nil
}

// PutBlocks stores blocks, using batch writes when supported.
func PutBlocks(ctx context.Context, writer Writer, blocks []Block) ([]PutResult, error) {
	if len(blocks) == 0 {
		return []PutResult{}, nil
	}
	if batch, ok := writer.(BatchWriter); ok {
		results, err := batch.PutBatch(ctx, blocks)
		if err != nil {
			return nil, err
		}
		if len(results) != len(blocks) {
			return nil, fmt.Errorf("batch writer returned %d results for %d blocks", len(results), len(blocks))
		}
		return results, nil
	}

	results := make([]PutResult, len(blocks))
	for i, block := range blocks {
		codec := NormalizeCodec(block.Codec)
		var (
			blockCID cid.Cid
			err      error
		)
		if codec == cid.Raw {
			blockCID, err = writer.Put(ctx, block.Data)
		} else {
			typed, ok := writer.(TypedWriter)
			if !ok {
				return nil, fmt.Errorf("block %d requests codec %d but writer does not implement cas.TypedWriter", i, codec)
			}
			blockCID, err = typed.PutWithCodec(ctx, block.Data, codec)
		}
		if err != nil {
			return nil, err
		}
		results[i] = PutResult{CID: blockCID, Status: PutStatusStored}
	}
	return results, nil
}
