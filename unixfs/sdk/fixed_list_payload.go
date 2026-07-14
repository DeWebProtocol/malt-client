package unixfs

import (
	"context"
	"fmt"
	"io"

	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

// FixedListPayloadWriter supplies the writer-side operations needed to
// materialize a fixed-width list payload.
type FixedListPayloadWriter interface {
	CreateFixedListBaseRoot(ctx context.Context) (cid.Cid, error)
	ApplyFixedListPayloadMutation(ctx context.Context, mut mutation.SemanticMutation) (cid.Cid, error)
}

// MaterializeFixedListPayload streams payload chunks into CAS, commits the
// fixed-list root through writer semantics, and returns the new list root.
func MaterializeFixedListPayload(ctx context.Context, blocks StagedBlockStore, writer FixedListPayloadWriter, r io.Reader, totalSize uint64, chunkSize int) (cid.Cid, error) {
	if blocks == nil {
		return cid.Undef, fmt.Errorf("block store is nil")
	}
	if writer == nil {
		return cid.Undef, fmt.Errorf("fixed-list payload writer is nil")
	}

	chunks := make([]cid.Cid, 0)
	err := unixfsmodel.StreamPayloadChunks(r, chunkSize, func(chunk []byte) error {
		chunkCID, err := blocks.Put(ctx, chunk)
		if err != nil {
			return fmt.Errorf("upload payload chunk: %w", err)
		}
		chunks = append(chunks, chunkCID)
		return nil
	})
	if err != nil {
		return cid.Undef, err
	}
	if len(chunks) == 0 {
		return cid.Undef, fmt.Errorf("empty chunk sequence")
	}
	if flusher, ok := blocks.(stagedBlockFlusher); ok {
		if err := flusher.Flush(ctx); err != nil {
			return cid.Undef, fmt.Errorf("flush payload chunks: %w", err)
		}
	}

	baseRoot, err := writer.CreateFixedListBaseRoot(ctx)
	if err != nil {
		return cid.Undef, err
	}
	mut, err := unixfsmodel.FixedListPayloadMutation(baseRoot, chunks, totalSize, uint64(chunkSize))
	if err != nil {
		return cid.Undef, err
	}
	return writer.ApplyFixedListPayloadMutation(ctx, mut)
}

// MaterializeStagedFilePayload stores a file payload according to the UnixFS
// staged-add policy. Small files become raw CAS payloads; larger files become
// fixed-width list payloads.
func MaterializeStagedFilePayload(ctx context.Context, blocks StagedBlockStore, writer FixedListPayloadWriter, r io.Reader, size int64, chunkSize int) (cid.Cid, bool, error) {
	if size < 0 {
		return cid.Undef, false, fmt.Errorf("file size must not be negative")
	}
	if size <= int64(chunkSize) {
		data, err := io.ReadAll(r)
		if err != nil {
			return cid.Undef, false, err
		}
		payload, err := blocks.Put(ctx, data)
		if err != nil {
			return cid.Undef, false, err
		}
		return payload, false, nil
	}
	payload, err := MaterializeFixedListPayload(ctx, blocks, writer, r, uint64(size), chunkSize)
	if err != nil {
		return cid.Undef, false, err
	}
	return payload, true, nil
}
