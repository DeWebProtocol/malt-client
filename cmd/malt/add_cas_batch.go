package main

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-client/internal/cas"
	cid "github.com/ipfs/go-cid"
)

type addCASBatcher struct {
	inner    addCASClient
	blocks   []cas.Block
	seen     map[string]cid.Cid
	uploaded int
}

func newAddCASBatcher(inner addCASClient) *addCASBatcher {
	return &addCASBatcher{
		inner: inner,
		seen:  make(map[string]cid.Cid),
	}
}

func asAddCASBatcher(client addCASClient) *addCASBatcher {
	if batcher, ok := client.(*addCASBatcher); ok {
		return batcher
	}
	return newAddCASBatcher(client)
}

func (b *addCASBatcher) Put(ctx context.Context, data []byte) (cid.Cid, error) {
	return b.PutWithCodec(ctx, data, cid.Raw)
}

func (b *addCASBatcher) PutWithCodec(_ context.Context, data []byte, codec uint64) (cid.Cid, error) {
	block := cas.Block{Data: data, Codec: codec}
	blockCID, err := cas.CIDForBlock(block)
	if err != nil {
		return cid.Undef, err
	}
	if b.seen == nil {
		b.seen = make(map[string]cid.Cid)
	}
	key := blockCID.String()
	if _, ok := b.seen[key]; !ok {
		b.seen[key] = blockCID
		b.blocks = append(b.blocks, cas.Block{
			Data:  append([]byte(nil), data...),
			Codec: codec,
		})
	}
	return blockCID, nil
}

func (b *addCASBatcher) Get(ctx context.Context, c cid.Cid) ([]byte, error) {
	return b.inner.Get(ctx, c)
}

func (b *addCASBatcher) Flush(ctx context.Context) error {
	if len(b.blocks) == 0 {
		return nil
	}
	results, err := cas.PutBlocks(ctx, b.inner, b.blocks)
	if err != nil {
		return err
	}
	if len(results) != len(b.blocks) {
		return fmt.Errorf("CAS batch flush returned %d results for %d blocks", len(results), len(b.blocks))
	}
	for i, result := range results {
		want, err := cas.CIDForBlock(b.blocks[i])
		if err != nil {
			return err
		}
		if !result.CID.Equals(want) {
			return fmt.Errorf("CAS batch flush returned CID %s for block %d, want %s", result.CID, i, want)
		}
	}
	b.uploaded += len(b.blocks)
	b.blocks = nil
	b.seen = make(map[string]cid.Cid)
	return nil
}

func (b *addCASBatcher) UploadedCount() int {
	if b == nil {
		return 0
	}
	return b.uploaded
}
