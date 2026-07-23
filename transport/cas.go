package transport

import (
	"context"
	"fmt"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	cid "github.com/ipfs/go-cid"
)

const (
	CASPutBatchProfile = "cas.put-batch/v0alpha1"
	CASHasBatchProfile = "cas.has-batch/v0alpha1"
	MaxCASBatchBlocks  = 4096
	MaxCASBatchBytes   = 64 << 20
)

type Block = clientcas.Block
type PutBatchResult = clientcas.PutResult

type HasBatchResult struct {
	CID     cid.Cid
	Present bool
}

// PutBatch stores an ordered, bounded group of immutable blocks. The client
// recomputes every returned CID before exposing the result.
func (c *Client) PutBatch(ctx context.Context, blocks []Block) ([]PutBatchResult, error) {
	if len(blocks) == 0 || len(blocks) > MaxCASBatchBlocks {
		return nil, fmt.Errorf("CAS batch must contain 1 to %d blocks", MaxCASBatchBlocks)
	}
	total := 0
	wireBlocks := make([]struct {
		Codec uint64 `json:"codec,omitempty"`
		Data  []byte `json:"data"`
	}, len(blocks))
	for i, block := range blocks {
		if len(block.Data) > MaxCASBatchBytes || total > MaxCASBatchBytes-len(block.Data) {
			return nil, fmt.Errorf("CAS batch exceeds %d decoded bytes", MaxCASBatchBytes)
		}
		total += len(block.Data)
		wireBlocks[i].Codec = block.Codec
		wireBlocks[i].Data = block.Data
	}
	request := struct {
		Profile string `json:"profile"`
		Blocks  any    `json:"blocks"`
	}{Profile: CASPutBatchProfile, Blocks: wireBlocks}
	var response struct {
		Profile string `json:"profile"`
		Results []struct {
			CID    string `json:"cid"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := c.doNative(ctx, "POST", "/v1/cas/batch", nil, request, &response); err != nil {
		return nil, err
	}
	if response.Profile != CASPutBatchProfile || len(response.Results) != len(blocks) {
		return nil, fmt.Errorf("invalid CAS put-batch response")
	}
	results := make([]clientcas.PutResult, len(blocks))
	for i, raw := range response.Results {
		got, err := cid.Parse(raw.CID)
		if err != nil {
			return nil, fmt.Errorf("decode CAS batch result %d: %w", i, err)
		}
		want, err := clientcas.CIDForBlock(clientcas.Block{Data: blocks[i].Data, Codec: blocks[i].Codec})
		if err != nil {
			return nil, err
		}
		if !got.Equals(want) {
			return nil, fmt.Errorf("CAS batch result %d returned CID %s, want %s", i, got, want)
		}
		results[i] = clientcas.PutResult{CID: got, Status: clientcas.PutStatus(raw.Status)}
	}
	return results, nil
}

// HasBatch checks an ordered group of immutable CIDs and rejects reordered or
// otherwise malformed gateway responses.
func (c *Client) HasBatchDetailed(ctx context.Context, keys []cid.Cid) ([]HasBatchResult, error) {
	if len(keys) == 0 || len(keys) > MaxCASBatchBlocks {
		return nil, fmt.Errorf("CAS has batch must contain 1 to %d CIDs", MaxCASBatchBlocks)
	}
	rawKeys := make([]string, len(keys))
	for i, key := range keys {
		if !key.Defined() {
			return nil, fmt.Errorf("CAS has batch CID %d is undefined", i)
		}
		rawKeys[i] = key.String()
	}
	request := struct {
		Profile string   `json:"profile"`
		CIDs    []string `json:"cids"`
	}{Profile: CASHasBatchProfile, CIDs: rawKeys}
	var response struct {
		Profile string `json:"profile"`
		Results []struct {
			CID     string `json:"cid"`
			Present bool   `json:"present"`
		} `json:"results"`
	}
	if err := c.doNative(ctx, "POST", "/v1/cas/has", nil, request, &response); err != nil {
		return nil, err
	}
	if response.Profile != CASHasBatchProfile || len(response.Results) != len(keys) {
		return nil, fmt.Errorf("invalid CAS has-batch response")
	}
	results := make([]HasBatchResult, len(keys))
	for i, raw := range response.Results {
		got, err := cid.Parse(raw.CID)
		if err != nil || !got.Equals(keys[i]) {
			return nil, fmt.Errorf("CAS has-batch result %d does not match requested CID", i)
		}
		results[i] = HasBatchResult{CID: got, Present: raw.Present}
	}
	return results, nil
}

// HasBatch is the compact compatibility surface consumed by streaming CAS
// writers. Use HasBatchDetailed when ordered CIDs are useful to the caller.
func (c *Client) HasBatch(ctx context.Context, keys []cid.Cid) ([]bool, error) {
	detailed, err := c.HasBatchDetailed(ctx, keys)
	if err != nil {
		return nil, err
	}
	result := make([]bool, len(detailed))
	for i := range detailed {
		result[i] = detailed[i].Present
	}
	return result, nil
}
