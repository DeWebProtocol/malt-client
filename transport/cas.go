package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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

// PutBatchMeasurement is the exact HTTP-message boundary for one CAS batch.
// RequestWireBytes and ResponseWireBytes are kept directionally separate;
// RoundTripNS starts immediately before the HTTP exchange and ends after the
// complete bounded response body has arrived. Local response/CID validation is
// deliberately outside that duration.
type PutBatchMeasurement struct {
	Results           []PutBatchResult
	RoundTripNS       uint64
	RequestWireBytes  uint64
	ResponseWireBytes uint64
}

type HasBatchResult struct {
	CID     cid.Cid
	Present bool
}

// PutBatch stores an ordered, bounded group of immutable blocks. The client
// recomputes every returned CID before exposing the result.
func (c *Client) PutBatch(ctx context.Context, blocks []Block) ([]PutBatchResult, error) {
	measurement, err := c.PutBatchMeasured(ctx, blocks)
	if err != nil {
		return nil, err
	}
	return measurement.Results, nil
}

// PutBatchMeasured stores a batch and exposes exact request/response body
// sizes plus the HTTP round trip for evaluator phase accounting. Ordinary
// application callers should continue to use PutBatch.
func (c *Client) PutBatchMeasured(ctx context.Context, blocks []Block) (PutBatchMeasurement, error) {
	if len(blocks) == 0 || len(blocks) > MaxCASBatchBlocks {
		return PutBatchMeasurement{}, fmt.Errorf("CAS batch must contain 1 to %d blocks", MaxCASBatchBlocks)
	}
	total := 0
	wireBlocks := make([]struct {
		Codec uint64 `json:"codec,omitempty"`
		Data  []byte `json:"data"`
	}, len(blocks))
	for i, block := range blocks {
		if len(block.Data) > MaxCASBatchBytes || total > MaxCASBatchBytes-len(block.Data) {
			return PutBatchMeasurement{}, fmt.Errorf("CAS batch exceeds %d decoded bytes", MaxCASBatchBytes)
		}
		total += len(block.Data)
		wireBlocks[i].Codec = block.Codec
		wireBlocks[i].Data = block.Data
	}
	request := struct {
		Profile string `json:"profile"`
		Blocks  any    `json:"blocks"`
	}{Profile: CASPutBatchProfile, Blocks: wireBlocks}
	requestData, err := json.Marshal(request)
	if err != nil {
		return PutBatchMeasurement{}, fmt.Errorf("encode CAS put-batch request: %w", err)
	}
	u, err := c.endpoint(c.nativeRoute("/v1/cas/batch"))
	if err != nil {
		return PutBatchMeasurement{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(requestData))
	if err != nil {
		return PutBatchMeasurement{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	started := time.Now()
	httpResponse, err := c.send(httpRequest, c.bucketID != "")
	if err != nil {
		return PutBatchMeasurement{}, err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return PutBatchMeasurement{}, c.responseError(httpResponse)
	}
	responseData, err := readBounded(httpResponse.Body, c.maxJSONResponseBytes, "Gateway CAS put-batch response")
	roundTripNS := casDurationNS(time.Since(started))
	if err != nil {
		return PutBatchMeasurement{}, err
	}
	var response struct {
		Profile string `json:"profile"`
		Results []struct {
			CID    string `json:"cid"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(responseData, &response); err != nil {
		return PutBatchMeasurement{}, fmt.Errorf("decode Gateway CAS put-batch response: %w", err)
	}
	if response.Profile != CASPutBatchProfile || len(response.Results) != len(blocks) {
		return PutBatchMeasurement{}, fmt.Errorf("invalid CAS put-batch response")
	}
	results := make([]clientcas.PutResult, len(blocks))
	for i, raw := range response.Results {
		got, err := cid.Parse(raw.CID)
		if err != nil {
			return PutBatchMeasurement{}, fmt.Errorf("decode CAS batch result %d: %w", i, err)
		}
		want, err := clientcas.CIDForBlock(clientcas.Block{Data: blocks[i].Data, Codec: blocks[i].Codec})
		if err != nil {
			return PutBatchMeasurement{}, err
		}
		if !got.Equals(want) {
			return PutBatchMeasurement{}, fmt.Errorf("CAS batch result %d returned CID %s, want %s", i, got, want)
		}
		status := clientcas.PutStatus(raw.Status)
		switch status {
		case clientcas.PutStatusStored, clientcas.PutStatusAlreadyPresent, clientcas.PutStatusDuplicate,
			clientcas.PutStatusNewlyPersisted, clientcas.PutStatusDuplicateInRequest:
		default:
			return PutBatchMeasurement{}, fmt.Errorf("CAS batch result %d has unsupported status %q", i, raw.Status)
		}
		results[i] = clientcas.PutResult{CID: got, Status: status}
	}
	return PutBatchMeasurement{
		Results: results, RoundTripNS: roundTripNS,
		RequestWireBytes: uint64(len(requestData)), ResponseWireBytes: uint64(len(responseData)),
	}, nil
}

func casDurationNS(value time.Duration) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
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
