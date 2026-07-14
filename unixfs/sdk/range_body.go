package unixfs

import (
	"bytes"
	"fmt"

	"github.com/dewebprotocol/malt/auth/proof/prooflist"
	cid "github.com/ipfs/go-cid"
)

// VerifyRangeBody verifies that body is the byte range [start, end) assembled
// from the segment CIDs authenticated by a matching list_range ProofList step.
//
// This helper does not replace ProofList verification. Callers should first
// verify the ProofList against the trusted root, then use this helper before
// trusting HTTP range body bytes.
func VerifyRangeBody(pl prooflist.ProofList, body []byte, start, end uint64, fetch func(cid.Cid) ([]byte, error)) error {
	if fetch == nil {
		return fmt.Errorf("range body segment fetcher is nil")
	}
	if start > end {
		return fmt.Errorf("range start %d is after end %d", start, end)
	}
	if err := pl.ValidateShape(prooflist.RequireSteps()); err != nil {
		return err
	}
	step, ok := matchingRangeStep(pl, start, end)
	if !ok {
		return fmt.Errorf("no matching list_range proof for byte range [%d,%d)", start, end)
	}
	if step.TotalSize == nil {
		return fmt.Errorf("matching list_range proof is missing total size")
	}
	if step.ChunkSize == nil || *step.ChunkSize == 0 {
		return fmt.Errorf("matching list_range proof has invalid chunk size")
	}
	if end > *step.TotalSize {
		return fmt.Errorf("range end %d exceeds authenticated total size %d", end, *step.TotalSize)
	}
	wantLen := end - start
	if uint64(len(body)) != wantLen {
		return fmt.Errorf("range body length %d does not match requested length %d", len(body), wantLen)
	}

	assembled := make([]byte, 0, len(body))
	for i, segment := range step.Segments {
		data, err := fetch(segment)
		if err != nil {
			return fmt.Errorf("fetching authenticated segment %d %s: %w", i, segment.String(), err)
		}
		computed, err := segment.Prefix().Sum(data)
		if err != nil {
			return fmt.Errorf("computing fetched segment %d CID: %w", i, err)
		}
		if !computed.Equals(segment) {
			return fmt.Errorf("fetched segment %d does not match authenticated segment CID %s", i, segment.String())
		}
		assembled = append(assembled, data...)
	}

	offset := start % *step.ChunkSize
	limit := offset + wantLen
	if uint64(len(assembled)) < limit {
		return fmt.Errorf("authenticated segments provide %d bytes from range offset %d, need %d", len(assembled), offset, limit)
	}
	if !bytes.Equal(body, assembled[offset:limit]) {
		return fmt.Errorf("range body does not match authenticated segments")
	}
	return nil
}

func matchingRangeStep(pl prooflist.ProofList, start, end uint64) (prooflist.Step, bool) {
	for _, step := range pl.Steps {
		if step.Kind != prooflist.KindListRange {
			continue
		}
		if step.Start == nil {
			continue
		}
		endMatches := step.End != nil && *step.End == end
		if step.End == nil && step.TotalSize != nil && *step.TotalSize == end {
			endMatches = true
		}
		if *step.Start == start && endMatches {
			return step, true
		}
	}
	return prooflist.Step{}, false
}
