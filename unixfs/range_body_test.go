package unixfs

import (
	"errors"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt/auth/proof/prooflist"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestVerifyRangeBodyAcceptsBytesBoundToSegments(t *testing.T) {
	pl, segments := rangeBodyProofList(t)

	err := VerifyRangeBody(pl, []byte("cdefghi"), 2, 9, segmentFetcher(segments))
	if err != nil {
		t.Fatalf("VerifyRangeBody returned error: %v", err)
	}
}

func TestVerifyRangeBodyRejectsTamperedBytes(t *testing.T) {
	pl, segments := rangeBodyProofList(t)

	err := VerifyRangeBody(pl, []byte("cdefghX"), 2, 9, segmentFetcher(segments))
	if err == nil {
		t.Fatal("VerifyRangeBody accepted tampered bytes")
	}
	if !strings.Contains(err.Error(), "range body does not match authenticated segments") {
		t.Fatalf("tampered body error = %q, want body mismatch error", err.Error())
	}
}

func TestVerifyRangeBodyRejectsShiftedRange(t *testing.T) {
	pl, segments := rangeBodyProofList(t)

	err := VerifyRangeBody(pl, []byte("defghij"), 3, 10, segmentFetcher(segments))
	if err == nil {
		t.Fatal("VerifyRangeBody accepted bytes for a shifted range")
	}
	if !strings.Contains(err.Error(), "no matching list_range proof") {
		t.Fatalf("shifted range error = %q, want missing range proof error", err.Error())
	}
}

func TestVerifyRangeBodyRejectsSegmentCIDMismatch(t *testing.T) {
	pl, segments := rangeBodyProofList(t)
	for i := range pl.Steps {
		if pl.Steps[i].Kind == prooflist.KindListRange {
			pl.Steps[i].Segments[1] = rangeBodyCID(t, "wrong-segment")
			segments[pl.Steps[i].Segments[1].String()] = []byte("XXXX")
			break
		}
	}

	err := VerifyRangeBody(pl, []byte("cdefghi"), 2, 9, segmentFetcher(segments))
	if err == nil {
		t.Fatal("VerifyRangeBody accepted bytes with a mismatched segment CID")
	}
	if !strings.Contains(err.Error(), "does not match authenticated segment CID") {
		t.Fatalf("segment mismatch error = %q, want CID mismatch error", err.Error())
	}
}

func TestVerifyRangeBodyRejectsFetcherBytesThatDoNotMatchSegmentCID(t *testing.T) {
	pl, segments := rangeBodyProofList(t)
	for i := range pl.Steps {
		if pl.Steps[i].Kind == prooflist.KindListRange {
			wrong := rangeBodyCID(t, "wrong-segment-cid")
			pl.Steps[i].Segments[1] = wrong
			segments[wrong.String()] = []byte("efgh")
			break
		}
	}

	err := VerifyRangeBody(pl, []byte("cdefghi"), 2, 9, segmentFetcher(segments))
	if err == nil {
		t.Fatal("VerifyRangeBody accepted bytes fetched for a CID they do not match")
	}
	if !strings.Contains(err.Error(), "does not match authenticated segment CID") {
		t.Fatalf("segment CID validation error = %q, want CID mismatch error", err.Error())
	}
}

func rangeBodyProofList(t *testing.T) (prooflist.ProofList, map[string][]byte) {
	t.Helper()
	root := rangeBodyCID(t, "list-root")
	segAData := []byte("abcd")
	segBData := []byte("efgh")
	segCData := []byte("ij")
	segA := rangeBodyCIDForBytes(t, segAData)
	segB := rangeBodyCIDForBytes(t, segBData)
	segC := rangeBodyCIDForBytes(t, segCData)
	start := uint64(2)
	end := uint64(9)
	childCount := uint64(3)
	totalSize := uint64(10)
	chunkSize := uint64(4)
	return prooflist.ProofList{
			Root:  root,
			Query: "large.bin[2:9]",
			Steps: []prooflist.Step{
				{
					Kind:            prooflist.KindListRange,
					From:            root,
					Target:          root,
					Start:           &start,
					End:             &end,
					ChildCount:      &childCount,
					TotalSize:       &totalSize,
					ChunkSize:       &chunkSize,
					Segments:        []cid.Cid{segA, segB, segC},
					EvidenceKind:    "structure",
					EvidenceBackend: "measured_list",
					Proof:           []byte("range-proof"),
				},
			},
		}, map[string][]byte{
			segA.String(): segAData,
			segB.String(): segBData,
			segC.String(): segCData,
		}
}

func segmentFetcher(segments map[string][]byte) func(cid.Cid) ([]byte, error) {
	return func(id cid.Cid) ([]byte, error) {
		data, ok := segments[id.String()]
		if !ok {
			return nil, errors.New("segment not found")
		}
		return append([]byte(nil), data...), nil
	}
}

func rangeBodyCIDForBytes(t *testing.T, data []byte) cid.Cid {
	t.Helper()
	sum, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("hash bytes: %v", err)
	}
	return cid.NewCidV1(cid.Raw, sum)
}

func rangeBodyCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	sum, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("hash seed: %v", err)
	}
	return cid.NewCidV1(cid.Raw, sum)
}
