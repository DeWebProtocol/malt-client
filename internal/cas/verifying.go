package cas

import (
	"context"
	"errors"
	"fmt"

	cid "github.com/ipfs/go-cid"
)

// ErrCorruptedBlock is returned when a CAS Get returns bytes whose multihash
// does not match the requested CID. The MALT trust model treats CAS as
// untrusted execution state (see ARCHITECTURE.md, section "Trust Model"); a
// reader that does not verify hashes lets a compromised CAS substitute
// arbitrary content underneath ProofList header guarantees.
var ErrCorruptedBlock = errors.New("cas: returned block does not match requested CID")

// VerifyingReader wraps a CAS Reader and validates that bytes returned by Get
// hash to the requested CID. It also forwards Has unchanged and, if the
// underlying reader implements BatchReader, exposes HasBatch.
//
// The verification is intentionally cheap: it reuses the multihash carried in
// the requested CID, recomputes it over the returned bytes, and rejects on
// mismatch. Callers that want to skip verification (for example for
// non-content-addressed identifiers) must call the underlying reader
// directly.
type VerifyingReader struct {
	inner Reader
}

// NewVerifyingReader wraps r so that Get verifies returned bytes against the
// requested CID. A nil inner reader is treated as a programming error.
func NewVerifyingReader(r Reader) *VerifyingReader {
	if r == nil {
		panic("cas: NewVerifyingReader called with nil reader")
	}
	return &VerifyingReader{inner: r}
}

// Inner returns the wrapped reader, useful for tests and adapters that need
// to bypass verification deliberately.
func (v *VerifyingReader) Inner() Reader {
	return v.inner
}

// Get returns the bytes for c only if their multihash matches c. Returned
// errors from the underlying reader are propagated unchanged; verification
// failures are wrapped with ErrCorruptedBlock so callers can identify them
// with errors.Is.
func (v *VerifyingReader) Get(ctx context.Context, c cid.Cid) ([]byte, error) {
	if !c.Defined() {
		// Refuse to issue a Get for an undefined CID at all. There is no
		// hash to validate against, and any returned bytes would be
		// indistinguishable from forged content.
		return nil, fmt.Errorf("%w: undefined CID", ErrCorruptedBlock)
	}
	data, err := v.inner.Get(ctx, c)
	if err != nil {
		return nil, err
	}
	got, err := cidForData(c, data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptedBlock, err)
	}
	if !got.Equals(c) {
		return nil, fmt.Errorf("%w: got %s want %s", ErrCorruptedBlock, got.String(), c.String())
	}
	return data, nil
}

// Has forwards to the underlying reader.
func (v *VerifyingReader) Has(ctx context.Context, c cid.Cid) (bool, error) {
	return v.inner.Has(ctx, c)
}

// HasBatch forwards when the underlying reader supports it. Implementations
// that do not implement BatchReader fall through to per-CID Has checks via
// the cas package contract elsewhere; here we only forward the optimization.
func (v *VerifyingReader) HasBatch(ctx context.Context, cids []cid.Cid) ([]bool, error) {
	if br, ok := v.inner.(BatchReader); ok {
		return br.HasBatch(ctx, cids)
	}
	results := make([]bool, len(cids))
	for i, c := range cids {
		ok, err := v.inner.Has(ctx, c)
		if err != nil {
			return nil, err
		}
		results[i] = ok
	}
	return results, nil
}

// errReadOnlyCAS is returned when a write method is called against a wrapper
// whose inner reader does not support that write surface. Tests inject
// pure-reader CAS implementations (mock.shortReader, etc.); we expose the
// error so callers can distinguish "not configured" from "rejected".
var errReadOnlyCAS = errors.New("cas: underlying reader does not support writes")

// Put forwards to the inner reader if it implements Writer and verifies the
// returned CID actually matches the bytes that were written. A malicious
// remote CAS that swaps in a fabricated CID at upload time would otherwise
// let a MALT root reference content the writer never produced. cas.Writer
// is the codec-less surface, so the requested codec is implicitly cid.Raw.
func (v *VerifyingReader) Put(ctx context.Context, data []byte) (cid.Cid, error) {
	w, ok := v.inner.(Writer)
	if !ok {
		return cid.Undef, errReadOnlyCAS
	}
	got, err := w.Put(ctx, data)
	if err != nil {
		return cid.Undef, err
	}
	return verifyPutResult(got, data, cid.Raw)
}

// PutWithCodec forwards to the inner reader if it implements TypedWriter and
// verifies the returned CID matches the bytes plus the codec that were
// requested. Validating against the requested codec (rather than the codec
// the writer chose to embed in the returned CID) prevents a hostile CAS
// from accepting typed-block bytes and committing them under a cid.Raw CID
// — that would still hash-match the bytes but mean a downstream consumer
// reads them with the wrong codec.
//
// Falls back to Put for cid.Raw when typed writes are unavailable.
func (v *VerifyingReader) PutWithCodec(ctx context.Context, data []byte, codec uint64) (cid.Cid, error) {
	if tw, ok := v.inner.(TypedWriter); ok {
		got, err := tw.PutWithCodec(ctx, data, codec)
		if err != nil {
			return cid.Undef, err
		}
		return verifyPutResult(got, data, codec)
	}
	if NormalizeCodec(codec) == cid.Raw {
		return v.Put(ctx, data)
	}
	return cid.Undef, errReadOnlyCAS
}

// PutBatch forwards to the inner reader if it implements BatchWriter, then
// verifies every returned CID against its source bytes and the codec the
// caller asked for. The non-batch fallback dispatches per-block through the
// wrapper's verifying PutWithCodec so corrupt CIDs are rejected at the same
// boundary as the batch path.
func (v *VerifyingReader) PutBatch(ctx context.Context, blocks []Block) ([]PutResult, error) {
	if len(blocks) == 0 {
		return []PutResult{}, nil
	}
	if bw, ok := v.inner.(BatchWriter); ok {
		results, err := bw.PutBatch(ctx, blocks)
		if err != nil {
			return nil, err
		}
		if err := verifyBatchResults(blocks, results); err != nil {
			return nil, err
		}
		return results, nil
	}
	if _, ok := v.inner.(Writer); !ok {
		return nil, errReadOnlyCAS
	}
	results := make([]PutResult, len(blocks))
	for i, b := range blocks {
		codec := NormalizeCodec(b.Codec)
		got, err := v.PutWithCodec(ctx, b.Data, codec)
		if err != nil {
			return nil, err
		}
		results[i] = PutResult{CID: got, Status: PutStatusStored}
	}
	return results, nil
}

// verifyPutResult validates that a writer's claimed CID matches the
// canonical CID for the requested bytes and codec. The expected CID is
// derived locally via CIDForBlock — that is the repo-wide write contract
// (see storage/cas/cas.go: CIDv1 + SHA2-256 + NormalizeCodec). Anchoring
// to that contract — instead of recomputing using the *returned* CID's
// prefix — closes three classes of attack:
//
//   - returning a different codec for the same bytes (downstream consumers
//     would decode with the wrong codec);
//   - returning a CID with a weaker multihash (e.g. SHA-1) that happens to
//     match the bytes, downgrading the integrity guarantee;
//   - returning CIDv0 for a payload the writer was asked to store as
//     CIDv1 (or vice versa), confusing later resolution.
//
// requestedCodec is normalized via NormalizeCodec so callers can pass
// either 0 or cid.Raw to mean "raw" without ambiguity.
func verifyPutResult(got cid.Cid, data []byte, requestedCodec uint64) (cid.Cid, error) {
	if !got.Defined() {
		return cid.Undef, fmt.Errorf("%w: writer returned undefined CID", ErrCorruptedBlock)
	}
	want, err := CIDForBlock(Block{Data: data, Codec: requestedCodec})
	if err != nil {
		return cid.Undef, fmt.Errorf("%w: %v", ErrCorruptedBlock, err)
	}
	if !want.Equals(got) {
		return cid.Undef, fmt.Errorf("%w: writer returned %s, canonical CID for the bytes is %s", ErrCorruptedBlock, got, want)
	}
	return got, nil
}

// verifyBatchResults walks parallel slices of input blocks and writer
// results, recomputing the CID for every entry. The wrapper requires every
// returned PutResult to commit to a defined CID with the codec that was
// asked for: runtime/unixfs writes the chunk list straight from the
// PutResult slice, and propagating an
// undefined or codec-mismatched CID would let a hostile or buggy CAS
// produce a root with invalid chunk references.
func verifyBatchResults(blocks []Block, results []PutResult) error {
	if len(results) != len(blocks) {
		return fmt.Errorf("%w: writer returned %d results for %d blocks", ErrCorruptedBlock, len(results), len(blocks))
	}
	for i, r := range results {
		if _, err := verifyPutResult(r.CID, blocks[i].Data, blocks[i].Codec); err != nil {
			return err
		}
	}
	return nil
}

// SnapshotStats forwards to the inner reader if it provides a metrics
// snapshot. This keeps the metrics pipeline transparent through the wrapper.
func (v *VerifyingReader) SnapshotStats() Stats {
	if s, ok := v.inner.(interface{ SnapshotStats() Stats }); ok {
		return s.SnapshotStats()
	}
	return Stats{}
}

// ResetStats forwards to the inner reader when supported.
func (v *VerifyingReader) ResetStats() {
	if r, ok := v.inner.(interface{ ResetStats() }); ok {
		r.ResetStats()
	}
}

// cidForData recomputes the CID for data using the same codec and multihash
// algorithm as the requested CID. Reusing the requested CID's prefix keeps
// the comparison meaningful even for non-default codecs (DAG-CBOR, DAG-JSON,
// etc.).
func cidForData(want cid.Cid, data []byte) (cid.Cid, error) {
	prefix := want.Prefix()
	return prefix.Sum(data)
}
