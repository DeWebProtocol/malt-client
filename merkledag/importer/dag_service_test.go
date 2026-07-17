package importer

import (
	"context"
	"errors"
	"strings"
	"testing"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	cid "github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
)

type failingStore struct {
	err error
}

func (s failingStore) PutWithCodec(context.Context, []byte, uint64) (cid.Cid, error) {
	return cid.Undef, errors.New("unexpected put")
}

func (s failingStore) Get(context.Context, cid.Cid) ([]byte, error) {
	return nil, s.err
}

func TestDAGServiceMapsCASNotFound(t *testing.T) {
	key := mustRawCID(t, []byte("missing"))
	_, err := NewDAGService(failingStore{err: clientcas.ErrNotFound}).Get(t.Context(), key)
	var notFound ipld.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("Get error = %T %v, want ipld.ErrNotFound", err, err)
	}
}

func TestDAGServicePreservesNonNotFoundFailure(t *testing.T) {
	key := mustRawCID(t, []byte("unavailable"))
	sourceErr := errors.New("upstream timeout")
	_, err := NewDAGService(failingStore{err: sourceErr}).Get(t.Context(), key)
	if !errors.Is(err, sourceErr) {
		t.Fatalf("Get error = %v, want source error", err)
	}
	var notFound ipld.ErrNotFound
	if errors.As(err, &notFound) {
		t.Fatalf("Get mapped non-not-found failure to ipld.ErrNotFound: %v", err)
	}
	if !strings.Contains(err.Error(), "load Merkle DAG block") {
		t.Fatalf("Get error lacks operation context: %v", err)
	}
}

func mustRawCID(t *testing.T, data []byte) cid.Cid {
	t.Helper()
	key, err := clientcas.CIDForBlock(clientcas.Block{Data: data, Codec: cid.Raw})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
