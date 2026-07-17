package importer_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-client/merkledag/importer"
	cid "github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
	mh "github.com/multiformats/go-multihash"
)

type externalMissingStore struct{}

func (externalMissingStore) PutWithCodec(context.Context, []byte, uint64) (cid.Cid, error) {
	return cid.Undef, errors.New("unexpected put")
}

func (externalMissingStore) Get(context.Context, cid.Cid) ([]byte, error) {
	return nil, fmt.Errorf("external store lookup: %w", importer.ErrNotFound)
}

func TestExternalStoreCanReportMissingBlock(t *testing.T) {
	key, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}).Sum([]byte("missing"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = importer.NewDAGService(externalMissingStore{}).Get(t.Context(), key)
	var notFound ipld.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("Get error = %T %v, want ipld.ErrNotFound", err, err)
	}
	if !notFound.Cid.Equals(key) {
		t.Fatalf("not-found CID = %s, want %s", notFound.Cid, key)
	}
}
