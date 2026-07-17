package memory

import (
	"errors"
	"testing"

	"github.com/dewebprotocol/malt-client/internal/cas"
	cid "github.com/ipfs/go-cid"
)

func TestGetClassifiesMissingBlock(t *testing.T) {
	_, err := New().Get(t.Context(), cid.Undef)
	if !errors.Is(err, cas.ErrNotFound) {
		t.Fatalf("Get error = %v, want cas.ErrNotFound", err)
	}
}
