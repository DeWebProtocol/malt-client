package unixfs

import (
	"context"

	cid "github.com/ipfs/go-cid"
)

// BlockGetter is the client-side CAS read capability used while planning a
// UnixFS update. It intentionally carries no HTTP or concrete backend type.
type BlockGetter interface {
	Get(context.Context, cid.Cid) ([]byte, error)
}
