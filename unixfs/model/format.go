package unixfs

import (
	unixfsformat "github.com/dewebprotocol/malt-client/unixfs/model/internal/format"
	cid "github.com/ipfs/go-cid"
)

// StorageKindFromCID projects a UnixFS payload CID into the public storage
// kind vocabulary used by client and gateway adapters.
func StorageKindFromCID(c cid.Cid) string {
	return unixfsformat.StorageKindFromCID(c)
}

// DirectoryRootBindings builds the map bindings for a materialized UnixFS
// directory root.
func DirectoryRootBindings(payload cid.Cid, children map[string]cid.Cid, descendants map[string]cid.Cid) map[string]string {
	return unixfsformat.DirectoryRootBindings(payload, children, descendants)
}

// CountDefinedBindings counts non-empty create-structure bindings.
func CountDefinedBindings(bindings map[string]string) int {
	return unixfsformat.CountDefinedBindings(bindings)
}
