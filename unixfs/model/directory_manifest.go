package unixfs

import (
	"slices"

	unixfsformat "github.com/dewebprotocol/malt-client/unixfs/model/internal/format"
	"github.com/dewebprotocol/malt-client/unixfs/model/internal/manifest"
	cid "github.com/ipfs/go-cid"
)

// DirectoryManifestCodec is the UnixFS manifest CID codec.
const DirectoryManifestCodec = unixfsformat.CodecMaltManifest

// NewDirectoryManifestCID creates a CID for a directory manifest payload.
func NewDirectoryManifestCID(payload []byte) (cid.Cid, error) {
	return unixfsformat.NewManifestCID(payload)
}

// IsDirectoryManifestCID reports whether a CID uses the UnixFS manifest codec.
func IsDirectoryManifestCID(value cid.Cid) bool {
	return unixfsformat.IsManifestCID(value)
}

// DirectoryManifestPayload serializes directory entries using the UnixFS
// manifest payload format.
func DirectoryManifestPayload(entries []string) ([]byte, error) {
	return manifest.MarshalDirectoryEntries(entries)
}

// ParseDirectoryManifest parses already-fetched manifest bytes. CAS access is
// intentionally owned by client/runtime adapters rather than the model.
func ParseDirectoryManifest(data []byte) ([]string, error) {
	value, err := manifest.ParseDirectoryJSON(data)
	if err != nil {
		return nil, err
	}
	return slices.Clone(value.Entries), nil
}
