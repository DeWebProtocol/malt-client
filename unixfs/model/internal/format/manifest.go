// Package format defines UnixFS application-model format constants.
package format

import (
	"fmt"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// CodecMaltManifest is the UnixFS manifest CID codec.
const CodecMaltManifest = 0x300005 // malt-manifest

// NewManifestCID creates a CID for a directory manifest payload.
func NewManifestCID(payload []byte) (cid.Cid, error) {
	mhash, err := mh.Sum(payload, mh.SHA2_256, -1)
	if err != nil {
		return cid.Undef, fmt.Errorf("failed to create manifest multihash: %w", err)
	}
	return cid.NewCidV1(CodecMaltManifest, mhash), nil
}

// IsManifestCID reports whether c is a UnixFS model manifest CID.
func IsManifestCID(c cid.Cid) bool {
	return c.Defined() && c.Prefix().Codec == CodecMaltManifest
}

// CodecName returns the locked wire name for UnixFS codecs.
func CodecName(codec uint64) string {
	switch codec {
	case CodecMaltManifest:
		return "malt-manifest"
	default:
		return fmt.Sprintf("unknown-%x", codec)
	}
}
