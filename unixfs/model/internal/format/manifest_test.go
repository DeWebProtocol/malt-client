package format_test

import (
	"testing"

	unixfsformat "github.com/dewebprotocol/malt-client/unixfs/model/internal/format"
	"github.com/dewebprotocol/malt/wire/maltcid"
)

func TestNewManifestCID(t *testing.T) {
	payload := []byte(`{"entries":["docs","readme.md"]}`)
	c, err := unixfsformat.NewManifestCID(payload)
	if err != nil {
		t.Fatalf("NewManifestCID: %v", err)
	}
	if c.Prefix().Codec != unixfsformat.CodecMaltManifest {
		t.Fatalf("codec %x, want %x", c.Prefix().Codec, unixfsformat.CodecMaltManifest)
	}
	if !unixfsformat.IsManifestCID(c) {
		t.Fatal("manifest CID should be recognized")
	}
}

func TestCodecName(t *testing.T) {
	if got := unixfsformat.CodecName(unixfsformat.CodecMaltManifest); got != "malt-manifest" {
		t.Fatalf("CodecName = %q, want malt-manifest", got)
	}
}

func TestManifestCIDDoesNotOverlapMaltStructureCID(t *testing.T) {
	manifestCID, err := unixfsformat.NewManifestCID([]byte(`{"entries":["a.txt"]}`))
	if err != nil {
		t.Fatalf("NewManifestCID: %v", err)
	}
	if codec := manifestCID.Prefix().Codec; codec >= 0x300000 && codec <= 0x30ffff {
		t.Fatalf("manifest codec %x occupies the reserved 0x30VSBB typed-root namespace", codec)
	}
	if maltcid.IsMaltCid(manifestCID) {
		t.Fatal("manifest CID should not be recognized as a MALT map/list root")
	}
	if got := maltcid.SemanticKindOf(manifestCID); got != maltcid.SemanticKindUnknown {
		t.Fatalf("manifest semantic kind = %q, want %q", got, maltcid.SemanticKindUnknown)
	}
	if got := maltcid.GetMaltCodec(manifestCID); got != 0 {
		t.Fatalf("manifest malt codec = %x, want 0", got)
	}

	mapCID, err := maltcid.NewMapKZGCid(make([]byte, maltcid.KZGCommitmentSize))
	if err != nil {
		t.Fatalf("NewMapKZGCid: %v", err)
	}
	if unixfsformat.IsManifestCID(mapCID) {
		t.Fatal("MALT map root should not be recognized as a UnixFS manifest")
	}

	listCID, err := maltcid.NewListKZGCid(make([]byte, maltcid.KZGCommitmentSize))
	if err != nil {
		t.Fatalf("NewListKZGCid: %v", err)
	}
	if unixfsformat.IsManifestCID(listCID) {
		t.Fatal("MALT list root should not be recognized as a UnixFS manifest")
	}
}
