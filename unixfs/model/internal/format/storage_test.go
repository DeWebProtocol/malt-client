package format

import (
	"testing"

	maltcid "github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestStorageKindFromCIDUsesMALTSemanticKind(t *testing.T) {
	mapRoot, err := maltcid.NewMapKZGCid(make([]byte, maltcid.KZGCommitmentSize))
	if err != nil {
		t.Fatal(err)
	}
	listRoot, err := maltcid.NewListIPACid(make([]byte, maltcid.IPACommitmentSize))
	if err != nil {
		t.Fatal(err)
	}
	rawHash, err := mh.Sum([]byte("raw"), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	raw := cid.NewCidV1(cid.Raw, rawHash)

	for name, test := range map[string]struct {
		cid  cid.Cid
		want string
	}{
		"undefined": {cid: cid.Undef, want: ""},
		"raw":       {cid: raw, want: "raw"},
		"map":       {cid: mapRoot, want: "map"},
		"list":      {cid: listRoot, want: "list"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := StorageKindFromCID(test.cid); got != test.want {
				t.Fatalf("StorageKindFromCID() = %q, want %q", got, test.want)
			}
		})
	}
}
