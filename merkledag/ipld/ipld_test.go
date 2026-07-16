package ipld_test

import (
	"context"
	"testing"

	clientipld "github.com/dewebprotocol/malt-client/merkledag/ipld"
	cid "github.com/ipfs/go-cid"
)

type memoryBlocks map[string][]byte

func (m memoryBlocks) Get(_ context.Context, key cid.Cid) ([]byte, error) {
	return append([]byte(nil), m[key.String()]...), nil
}

func TestParserFollowsDAGJSONLinkAndBindsEveryBlockCID(t *testing.T) {
	raw, rawCID, err := clientipld.CreateRawBlock([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	dagJSON, root, err := clientipld.CreateDAGJSON(map[string]any{
		"child":  rawCID,
		"nested": []any{map[string]any{"again": rawCID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	blocks := memoryBlocks{root.String(): dagJSON, rawCID.String(): raw}
	parser := clientipld.NewParser(blocks)
	node, err := parser.ParseBlock(root, dagJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(node.Links) != 2 || node.Links[0].Name != "child" || node.Links[1].Name != "nested/0/again" {
		t.Fatalf("DAG-JSON links = %#v", node.Links)
	}
	followed, err := parser.FollowLink(t.Context(), root, "child")
	if err != nil {
		t.Fatal(err)
	}
	if string(followed.Data) != "payload" || followed.Codec != clientipld.CodecRaw {
		t.Fatalf("followed node = %#v", followed)
	}
	tampered := append([]byte(nil), dagJSON...)
	tampered[len(tampered)-1] ^= 1
	if _, err := parser.ParseBlock(root, tampered); err == nil {
		t.Fatal("parser accepted bytes that do not match the caller-selected CID")
	}
}

func TestCodecRegistryCanAddApplicationCodec(t *testing.T) {
	// Keep the application codec in the private-use area but outside MALT's
	// 0x30VSBB typed-root namespace.
	const codec = 0x320001
	data := []byte("custom")
	_, key, err := func() ([]byte, cid.Cid, error) {
		// Reuse a raw CID prefix then replace the codec for the custom registry.
		body, raw, err := clientipld.CreateRawBlock(data)
		if err != nil {
			return nil, cid.Undef, err
		}
		return body, cid.NewCidV1(codec, raw.Hash()), nil
	}()
	if err != nil {
		t.Fatal(err)
	}
	registry := clientipld.NewRegistry()
	registry.Register(codec, func(_ cid.Cid, body []byte) (*clientipld.Node, error) {
		return &clientipld.Node{Codec: clientipld.Codec(codec), Data: append([]byte(nil), body...)}, nil
	})
	parser := clientipld.NewParserWithRegistry(nil, registry)
	node, err := parser.ParseBlock(key, data)
	if err != nil {
		t.Fatal(err)
	}
	if string(node.Data) != "custom" {
		t.Fatalf("custom node = %#v", node)
	}
}
