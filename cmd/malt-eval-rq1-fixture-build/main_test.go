package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestBuildMALTProducesExactDepthTrie(t *testing.T) {
	payload := deterministicPayload()
	payloadCID, err := cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}.Sum(payload)
	if err != nil {
		t.Fatal(err)
	}
	root, objects, err := buildMALT(context.Background(), payloadCID)
	if err != nil {
		t.Fatal(err)
	}
	if maltcid.BackendKindOf(root) != maltcid.BackendKindKZG || maltcid.SemanticKindOf(root) != maltcid.SemanticKindMap {
		t.Fatalf("root = %s", root)
	}
	// 1 root + (D-1) intermediate maps for each disjoint first segment.
	if len(objects) != 1+(1-1)+(2-1)+(4-1)+(8-1) {
		t.Fatalf("object count = %d", len(objects))
	}
	top := objects[len(objects)-1]
	if !top.root.Equals(root) || len(top.entries) != len(exactDepths) {
		t.Fatalf("top object = %#v", top)
	}
	for _, name := range []string{"d1", "d2", "d4", "d8"} {
		if !top.entries[name].Defined() {
			t.Fatalf("top object lacks %q", name)
		}
	}
}

func TestFixtureValidationRequiresSharedCompatibilityRoot(t *testing.T) {
	payload := deterministicPayload()
	digest := sha256.Sum256(payload)
	payloadCID, err := cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}.Sum(payload)
	if err != nil {
		t.Fatal(err)
	}
	compatibilityRoot, err := cid.Prefix{Version: 1, Codec: cid.DagProtobuf, MhType: mh.SHA2_256, MhLength: -1}.Sum([]byte("compatibility-root"))
	if err != nil {
		t.Fatal(err)
	}
	maltRoot, _, err := buildMALT(context.Background(), payloadCID)
	if err != nil {
		t.Fatal(err)
	}
	value := fixture{
		SchemaVersion: fixtureSchema, FixtureID: fixtureIdentifier,
		Payload: payloadFixture{CID: payloadCID.String(), Bytes: uint64(len(payload)), SHA256: hex.EncodeToString(digest[:])},
		Depths:  cloneDepths(exactDepths),
		Routes: []routeRoot{
			{Route: "trusted-path-gateway", Root: compatibilityRoot.String()}, {Route: "trustless-car", Root: compatibilityRoot.String()},
			{Route: "direct-cas", Root: compatibilityRoot.String()}, {Route: "malt-kzg", Root: maltRoot.String()},
		},
		UnixFSProfile: unixFSProfile, MALTProfile: maltProfile, Verification: verificationMode, BootstrapCount: bootstrapObjects,
	}
	if err := value.validate(); err != nil {
		t.Fatal(err)
	}
	value.Routes[1].Root = payloadCID.String()
	if err := value.validate(); err == nil {
		t.Fatal("different CAR root was accepted")
	}
}

func TestDeterministicPayloadIsStable(t *testing.T) {
	first, second := deterministicPayload(), deterministicPayload()
	if len(first) != payloadBytes || !bytes.Equal(first, second) {
		t.Fatal("fixture payload is not stable")
	}
	digest := sha256.Sum256(first)
	if hex.EncodeToString(digest[:]) != "432f51b0d64d9bcdf2e738ee846a9f5740646e0bb1cc095616293e6cac8bfe40" {
		t.Fatalf("payload digest = %x", digest)
	}
}
