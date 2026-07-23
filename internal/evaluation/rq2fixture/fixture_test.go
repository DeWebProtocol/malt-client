package rq2fixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

func TestDecodeAndOracleBindExactSource(t *testing.T) {
	fixture, view, raw := testFixture(t)
	if err := fixture.ValidateInitialView(view, "kzg"); err != nil {
		t.Fatal(err)
	}
	hostile := fixture.InitialSource()
	hostile["document.txt"][0] ^= 0xff
	if err := fixture.ValidateViewAgainstSource(view, "kzg", hostile); err == nil {
		t.Fatal("source bytes unrelated to the authenticated CID passed the oracle")
	}

	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := Decode(unknown); err == nil {
		t.Fatal("unknown fixture field was accepted")
	}
	duplicate := []byte(`{"schema_version":"malt-rq2-source-fixture/v1","schema_version":"malt-rq2-source-fixture/v1"}`)
	if _, err := Decode(duplicate); err == nil {
		t.Fatal("duplicate fixture field was accepted")
	}
}

func TestDocumentEditUsesRetainedExactPostImage(t *testing.T) {
	fixture, _, _ := testFixture(t)
	operation, err := fixture.Operation("document-edit-cid-binding-submit")
	if err != nil {
		t.Fatal(err)
	}
	initial := fixture.InitialSource()
	first, payloads, err := fixture.ApplySourceOperation(initial, operation, 0)
	if err != nil || len(payloads) != 1 {
		t.Fatal(err)
	}
	second, _, err := fixture.ApplySourceOperation(first, operation, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(second["document.txt"]), len(initial["document.txt"])+2*int(operation.PayloadBytes); got != want {
		t.Fatalf("retained document bytes = %d, want %d", got, want)
	}
}

func testFixture(t *testing.T) (*Fixture, mutation.UpdateView, []byte) {
	t.Helper()
	data := []byte("document bytes")
	key, err := clientcas.CIDForBlock(clientcas.Block{Codec: cid.Raw, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	mapper, err := mappingradix.NewMap(scheme, materializermemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	root, err := mapper.Commit(context.Background(), "root", mapping.NewViewFrom(map[string]cid.Cid{"document.txt": key}))
	if err != nil {
		t.Fatal(err)
	}
	coordinate, _ := arcset.NewMapCoordinate("document.txt")
	entries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{{Coordinate: coordinate, Target: arcset.NewCASTarget(key)}})
	if err != nil {
		t.Fatal(err)
	}
	view := mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile, BaseRoot: root,
		Bounds:  mutation.UpdateViewBounds{MaxObjects: 2, MaxTotalEntries: 8, MaxDepth: 2},
		Objects: []mutation.UpdateObject{{ObjectID: "root", Root: root, Kind: arcset.KindMap, Entries: entries}},
	}
	seed := sha256.Sum256([]byte("fixture seed"))
	value := Fixture{
		SchemaVersion: SchemaVersion, FixtureID: "fixture", MutationSeedSHA256: hex.EncodeToString(seed[:]),
		InitialRoots: []RootBinding{{Backend: "kzg", CID: root.String()}},
		DirectFiles:  []DirectFile{{Path: "document.txt", Coordinate: "document.txt", Bytes: data, CID: key.String()}},
		Operations: []Operation{{
			Name: "document-edit-cid-binding-submit", Kind: KindDocumentEdit,
			SourcePath: "document.txt", SourceCoordinate: "document.txt", PayloadBytes: 32,
		}},
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, view, raw
}
