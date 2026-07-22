package clientroot

import (
	"context"
	"errors"
	"testing"

	"github.com/dewebprotocol/malt/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	clientwriter "github.com/dewebprotocol/malt/sdk/writer"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestSessionAdvancesOnlyAfterExactDurableReceipt(t *testing.T) {
	view, intent, runtime := sessionFixture(t)
	remote := &sessionRemote{view: view}
	session, err := New(remote, runtime)
	if err != nil {
		t.Fatal(err)
	}
	load, err := session.Load(t.Context(), view.BaseRoot, &protocol.UpdateViewBounds{MaxObjects: 8, MaxTotalEntries: 64, MaxDepth: 8})
	if err != nil {
		t.Fatal(err)
	}
	if load.UpdateViewWireBytes != 123 || !session.BaseRoot().Equals(view.BaseRoot) {
		t.Fatalf("load = %#v base=%s", load, session.BaseRoot())
	}
	snapshot, err := session.SnapshotView()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Objects[0].ObjectID = "mutated-copy"
	retained, err := session.SnapshotView()
	if err != nil || retained.Objects[0].ObjectID == "mutated-copy" {
		t.Fatalf("SnapshotView leaked mutable session state: %#v, %v", retained, err)
	}
	result, err := session.Execute(t.Context(), "native-map-replace", intent)
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidate.Equals(view.BaseRoot) || !session.BaseRoot().Equals(result.Candidate) {
		t.Fatalf("result=%#v base=%s", result, session.BaseRoot())
	}
	wantViewDigest, err := view.Digest()
	if err != nil {
		t.Fatal(err)
	}
	canonicalIntent, err := mutation.NormalizeSemanticIntent(view, intent)
	if err != nil {
		t.Fatal(err)
	}
	wantIntentDigest, err := canonicalIntent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if result.ViewDigest != wantViewDigest || result.IntentDigest != wantIntentDigest {
		t.Fatalf("prepared canonical evidence = %x/%x, want %x/%x", result.ViewDigest, result.IntentDigest, wantViewDigest, wantIntentDigest)
	}
	if result.Metrics.BundleWireBytes != 456 || result.Metrics.ReceiptWireBytes != 78 || result.Metrics.Gateway.PersistNS != 3 {
		t.Fatalf("metrics = %#v", result.Metrics)
	}
	next, err := session.SnapshotView()
	if err != nil || !next.BaseRoot.Equals(result.Candidate) {
		t.Fatalf("retained next view = %#v, %v", next, err)
	}
	if err := session.Audit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRejectsReceiptSubstitutionWithoutAdvancing(t *testing.T) {
	view, intent, runtime := sessionFixture(t)
	remote := &sessionRemote{view: view, substituteReceipt: true}
	session, err := New(remote, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Load(t.Context(), view.BaseRoot, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Execute(t.Context(), "hostile-receipt", intent); err == nil {
		t.Fatal("substituted receipt was accepted")
	}
	if !session.BaseRoot().Equals(view.BaseRoot) {
		t.Fatal("rejected receipt advanced the writer base")
	}
	remote.submitErr = errors.New("persistence failed")
	remote.substituteReceipt = false
	if _, err := session.Execute(t.Context(), "persist-failure", intent); !errors.Is(err, remote.submitErr) {
		t.Fatalf("submit error = %v", err)
	}
	if !session.BaseRoot().Equals(view.BaseRoot) {
		t.Fatal("persistence failure advanced the writer base")
	}
}

type sessionRemote struct {
	view              mutation.UpdateView
	substituteReceipt bool
	submitErr         error
}

func (r *sessionRemote) FetchUpdateView(_ context.Context, root cid.Cid, _ *protocol.UpdateViewBounds) (ViewEnvelope, error) {
	if !root.Equals(r.view.BaseRoot) {
		return ViewEnvelope{}, errors.New("unexpected root")
	}
	return ViewEnvelope{View: r.view, WireBytes: 123}, nil
}

func (r *sessionRemote) SubmitClientRoot(_ context.Context, bundle mutation.ClientRootBundle) (ReceiptEnvelope, error) {
	if r.submitErr != nil {
		return ReceiptEnvelope{}, r.submitErr
	}
	digest, err := bundle.Digest()
	if err != nil {
		return ReceiptEnvelope{}, err
	}
	candidate := bundle.Candidate
	if r.substituteReceipt {
		candidate = bundle.View.BaseRoot
	}
	return ReceiptEnvelope{
		Receipt: mutation.MaterializationReceipt{
			Profile: mutation.MaterializationReceiptProfile, OperationID: bundle.OperationID,
			BaseRoot: bundle.View.BaseRoot, Candidate: candidate, BundleDigest: digest,
			DurableBoundary: "gateway-client-root-atomic-v1",
		},
		RequestWireBytes: 456, ResponseWireBytes: 78,
		Gateway: GatewayPhaseMetrics{OldStateValidationNS: 1, GatewayReplayNS: 2, PersistNS: 3, ReceiptNS: 4},
	}, nil
}

func sessionFixture(t *testing.T) (mutation.UpdateView, mutation.SemanticIntent, *clientwriter.Runtime) {
	t.Helper()
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	oldPayload := sessionRawCID(t, "old")
	newPayload := sessionRawCID(t, "new")
	oldMap, err := mappingradix.NewMap(scheme, materializermemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	oldRoot, err := oldMap.Commit(ctx, "fixture", mapping.NewViewFrom(map[string]cid.Cid{"payload": oldPayload}))
	if err != nil {
		t.Fatal(err)
	}
	coordinate, err := arcset.NewMapCoordinate("payload")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{{Coordinate: coordinate, Target: arcset.NewCASTarget(oldPayload)}})
	if err != nil {
		t.Fatal(err)
	}
	view := mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot: oldRoot, Bounds: mutation.UpdateViewBounds{MaxObjects: 8, MaxTotalEntries: 64, MaxDepth: 8},
		Objects: []mutation.UpdateObject{{ObjectID: "root", Root: oldRoot, Kind: arcset.KindMap, Entries: entries}},
	}
	before := arcset.NewCASTarget(oldPayload)
	after := arcset.NewCASTarget(newPayload)
	intent := mutation.SemanticIntent{
		Profile: mutation.SemanticIntentProfile, BaseRoot: oldRoot, TopOutputID: "root-output",
		Transitions: []mutation.IntentTransition{{
			ID: "root-output", ObjectID: "root", OldRoot: oldRoot, Kind: arcset.KindMap, Backend: maltcid.BackendKindKZG,
			Changes: []mutation.IntentChange{{Coordinate: coordinate, Before: &before, After: &after}},
		}},
	}
	runtime, err := clientwriter.NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{maltcid.BackendKindKZG: scheme})
	if err != nil {
		t.Fatal(err)
	}
	return view, intent, runtime
}

func sessionRawCID(t *testing.T, value string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(value), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}
