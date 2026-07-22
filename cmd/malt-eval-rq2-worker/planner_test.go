package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	"github.com/dewebprotocol/malt/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/ipa"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	listtree "github.com/dewebprotocol/malt/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt/mutation"
	clientwriter "github.com/dewebprotocol/malt/sdk/writer"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestNativePlannerExecutesAllRegisteredOperationsWithKZGAndIPA(t *testing.T) {
	for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
		t.Run(string(backend), func(t *testing.T) {
			scheme := testScheme(t, backend)
			view, fixture := nativePlannerFixture(t, scheme, backend)
			if err := fixture.ValidateInitialView(view, string(backend)); err != nil {
				t.Fatal(err)
			}
			runtime, err := clientwriter.NewRuntime(
				materializermemory.New(true),
				map[maltcid.BackendKind]commitment.IndexCommitment{backend: scheme},
			)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := runtime.VerifyUpdateView(t.Context(), view)
			if err != nil {
				t.Fatal(err)
			}
			workspace, err := newNativeWorkspace(fixture)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = workspace.close() })
			operations := []string{
				"append", "batch-sync", "create-small-file", "delete-directory-entry",
				"insert-directory-entry", "modify-small-file", "move", "rename", "replace-large-file-chunk",
			}
			for index, operation := range operations {
				declaration, err := fixture.Operation(operation)
				if err != nil {
					t.Fatalf("fixture operation %s: %v", operation, err)
				}
				prepared, err := prepareNativeOperation(declaration, fixture, workspace, uint64(index))
				if err != nil {
					t.Fatalf("prepare %s: %v", operation, err)
				}
				metadataOnly := operation == "delete-directory-entry" || operation == "move" || operation == "rename"
				if metadataOnly {
					if prepared.scan.Applicable || prepared.chunk.Applicable || prepared.hash.Applicable ||
						prepared.scan.Status != phaseNotApplicable || prepared.chunk.Status != phaseNotApplicable || prepared.hash.Status != phaseNotApplicable ||
						len(prepared.blocks) != 0 {
						t.Fatalf("%s metadata-only pipeline metrics = %#v", operation, prepared)
					}
				} else if !prepared.scan.Applicable || !prepared.chunk.Applicable || !prepared.hash.Applicable ||
					prepared.scan.Status != phaseObserved || prepared.scan.Bytes == 0 || prepared.chunk.Count == 0 || prepared.hash.Count == 0 {
					t.Fatalf("%s payload pipeline metrics = %#v", operation, prepared)
				}
				intent, err := planNativeIntent(verified.View, declaration, prepared.cids)
				if err != nil {
					t.Fatalf("plan %s: %v", operation, err)
				}
				result, err := runtime.ComputeBundle(t.Context(), "operation-"+operation, verified, intent)
				if err != nil {
					t.Fatalf("compute %s: %v", operation, err)
				}
				if result.Bundle.Candidate.Equals(verified.View.BaseRoot) || maltcid.BackendKindOf(result.Bundle.Candidate) != backend {
					t.Fatalf("%s candidate = %s", operation, result.Bundle.Candidate)
				}
				verified, err = runtime.VerifyUpdateView(t.Context(), result.NextView)
				if err != nil {
					t.Fatalf("verify next view after %s: %v", operation, err)
				}
				source, err := workspace.snapshot()
				if err != nil {
					t.Fatalf("scan post-image after %s: %v", operation, err)
				}
				if err := fixture.ValidateViewAgainstSource(verified.View, string(backend), source); err != nil {
					t.Fatalf("full post-image oracle after %s: %v", operation, err)
				}
			}
			if _, err := os.Stat(workspace.root); err != nil {
				t.Fatalf("real workspace disappeared: %v", err)
			}
		})
	}
}

func TestNativePlannerRejectsSharedListLineage(t *testing.T) {
	scheme := testScheme(t, maltcid.BackendKindKZG)
	view, fixture := nativePlannerFixture(t, scheme, maltcid.BackendKindKZG)
	root := view.Objects[1]
	if !root.Root.Equals(view.BaseRoot) {
		root = view.Objects[0]
	}
	listObject, err := listObjectForPath(view, "large.bin")
	if err != nil {
		t.Fatal(err)
	}
	second, err := arcset.NewMapCoordinate("second-list-reference")
	if err != nil {
		t.Fatal(err)
	}
	entries := append(root.Entries.Entries(), arcset.ArcEntry{Coordinate: second, Target: arcset.NewListTarget(listObject.Root)})
	root.Entries, err = arcset.NewCanonicalArcSet(arcset.KindMap, entries)
	if err != nil {
		t.Fatal(err)
	}
	for index := range view.Objects {
		if view.Objects[index].Root.Equals(view.BaseRoot) {
			view.Objects[index] = root
		}
	}
	for index := range view.Objects {
		if view.Objects[index].ObjectID == "root" {
			view.Objects[index] = root
		}
	}
	operation, err := fixture.Operation("append")
	if err != nil {
		t.Fatal(err)
	}
	payload := testRawCID(t, []byte("replacement"))
	if _, err := planNativeIntent(view, operation, []cid.Cid{payload}); err == nil {
		t.Fatal("shared list object was accepted as an unambiguous update target")
	}
}

func TestBrowserPreflightFailsClosedWithoutRealBrowserWorker(t *testing.T) {
	w := &worker{config: workerConfig{clientKind: clientBrowserWASM, backend: "kzg", lifecycle: lifecycleBrowserCold}}
	request := workerRequest{
		SchemaVersion: workerRequestSchema, WorkerID: "worker", RequestID: "preflight", RecordKind: recordPreflight,
		SessionID: "session", ClientKind: clientBrowserWASM, PlatformID: "browser", Backend: "kzg",
		Lifecycle: lifecycleBrowserCold, FixtureID: "fixture",
	}
	record := w.preflight(request)
	if record.Success || record.FailureClass != "capability_unavailable" || record.Capabilities != nil || record.Runtime != nil {
		t.Fatalf("browser preflight = %#v", record)
	}
}

func nativePlannerFixture(t *testing.T, scheme commitment.IndexCommitment, backend maltcid.BackendKind) (mutation.UpdateView, *rq2fixture.Fixture) {
	t.Helper()
	ctx := context.Background()
	directBytes := map[string][]byte{
		"small.txt":                  []byte("old-small"),
		"metadata/delete-target.txt": []byte("delete-target"),
		"metadata/move-target.txt":   []byte("move-target"),
		"metadata/rename-target.txt": []byte("rename-target"),
	}
	chunkA := make([]byte, 32)
	chunkB := make([]byte, 32)
	copy(chunkA, "chunk-a")
	copy(chunkB, "chunk-b")
	chunkACID := testRawCID(t, chunkA)
	chunkBCID := testRawCID(t, chunkB)
	store := materializermemory.New(true)
	lister, err := listtree.NewList(scheme, store)
	if err != nil {
		t.Fatal(err)
	}
	listRoot, err := lister.CommitFixed(ctx, "list", []cid.Cid{chunkACID, chunkBCID}, 32, 64)
	if err != nil {
		t.Fatal(err)
	}
	mapper, err := mappingradix.NewMap(scheme, store)
	if err != nil {
		t.Fatal(err)
	}
	bindings := map[string]cid.Cid{"large.bin": listRoot}
	for path, data := range directBytes {
		bindings[path] = testRawCID(t, data)
	}
	root, err := mapper.Commit(ctx, "root", mapping.NewViewFrom(bindings))
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]arcset.ArcEntry, 0, len(bindings))
	largeCoordinate, _ := arcset.NewMapCoordinate("large.bin")
	entries = append(entries, arcset.ArcEntry{Coordinate: largeCoordinate, Target: arcset.NewListTarget(listRoot)})
	directFiles := make([]rq2fixture.DirectFile, 0, len(directBytes))
	for path, data := range directBytes {
		coordinate, _ := arcset.NewMapCoordinate(path)
		key := bindings[path]
		entries = append(entries, arcset.ArcEntry{Coordinate: coordinate, Target: arcset.NewCASTarget(key)})
		directFiles = append(directFiles, rq2fixture.DirectFile{Path: path, Coordinate: path, Bytes: data, CID: key.String()})
	}
	rootEntries, err := arcset.NewCanonicalArcSet(arcset.KindMap, entries)
	if err != nil {
		t.Fatal(err)
	}
	listEntries, err := arcset.NewCanonicalArcSet(arcset.KindList, []arcset.ArcEntry{
		{Coordinate: arcset.NewListCoordinateUint64(0), Target: arcset.NewCASTarget(chunkACID)},
		{Coordinate: arcset.NewListCoordinateUint64(1), Target: arcset.NewCASTarget(chunkBCID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	view := mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot: root, Bounds: mutation.UpdateViewBounds{MaxObjects: 8, MaxTotalEntries: 64, MaxDepth: 8},
		Objects: []mutation.UpdateObject{
			{
				ObjectID: "large-object", Root: listRoot, Kind: arcset.KindList, Entries: listEntries,
				Commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{ChunkSize: 32, TotalSize: 64}},
			},
			{ObjectID: "root", Root: root, Kind: arcset.KindMap, Entries: rootEntries},
		},
	}
	zero := uint64(0)
	seed := sha256.Sum256([]byte("native fixture mutation seed"))
	fixtureValue := rq2fixture.Fixture{
		SchemaVersion: rq2fixture.SchemaVersion, FixtureID: "fixture",
		MutationSeedSHA256: hex.EncodeToString(seed[:]),
		InitialRoots:       []rq2fixture.RootBinding{{Backend: string(backend), CID: root.String()}},
		DirectFiles:        directFiles,
		ListFiles: []rq2fixture.ListFile{{
			Path: "large.bin", Coordinate: "large.bin", ChunkSize: 32, TotalSize: 64,
			Chunks: []rq2fixture.ListChunk{{Index: 0, Bytes: chunkA, CID: chunkACID.String()}, {Index: 1, Bytes: chunkB, CID: chunkBCID.String()}},
		}},
		Operations: []rq2fixture.Operation{
			{Name: "append", Kind: rq2fixture.KindListAppend, SourcePath: "large.bin", SourceCoordinate: "large.bin", PayloadBytes: 32},
			{Name: "batch-sync", Kind: rq2fixture.KindBatchInsert, Batch: nativeBatchTargets()},
			{Name: "create-small-file", Kind: rq2fixture.KindDirectInsert, DestinationPath: "created/file.txt", DestinationCoordinate: "created/file.txt", PayloadBytes: 16},
			{Name: "delete-directory-entry", Kind: rq2fixture.KindDirectDelete, SourcePath: "metadata/delete-target.txt", SourceCoordinate: "metadata/delete-target.txt"},
			{Name: "insert-directory-entry", Kind: rq2fixture.KindDirectInsert, DestinationPath: "entries/entry.txt", DestinationCoordinate: "entries/entry.txt", PayloadBytes: 16},
			{Name: "modify-small-file", Kind: rq2fixture.KindDirectReplace, SourcePath: "small.txt", SourceCoordinate: "small.txt", PayloadBytes: 16},
			{Name: "move", Kind: rq2fixture.KindDirectMove, SourcePath: "metadata/move-target.txt", SourceCoordinate: "metadata/move-target.txt", DestinationPath: "moved/move-target.txt", DestinationCoordinate: "moved/move-target.txt"},
			{Name: "rename", Kind: rq2fixture.KindDirectMove, SourcePath: "metadata/rename-target.txt", SourceCoordinate: "metadata/rename-target.txt", DestinationPath: "metadata/renamed.txt", DestinationCoordinate: "metadata/renamed.txt"},
			{Name: "replace-large-file-chunk", Kind: rq2fixture.KindListReplace, SourcePath: "large.bin", SourceCoordinate: "large.bin", PayloadBytes: 32, ListIndex: &zero},
		},
	}
	raw, err := json.Marshal(fixtureValue)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := rq2fixture.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return view, fixture
}

func nativeBatchTargets() []rq2fixture.BatchTarget {
	targets := make([]rq2fixture.BatchTarget, 8)
	for index := range targets {
		path := fmt.Sprintf("batch/sync-%02d.txt", index)
		targets[index] = rq2fixture.BatchTarget{Path: path, Coordinate: path, PayloadBytes: 16}
	}
	return targets
}

func testScheme(t *testing.T, backend maltcid.BackendKind) commitment.IndexCommitment {
	t.Helper()
	var scheme commitment.IndexCommitment
	var err error
	if backend == maltcid.BackendKindKZG {
		scheme, err = kzg.NewScheme()
	} else {
		scheme, err = ipa.NewScheme()
	}
	if err != nil {
		t.Fatal(err)
	}
	return scheme
}

func testRawCID(t *testing.T, value []byte) cid.Cid {
	t.Helper()
	key, err := clientcas.CIDForBlock(clientcas.Block{Codec: cid.Raw, Data: value})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
