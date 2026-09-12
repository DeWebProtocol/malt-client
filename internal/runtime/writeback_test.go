package runtime

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"testing"

	writebackapp "github.com/dewebprotocol/malt-client/application/writeback"
	filesystemmount "github.com/dewebprotocol/malt-client/filesystem/mount"
	filesystemservice "github.com/dewebprotocol/malt-client/filesystem/service"
	"github.com/dewebprotocol/malt-client/filesystem/staging"
	gatewayclient "github.com/dewebprotocol/malt-client/transport"
	truststore "github.com/dewebprotocol/malt-client/trust"
	"github.com/dewebprotocol/malt-client/unixfs"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/protocol"
	clientwriter "github.com/dewebprotocol/malt-core/sdk/writer"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type runtimeWritebackBase struct {
	infos  map[string]filesystemservice.Info
	bodies map[string][]byte
}

func (b runtimeWritebackBase) Stat(_ context.Context, _ filesystemservice.View, name string) (filesystemservice.Info, error) {
	info, ok := b.infos[name]
	if !ok {
		return filesystemservice.Info{}, unixfs.ErrNotFound
	}
	return info, nil
}

func (b runtimeWritebackBase) ReadDir(_ context.Context, _ filesystemservice.View, directory string) ([]filesystemservice.DirEntry, error) {
	info, ok := b.infos[directory]
	if !ok {
		return nil, unixfs.ErrNotFound
	}
	if !info.IsDir() {
		return nil, unixfs.ErrNotDirectory
	}
	entries := make([]filesystemservice.DirEntry, 0)
	for name, child := range b.infos {
		if name == "" || name == directory || writebackParent(name) != directory {
			continue
		}
		entries = append(entries, filesystemservice.DirEntry{Name: path.Base(name), Kind: child.Kind})
	}
	slices.SortFunc(entries, func(left, right filesystemservice.DirEntry) int {
		if left.Name < right.Name {
			return -1
		}
		if left.Name > right.Name {
			return 1
		}
		return 0
	})
	return entries, nil
}

func (b runtimeWritebackBase) ReadFileRange(_ context.Context, _ filesystemservice.View, name string, offset, length uint64) ([]byte, filesystemservice.Info, error) {
	info, ok := b.infos[name]
	if !ok {
		return nil, filesystemservice.Info{}, unixfs.ErrNotFound
	}
	if info.IsDir() {
		return nil, info, unixfs.ErrNotFile
	}
	body := b.bodies[name]
	if offset >= uint64(len(body)) || length == 0 {
		return []byte{}, info, nil
	}
	end := offset + length
	if end < offset || end > uint64(len(body)) {
		end = uint64(len(body))
	}
	return append([]byte(nil), body[offset:end]...), info, nil
}

type writebackReplayFunc func(context.Context, filesystemservice.View) (writebackapp.Result, error)

func (f writebackReplayFunc) Replay(ctx context.Context, view filesystemservice.View) (writebackapp.Result, error) {
	return f(ctx, view)
}

type writerFactoryFunc func() (*clientwriter.Runtime, error)

func (f writerFactoryFunc) New() (*clientwriter.Runtime, error) { return f() }

type inertGatewayWritableRemote struct{}

func (inertGatewayWritableRemote) Get(context.Context, cid.Cid) ([]byte, error) {
	return nil, errors.New("unexpected Get")
}

func (inertGatewayWritableRemote) Put(_ context.Context, body []byte) (cid.Cid, error) {
	return cid.Prefix{Version: 1, Codec: cid.Raw, MhType: 0x12, MhLength: -1}.Sum(body)
}

func (inertGatewayWritableRemote) PutWithCodec(_ context.Context, body []byte, codec uint64) (cid.Cid, error) {
	return cid.Prefix{Version: 1, Codec: codec, MhType: 0x12, MhLength: -1}.Sum(body)
}

func (inertGatewayWritableRemote) FetchUpdateView(context.Context, cid.Cid, *protocol.UpdateViewBounds) (*gatewayclient.UpdateViewResponse, error) {
	return nil, errors.New("unexpected FetchUpdateView")
}

func (inertGatewayWritableRemote) SubmitClientRootResult(context.Context, clientwriter.ComputeResult) (*gatewayclient.ClientRootResponse, error) {
	return nil, errors.New("unexpected SubmitClientRoot")
}

type replayingGatewayWritableRemote struct {
	blocks    map[string][]byte
	view      mutation.UpdateView
	submitted *mutation.ClientRootBundle
}

func (r *replayingGatewayWritableRemote) Get(_ context.Context, key cid.Cid) ([]byte, error) {
	body, ok := r.blocks[key.KeyString()]
	if !ok {
		return nil, fmt.Errorf("block %s not found", key)
	}
	return append([]byte(nil), body...), nil
}

func (r *replayingGatewayWritableRemote) Put(ctx context.Context, body []byte) (cid.Cid, error) {
	return r.PutWithCodec(ctx, body, cid.Raw)
}

func (r *replayingGatewayWritableRemote) PutWithCodec(_ context.Context, body []byte, codec uint64) (cid.Cid, error) {
	key, err := cid.Prefix{Version: 1, Codec: codec, MhType: 0x12, MhLength: -1}.Sum(body)
	if err != nil {
		return cid.Undef, err
	}
	r.blocks[key.KeyString()] = append([]byte(nil), body...)
	return key, nil
}

func (r *replayingGatewayWritableRemote) FetchUpdateView(_ context.Context, root cid.Cid, _ *protocol.UpdateViewBounds) (*gatewayclient.UpdateViewResponse, error) {
	if !root.Equals(r.view.BaseRoot) {
		return nil, fmt.Errorf("unexpected update-view root %s", root)
	}
	return &gatewayclient.UpdateViewResponse{View: r.view, WireBytes: 1}, nil
}

func (r *replayingGatewayWritableRemote) SubmitClientRootResult(_ context.Context, prepared clientwriter.ComputeResult) (*gatewayclient.ClientRootResponse, error) {
	bundle := prepared.Bundle
	if prepared.Materialization.Profile != mutation.ClientRootMaterializationProfile ||
		!prepared.NextView.BaseRoot.Equals(bundle.Candidate) {
		return nil, errors.New("incomplete local writer result")
	}
	digest, err := bundle.Digest()
	if err != nil {
		return nil, err
	}
	copyBundle := bundle
	r.submitted = &copyBundle
	return &gatewayclient.ClientRootResponse{Receipt: mutation.MaterializationReceipt{
		Profile: mutation.MaterializationReceiptProfile, OperationID: bundle.OperationID,
		BaseRoot: bundle.View.BaseRoot, Candidate: bundle.Candidate, BundleDigest: digest,
		DurableBoundary: "test-gateway-atomic-v1",
	}}, nil
}

type runtimeRootCreator struct {
	scheme  commitment.IndexCommitment
	store   *materializermemory.Store
	objects []mutation.UpdateObject
}

func (c *runtimeRootCreator) CreateStagedRoot(ctx context.Context, bindings map[string]string) (cid.Cid, error) {
	objectID := fmt.Sprintf("runtime-directory-%03d", len(c.objects)+1)
	entries := make([]arcset.ArcEntry, 0, len(bindings))
	values := make(map[arcset.Path]cid.Cid, len(bindings))
	for name, raw := range bindings {
		key, err := cid.Parse(raw)
		if err != nil {
			return cid.Undef, err
		}
		coordinate, err := arcset.NewMapCoordinate(name)
		if err != nil {
			return cid.Undef, err
		}
		entries = append(entries, arcset.ArcEntry{Coordinate: coordinate, Target: runtimeTarget(key)})
		values[arcset.CanonicalizePath(name)] = key
	}
	canonical, err := arcset.NewCanonicalArcSet(arcset.KindMap, entries)
	if err != nil {
		return cid.Undef, err
	}
	semantics, err := mappingradix.NewMap(c.scheme, c.store)
	if err != nil {
		return cid.Undef, err
	}
	root, err := semantics.Commit(ctx, "client-root/v1/"+objectID, mapping.NewViewFromPaths(values))
	if err != nil {
		return cid.Undef, err
	}
	c.objects = append(c.objects, mutation.UpdateObject{ObjectID: objectID, Root: root, Kind: arcset.KindMap, Entries: canonical})
	return root, nil
}

func TestNewGatewayWritableBindingComposesPerDatasetState(t *testing.T) {
	view := runtimeWritebackView(t, maltcid.BackendKindKZG, 1)
	spec := filesystemmount.Spec{
		ID: "docs", DatasetID: view.DatasetID, Branch: view.Branch, Mountpoint: "/mnt/docs", TrustAlias: "docs",
		CachePolicy: filesystemmount.CacheVerified, WritePolicy: filesystemmount.WriteBack,
		LayoutPolicy: filesystemmount.LayoutFlatV1, ConflictPolicy: filesystemmount.ConflictPreserveLocal,
	}
	trust, err := truststore.Open(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	releaseCalls := 0
	binding, err := newGatewayWritableBinding(t.Context(), gatewayWritableBindingOptions{
		Spec: spec, View: view, Base: runtimeWritebackBaseFor(t, view.Root), Remote: inertGatewayWritableRemote{},
		Roots: trust, WriterFactory: &clientRootWriterFactory{}, StateDirectory: stateRoot, MaxStagedFileBytes: 1024,
		Release: func() error { releaseCalls++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if nilInterface(binding) {
		t.Fatal("newGatewayWritableBinding returned nil")
	}
	cachePath, journalPath, err := writableStatePaths(stateRoot, view.DatasetID, view.Branch)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(cachePath) != filepath.Dir(journalPath) {
		t.Fatalf("cache=%q journal=%q do not share one dataset state directory", cachePath, journalPath)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	if err := binding.Close(); err != nil || releaseCalls != 1 {
		t.Fatalf("idempotent binding Close = %v, release calls=%d", err, releaseCalls)
	}
	differentLayout := spec
	differentLayout.LayoutPolicy = filesystemmount.LayoutHybridV1
	partialReleaseCalls := 0
	partial, err := newGatewayWritableBinding(t.Context(), gatewayWritableBindingOptions{
		Spec: differentLayout, View: view, Base: runtimeWritebackBaseFor(t, view.Root), Remote: inertGatewayWritableRemote{},
		Roots: trust, WriterFactory: &clientRootWriterFactory{}, StateDirectory: stateRoot, MaxStagedFileBytes: 1024,
		Release: func() error { partialReleaseCalls++; return nil },
	})
	if !errors.Is(err, ErrWritableLayoutChanged) || nilInterface(partial) {
		t.Fatalf("changed durable layout binding=%T err=%v", partial, err)
	}
	if _, statErr := partial.Stat(t.Context(), ""); !errors.Is(statErr, filesystemservice.ErrClosed) {
		t.Fatalf("partial layout binding remained usable: %v", statErr)
	}
	if err := partial.Close(); err != nil {
		t.Fatal(err)
	}
	if partialReleaseCalls != 1 {
		t.Fatalf("partial binding release calls = %d, want 1", partialReleaseCalls)
	}
	reopened, err := newGatewayWritableBinding(t.Context(), gatewayWritableBindingOptions{
		Spec: spec, View: view, Base: runtimeWritebackBaseFor(t, view.Root), Remote: inertGatewayWritableRemote{},
		Roots: trust, WriterFactory: &clientRootWriterFactory{}, StateDirectory: stateRoot, MaxStagedFileBytes: 1024,
	})
	if err != nil {
		t.Fatalf("reopen with frozen layout: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	badView := view
	badView.Root = runtimeTestCID(t, "untyped")
	if _, err := newGatewayWritableBinding(t.Context(), gatewayWritableBindingOptions{Spec: spec, View: badView}); err == nil {
		t.Fatal("untyped accepted root reached writable composition")
	}
}

func TestNewGatewayWritableBindingReturnsCleanupOnlyBindingAfterLeaseAcquisition(t *testing.T) {
	view := runtimeWritebackView(t, maltcid.BackendKindKZG, 1)
	spec := filesystemmount.Spec{
		ID: "docs", DatasetID: view.DatasetID, Branch: view.Branch, Mountpoint: "/mnt/docs", TrustAlias: "docs",
		CachePolicy: filesystemmount.CacheVerified, WritePolicy: filesystemmount.WriteBack,
		LayoutPolicy: filesystemmount.LayoutFlatV1, ConflictPolicy: filesystemmount.ConflictPreserveLocal,
	}
	trust, err := truststore.Open(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	initializationFailure := errors.New("writer initialization failed")
	partial, err := newGatewayWritableBinding(t.Context(), gatewayWritableBindingOptions{
		Spec: spec, View: view, Base: runtimeWritebackBaseFor(t, view.Root), Remote: inertGatewayWritableRemote{},
		Roots: trust, WriterFactory: writerFactoryFunc(func() (*clientwriter.Runtime, error) { return nil, initializationFailure }),
		StateDirectory: stateRoot, MaxStagedFileBytes: 1024,
	})
	if !errors.Is(err, initializationFailure) || nilInterface(partial) {
		t.Fatalf("partial initialization binding=%T err=%v", partial, err)
	}
	if _, statErr := partial.Stat(t.Context(), ""); !errors.Is(statErr, filesystemservice.ErrClosed) {
		t.Fatalf("cleanup-only binding remained usable: %v", statErr)
	}
	if err := partial.Close(); err != nil {
		t.Fatal(err)
	}
	complete, err := newGatewayWritableBinding(t.Context(), gatewayWritableBindingOptions{
		Spec: spec, View: view, Base: runtimeWritebackBaseFor(t, view.Root), Remote: inertGatewayWritableRemote{},
		Roots: trust, WriterFactory: &clientRootWriterFactory{}, StateDirectory: stateRoot, MaxStagedFileBytes: 1024,
	})
	if err != nil {
		t.Fatalf("released partial binding kept dataset lease: %v", err)
	}
	if err := complete.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayWritableBindingReplaysFlatUnixFSAndSurvivesRemount(t *testing.T) {
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	remote := &replayingGatewayWritableRemote{blocks: map[string][]byte{}}
	oldBody := []byte("old remote body")
	oldPayload, err := remote.Put(t.Context(), oldBody)
	if err != nil {
		t.Fatal(err)
	}
	rootNode := unixfs.NewStagedDirectory()
	if err := unixfs.SetStagedFile(rootNode, "old.txt", oldPayload); err != nil {
		t.Fatal(err)
	}
	layout, err := unixfs.NewLayout(unixfs.LayoutFlatV1)
	if err != nil {
		t.Fatal(err)
	}
	creator := &runtimeRootCreator{scheme: scheme, store: materializermemory.New(true)}
	materialized, err := layout.Materialize(t.Context(), creator, remote, rootNode)
	if err != nil {
		t.Fatal(err)
	}
	remote.view, err = mutation.NormalizeUpdateView(mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot: materialized.Key, Bounds: mutation.UpdateViewBounds{MaxObjects: 64, MaxTotalEntries: 4096, MaxDepth: 32},
		Objects: append([]mutation.UpdateObject(nil), creator.objects...),
	})
	if err != nil {
		t.Fatal(err)
	}
	view := filesystemservice.View{DatasetID: "bucket", Branch: "main", Root: materialized.Key, Revision: 3}
	base := runtimeWritebackBase{
		infos: map[string]filesystemservice.Info{
			"":        {Path: "", Kind: unixfs.StagedKindDirectory, NodeRoot: view.Root},
			"old.txt": {Path: "old.txt", Name: "old.txt", Kind: unixfs.StagedKindFile, Payload: oldPayload, StorageKind: "raw", Size: uint64(len(oldBody))},
		},
		bodies: map[string][]byte{"old.txt": oldBody},
	}
	trust, err := truststore.Open(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Trust("docs", view.Root.String(), "unixfs", "gateway", "test"); err != nil {
		t.Fatal(err)
	}
	spec := filesystemmount.Spec{
		ID: "docs", DatasetID: view.DatasetID, Branch: view.Branch, Mountpoint: "/mnt/docs", TrustAlias: "docs",
		CachePolicy: filesystemmount.CacheVerified, WritePolicy: filesystemmount.WriteBack,
		LayoutPolicy: filesystemmount.LayoutFlatV1, ConflictPolicy: filesystemmount.ConflictPreserveLocal,
	}
	stateRoot := t.TempDir()
	factory := &clientRootWriterFactory{}
	open := func() filesystemmount.WritableBinding {
		binding, err := newGatewayWritableBinding(t.Context(), gatewayWritableBindingOptions{
			Spec: spec, View: view, Base: base, Remote: remote, Roots: trust, WriterFactory: factory,
			StateDirectory: stateRoot, MaxStagedFileBytes: 1024,
		})
		if err != nil {
			t.Fatal(err)
		}
		return binding
	}

	binding := open()
	if _, err := binding.Create(t.Context(), "new.txt"); err != nil {
		t.Fatal(err)
	}
	newBody := []byte("locally staged body")
	if _, err := binding.WriteAt(t.Context(), "new.txt", 0, newBody); err != nil {
		t.Fatal(err)
	}
	result, err := binding.Sync(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !result.LocalDurable || !result.RemotePersisted || result.CandidateRoot == "" || result.RootAccepted {
		t.Fatalf("Sync result=%#v", result)
	}
	if remote.submitted == nil || remote.submitted.Candidate.String() != result.CandidateRoot {
		t.Fatalf("submitted bundle=%#v result=%#v", remote.submitted, result)
	}
	record, err := trust.Get("docs")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != view.Root.String() || len(record.Candidates) != 1 || record.Candidates[0].Root != result.CandidateRoot {
		t.Fatalf("trust record=%#v", record)
	}
	newPayload, err := cid.Prefix{Version: 1, Codec: cid.Raw, MhType: 0x12, MhLength: -1}.Sum(newBody)
	if err != nil {
		t.Fatal(err)
	}
	if stored := remote.blocks[newPayload.KeyString()]; string(stored) != string(newBody) {
		t.Fatalf("stored payload=%q", stored)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := open()
	t.Cleanup(func() { _ = reopened.Close() })
	handle, err := reopened.Open(t.Context(), "new.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, err := handle.Read(t.Context(), 0, 64)
	if err != nil || string(body) != string(newBody) {
		t.Fatalf("remounted body=%q err=%v", body, err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := reopened.Sync(t.Context())
	if err != nil || !second.LocalDurable || second.RemotePersisted || second.CandidateRoot != "" || second.RootAccepted {
		t.Fatalf("remounted Sync=%#v err=%v", second, err)
	}
}

func TestRuntimeWritableBindingStagesAndRecordsCandidateWithoutAcceptance(t *testing.T) {
	view := runtimeWritebackView(t, maltcid.BackendKindKZG, 1)
	base := runtimeWritebackBaseFor(t, view.Root)
	staged, _, _ := newRuntimeStaging(t, base)
	candidate := runtimeMALTMapRoot(t, maltcid.BackendKindKZG, 2)
	var replayedView filesystemservice.View
	binding := &runtimeWritableBinding{
		view: view, staged: staged,
		replay: writebackReplayFunc(func(_ context.Context, got filesystemservice.View) (writebackapp.Result, error) {
			replayedView = got
			return writebackapp.Result{
				Profile: writebackapp.ResultProfile, CandidateRoot: candidate,
				RemotePersisted: true, CandidateStored: true, RootAccepted: false,
			}, nil
		}),
	}

	if _, err := binding.Create(t.Context(), "draft.txt"); err != nil {
		t.Fatal(err)
	}
	info, err := binding.WriteAt(t.Context(), "draft.txt", 0, []byte("verified candidate"))
	if err != nil || info.Size != uint64(len("verified candidate")) {
		t.Fatalf("WriteAt info=%#v err=%v", info, err)
	}
	handle, err := binding.Open(t.Context(), "draft.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, err := handle.Read(t.Context(), 0, 64)
	if err != nil || string(body) != "verified candidate" {
		t.Fatalf("Read body=%q err=%v", body, err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := binding.Sync(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !result.LocalDurable || !result.RemotePersisted || result.CandidateRoot != candidate.String() || result.RootAccepted {
		t.Fatalf("Sync result=%#v", result)
	}
	if !replayedView.Root.Equals(view.Root) || replayedView.DatasetID != view.DatasetID || replayedView.Branch != view.Branch {
		t.Fatalf("Replay view=%#v, want %#v", replayedView, view)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Stat(t.Context(), "draft.txt"); !errors.Is(err, filesystemservice.ErrClosed) {
		t.Fatalf("Stat after Close error=%v", err)
	}
}

func TestRuntimeWritableBindingOfflineFsyncRemainsLocallyDurableAndRestartable(t *testing.T) {
	view := runtimeWritebackView(t, maltcid.BackendKindIPA, 7)
	base := runtimeWritebackBaseFor(t, view.Root)
	root := t.TempDir()
	cachePath := filepath.Join(root, "cache")
	journalPath := filepath.Join(root, "journal.json")
	staged, err := staging.New(staging.Options{Base: base, CacheDirectory: cachePath, JournalPath: journalPath})
	if err != nil {
		t.Fatal(err)
	}
	offline := errors.New("gateway unavailable")
	binding := &runtimeWritableBinding{
		view: view, staged: staged,
		replay: writebackReplayFunc(func(context.Context, filesystemservice.View) (writebackapp.Result, error) {
			return writebackapp.Result{}, offline
		}),
	}
	if _, err := binding.Create(t.Context(), "offline.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.WriteAt(t.Context(), "offline.txt", 0, []byte("journal survives")); err != nil {
		t.Fatal(err)
	}
	result, err := binding.Sync(t.Context())
	if !errors.Is(err, offline) || !result.LocalDurable || result.RemotePersisted || result.CandidateRoot != "" || result.RootAccepted {
		t.Fatalf("offline Sync result=%#v err=%v", result, err)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := staging.New(staging.Options{Base: base, CacheDirectory: cachePath, JournalPath: journalPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	body, _, err := reopened.ReadFileRange(t.Context(), view, "offline.txt", 0, 64)
	if err != nil || string(body) != "journal survives" {
		t.Fatalf("restarted body=%q err=%v", body, err)
	}
}

func TestRuntimeWritableBindingRejectsInvalidRemoteTrustClaims(t *testing.T) {
	baseRoot := runtimeMALTMapRoot(t, maltcid.BackendKindKZG, 1)
	view := filesystemservice.View{DatasetID: "bucket", Branch: "main", Root: baseRoot}
	wrongBackend := runtimeMALTMapRoot(t, maltcid.BackendKindIPA, 2)
	raw := runtimeTestCID(t, "raw candidate")
	for _, test := range []struct {
		name   string
		result writebackapp.Result
	}{
		{name: "accepted", result: writebackapp.Result{Profile: writebackapp.ResultProfile, RootAccepted: true}},
		{name: "same root", result: writebackapp.Result{Profile: writebackapp.ResultProfile, CandidateRoot: baseRoot, RemotePersisted: true, CandidateStored: true}},
		{name: "raw root", result: writebackapp.Result{Profile: writebackapp.ResultProfile, CandidateRoot: raw, RemotePersisted: true, CandidateStored: true}},
		{name: "wrong backend", result: writebackapp.Result{Profile: writebackapp.ResultProfile, CandidateRoot: wrongBackend, RemotePersisted: true, CandidateStored: true}},
		{name: "no-change remote claim", result: writebackapp.Result{Profile: writebackapp.ResultProfile, NoAuthenticatedChange: true, RemotePersisted: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			staged, _, _ := newRuntimeStaging(t, runtimeWritebackBaseFor(t, baseRoot))
			binding := &runtimeWritableBinding{view: view, staged: staged, replay: writebackReplayFunc(func(context.Context, filesystemservice.View) (writebackapp.Result, error) {
				return test.result, nil
			})}
			if _, err := binding.Create(t.Context(), "change.txt"); err != nil {
				t.Fatal(err)
			}
			if result, err := binding.Sync(t.Context()); err == nil || !result.LocalDurable || result.RootAccepted {
				t.Fatalf("Sync result=%#v err=%v", result, err)
			}
		})
	}
}

func TestValidCandidateRootAllowsLegacyEvidenceToAdvanceToCurrentWireVersion(t *testing.T) {
	commitment := make([]byte, maltcid.KZGCommitmentSize)
	for index := range commitment {
		commitment[index] = byte(index + 1)
	}
	legacy, err := maltcid.NewTypedCIDForVersion(
		maltcid.LegacyMALTVersionID, maltcid.SemanticKindMap, maltcid.BackendKindKZG, commitment,
	)
	if err != nil {
		t.Fatal(err)
	}
	current := runtimeMALTMapRoot(t, maltcid.BackendKindKZG, 9)
	if !validCandidateRoot(legacy, current) {
		t.Fatalf("current candidate %s was rejected for legacy evidence %s", current, legacy)
	}
}

func TestRuntimeWritableBindingNoPendingAndNoChangeRemainLocalOnly(t *testing.T) {
	view := runtimeWritebackView(t, maltcid.BackendKindKZG, 1)
	for _, test := range []struct {
		name   string
		result writebackapp.Result
		err    error
	}{
		{name: "no pending", err: staging.ErrNoPendingUpload},
		{name: "authenticated no change", result: writebackapp.Result{Profile: writebackapp.ResultProfile, NoAuthenticatedChange: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			staged, _, _ := newRuntimeStaging(t, runtimeWritebackBaseFor(t, view.Root))
			binding := &runtimeWritableBinding{view: view, staged: staged, replay: writebackReplayFunc(func(context.Context, filesystemservice.View) (writebackapp.Result, error) {
				return test.result, test.err
			})}
			result, err := binding.Sync(t.Context())
			if err != nil || !result.LocalDurable || result.RemotePersisted || result.CandidateRoot != "" || result.RootAccepted {
				t.Fatalf("Sync result=%#v err=%v", result, err)
			}
		})
	}
}

func TestWritableStatePathsAreStableAndDatasetBranchIsolated(t *testing.T) {
	root := t.TempDir()
	cacheOne, journalOne, err := writableStatePaths(root, "bucket", "main")
	if err != nil {
		t.Fatal(err)
	}
	cacheAgain, journalAgain, err := writableStatePaths(root, "bucket", "main")
	if err != nil || cacheAgain != cacheOne || journalAgain != journalOne {
		t.Fatalf("stable paths=(%q,%q) err=%v, want (%q,%q)", cacheAgain, journalAgain, err, cacheOne, journalOne)
	}
	cacheOther, journalOther, err := writableStatePaths(root, "bucket", "feature")
	if err != nil || cacheOther == cacheOne || journalOther == journalOne {
		t.Fatalf("isolated paths=(%q,%q) err=%v", cacheOther, journalOther, err)
	}
	if _, _, err := writableStatePaths(root, " bucket", "main"); err == nil {
		t.Fatal("non-canonical dataset identity was accepted")
	}
}

func newRuntimeStaging(t *testing.T, base staging.Base) (*staging.Service, string, string) {
	t.Helper()
	root := t.TempDir()
	cachePath := filepath.Join(root, "cache")
	journalPath := filepath.Join(root, "journal.json")
	service, err := staging.New(staging.Options{Base: base, CacheDirectory: cachePath, JournalPath: journalPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service, cachePath, journalPath
}

func runtimeWritebackView(t *testing.T, backend maltcid.BackendKind, marker byte) filesystemservice.View {
	t.Helper()
	return filesystemservice.View{
		DatasetID: "bucket", Branch: "main", Root: runtimeMALTMapRoot(t, backend, marker), Revision: 9,
	}
}

func runtimeWritebackBaseFor(t *testing.T, root cid.Cid) runtimeWritebackBase {
	t.Helper()
	old := []byte("remote")
	return runtimeWritebackBase{
		infos: map[string]filesystemservice.Info{
			"":        {Path: "", Kind: unixfs.StagedKindDirectory, NodeRoot: root},
			"old.txt": {Path: "old.txt", Name: "old.txt", Kind: unixfs.StagedKindFile, Payload: runtimeTestCID(t, string(old)), StorageKind: "raw", Size: uint64(len(old))},
		},
		bodies: map[string][]byte{"old.txt": old},
	}
}

func runtimeMALTMapRoot(t *testing.T, backend maltcid.BackendKind, marker byte) cid.Cid {
	t.Helper()
	size := maltcid.KZGCommitmentSize
	if backend == maltcid.BackendKindIPA {
		size = maltcid.IPACommitmentSize
	}
	commitment := make([]byte, size)
	for index := range commitment {
		commitment[index] = marker + byte(index)
	}
	profile := maltcid.KZG4096
	if backend == maltcid.BackendKindIPA {
		profile = maltcid.IPA256
	}
	root, err := maltcid.NewRoot(maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 1, Profile: profile}, commitment)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func runtimeTarget(key cid.Cid) arcset.TargetRef {
	switch maltcid.SemanticKindOf(key) {
	case maltcid.SemanticKindMap:
		return arcset.NewMapTarget(key)
	case maltcid.SemanticKindList:
		return arcset.NewListTarget(key)
	default:
		return arcset.NewCASTarget(key)
	}
}

func writebackParent(value string) string {
	parent := path.Dir(value)
	if parent == "." {
		return ""
	}
	return parent
}

var _ filesystemmount.WritableBinding = (*runtimeWritableBinding)(nil)
