package application_test

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/dewebprotocol/malt-client/application"
	"github.com/dewebprotocol/malt-client/merkledag"
	"github.com/dewebprotocol/malt-client/trust"
	"github.com/dewebprotocol/malt-client/unixfs"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

type fakeUnixFS struct {
	readRoot     cid.Cid
	removeResult *unixfs.RemoveResult
	writeResult  *unixfs.WriteResult
}

func (f *fakeUnixFS) Resolve(context.Context, cid.Cid, string) (*unixfs.Resolution, error) {
	return &unixfs.Resolution{}, nil
}
func (f *fakeUnixFS) Stat(_ context.Context, root cid.Cid, _ string) (*unixfs.Stat, error) {
	f.readRoot = root
	return &unixfs.Stat{NodeRoot: root}, nil
}
func (f *fakeUnixFS) ReadFile(_ context.Context, root cid.Cid, _ string) (*unixfs.ReadResult, error) {
	f.readRoot = root
	return &unixfs.ReadResult{Body: []byte("verified"), Target: root}, nil
}
func (f *fakeUnixFS) ReadFileRange(_ context.Context, root cid.Cid, _ string, _, _ uint64) (*unixfs.ReadResult, error) {
	f.readRoot = root
	return &unixfs.ReadResult{Body: []byte("range"), Target: root}, nil
}
func (*fakeUnixFS) ReadListPayloadRange(context.Context, cid.Cid, uint64, uint64) (*unixfs.ReadResult, error) {
	return nil, nil
}
func (f *fakeUnixFS) EmptyDirectory(context.Context) (*unixfs.WriteResult, error) {
	return f.writeResult, nil
}
func (f *fakeUnixFS) AddDirectory(context.Context, cid.Cid, string) (*unixfs.WriteResult, error) {
	return f.writeResult, nil
}
func (f *fakeUnixFS) AddFile(context.Context, cid.Cid, string, []byte) (*unixfs.WriteResult, error) {
	return f.writeResult, nil
}
func (f *fakeUnixFS) AddFileStream(context.Context, cid.Cid, string, io.Reader) (*unixfs.WriteResult, error) {
	return f.writeResult, nil
}
func (f *fakeUnixFS) AddFileSized(context.Context, cid.Cid, string, io.Reader, int64) (*unixfs.WriteResult, error) {
	return f.writeResult, nil
}
func (f *fakeUnixFS) RemovePath(context.Context, cid.Cid, string) (*unixfs.RemoveResult, error) {
	return f.removeResult, nil
}

func TestUnixFSUseCaseSelectsAcceptedRootAndRecordsCandidateWithoutAcceptance(t *testing.T) {
	accepted := testCID(t, "accepted")
	candidate := testCID(t, "candidate")
	store, err := trust.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust("docs", accepted.String(), "unixfs", "https://gateway.example", "test"); err != nil {
		t.Fatal(err)
	}
	roots, err := application.NewRoots(store)
	if err != nil {
		t.Fatal(err)
	}
	facade := &fakeUnixFS{
		removeResult: &unixfs.RemoveResult{BaseRoot: accepted, CandidateRoot: candidate, Accepted: false},
		writeResult:  &unixfs.WriteResult{BaseRoot: accepted, CandidateRoot: candidate, Accepted: false},
	}
	app, err := application.NewUnixFS(facade, facade, roots)
	if err != nil {
		t.Fatal(err)
	}
	read, err := app.ReadFile(t.Context(), "docs", "file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read.Body, []byte("verified")) || !facade.readRoot.Equals(accepted) {
		t.Fatalf("read used root %s, want accepted root %s", facade.readRoot, accepted)
	}
	if _, err := app.RemovePath(t.Context(), "docs", "file.txt"); err != nil {
		t.Fatal(err)
	}
	record, err := store.Get("docs")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != accepted.String() || len(record.Candidates) != 1 || record.Candidates[0].Root != candidate.String() {
		t.Fatalf("candidate recording changed trust unexpectedly: %#v", record)
	}
	if _, err := roots.AcceptCandidate("docs", candidate, "explicit-test"); err != nil {
		t.Fatal(err)
	}
	record, _ = store.Get("docs")
	if record.AcceptedRoot != candidate.String() {
		t.Fatalf("explicit acceptance left root at %s", record.AcceptedRoot)
	}
}

func TestUnixFSUseCaseRejectsWriterClaimingAutomaticAcceptance(t *testing.T) {
	accepted := testCID(t, "accepted")
	candidate := testCID(t, "candidate")
	store, err := trust.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust("docs", accepted.String(), "unixfs", "", "test"); err != nil {
		t.Fatal(err)
	}
	roots, _ := application.NewRoots(store)
	facade := &fakeUnixFS{writeResult: &unixfs.WriteResult{BaseRoot: accepted, CandidateRoot: candidate, Accepted: true}}
	app, _ := application.NewUnixFS(facade, facade, roots)
	if _, err := app.AddFile(t.Context(), "docs", "file.txt", []byte("body")); err == nil {
		t.Fatal("application accepted a writer result marked as automatically accepted")
	}
	record, _ := store.Get("docs")
	if record.AcceptedRoot != accepted.String() || len(record.Candidates) != 0 {
		t.Fatalf("rejected result changed trust state: %#v", record)
	}
}

func TestUnixFSUseCaseRejectsCrossRootWriterSplice(t *testing.T) {
	accepted := testCID(t, "accepted")
	other := testCID(t, "other-root")
	candidate := testCID(t, "candidate")
	store, err := trust.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust("docs", accepted.String(), "unixfs", "", "test"); err != nil {
		t.Fatal(err)
	}
	roots, _ := application.NewRoots(store)
	facade := &fakeUnixFS{writeResult: &unixfs.WriteResult{BaseRoot: other, CandidateRoot: candidate, Accepted: false}}
	app, _ := application.NewUnixFS(facade, facade, roots)
	if _, err := app.AddFile(t.Context(), "docs", "file.txt", []byte("body")); err == nil {
		t.Fatal("application accepted a writer result bound to another root")
	}
	record, _ := store.Get("docs")
	if record.AcceptedRoot != accepted.String() || len(record.Candidates) != 0 {
		t.Fatalf("cross-root result changed trust state: %#v", record)
	}
}

type fakeMerkleDAG struct {
	root     cid.Cid
	segments []string
}

func (f *fakeMerkleDAG) ResolveMerkleDAGVerified(_ context.Context, root cid.Cid, segments []string) (*merkledag.MerkleDAGResolveResponse, error) {
	f.root, f.segments = root, append([]string(nil), segments...)
	return &merkledag.MerkleDAGResolveResponse{Target: root.String()}, nil
}
func (f *fakeMerkleDAG) ReadMerkleDAGVerified(_ context.Context, root cid.Cid, segments []string, _, _ *uint64) (*merkledag.MerkleDAGReadResponse, error) {
	f.root, f.segments = root, append([]string(nil), segments...)
	return &merkledag.MerkleDAGReadResponse{Target: root.String(), Data: []byte("verified")}, nil
}

func TestMerkleDAGUseCasePreservesCallerSelectedRootAndSegments(t *testing.T) {
	root := testCID(t, "root")
	fake := &fakeMerkleDAG{}
	app, err := application.NewMerkleDAG(fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	segments := []string{"a", "b"}
	if _, err := app.Read(t.Context(), root, segments, nil, nil); err != nil {
		t.Fatal(err)
	}
	segments[0] = "changed"
	if !fake.root.Equals(root) || len(fake.segments) != 2 || fake.segments[0] != "a" {
		t.Fatalf("Merkle-DAG use case lost caller boundary: root=%s segments=%v", fake.root, fake.segments)
	}
}

func testCID(t *testing.T, body string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(body), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

var _ unixfs.Writer = (*fakeUnixFS)(nil)
var _ application.MerkleDAGVerifiedClient = (*fakeMerkleDAG)(nil)
