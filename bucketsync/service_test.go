package bucketsync

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt-client/transport"
	cid "github.com/ipfs/go-cid"
)

type fakeGateway struct {
	head     transport.BucketRef
	result   transport.BucketPushResult
	headErr  error
	pushErr  error
	onHead   func()
	lastPush transport.BucketPushRequest
}

func (f *fakeGateway) BucketHead(context.Context) (*transport.BucketRef, error) {
	if f.onHead != nil {
		f.onHead()
	}
	if f.headErr != nil {
		return nil, f.headErr
	}
	value := f.head
	return &value, nil
}

func (f *fakeGateway) PushBucket(_ context.Context, request transport.BucketPushRequest) (*transport.BucketPushResult, error) {
	f.lastPush = request
	if f.pushErr != nil {
		return nil, f.pushErr
	}
	value := f.result
	return &value, nil
}

func TestPushStashesBeforeFetchAndKeepsOriginalBase(t *testing.T) {
	baseRoot := testCID(t, "base")
	remoteRoot := testCID(t, "remote")
	candidateRoot := testCID(t, "candidate")
	mergedRoot := testCID(t, "merged")
	now := time.Now().UTC()
	gateway := &fakeGateway{head: testHead("cmt_base", baseRoot, 1, now)}
	service, err := Open(filepath.Join(t.TempDir(), "buckets.json"), gateway, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}
	base, err := service.CurrentBase(baseRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Stage(candidateRoot, base, cid.Undef, "local edit"); err != nil {
		t.Fatal(err)
	}
	gateway.head = testHead("cmt_remote", remoteRoot, 2, now)
	gateway.result = transport.BucketPushResult{
		Status: "merged",
		Head:   testHead("cmt_merge", mergedRoot, 3, now),
		Commit: transport.BucketCommit{ID: "cmt_merge", BucketID: "bkt_one", Root: mergedRoot.String(), Author: "alice", CreatedAt: now},
	}
	gateway.onHead = func() {
		workspace, err := service.Status()
		if err != nil {
			t.Error(err)
			return
		}
		if len(workspace.Stashes) != 1 || workspace.Stashes[0].Status != "pending" {
			t.Errorf("workspace was fetched before stash: %#v", workspace)
		}
		if workspace.Stashes[0].Base.CommitID != "cmt_base" || workspace.Stashes[0].Base.Root != baseRoot.String() {
			t.Errorf("stash base = %#v", workspace.Stashes[0].Base)
		}
	}
	outcome, err := service.Push(t.Context(), candidateRoot, cid.Undef, "local edit")
	if err != nil {
		t.Fatal(err)
	}
	if gateway.lastPush.BaseCommit != "cmt_base" || gateway.lastPush.BaseRoot != baseRoot.String() || gateway.lastPush.ExpectedHeadRevision != 1 {
		t.Fatalf("push used fetched head instead of stashed base: %#v", gateway.lastPush)
	}
	if outcome.Result.Status != "merged" || outcome.Workspace.Base.CommitID != "cmt_merge" || len(outcome.Workspace.Stashes) != 0 {
		t.Fatalf("outcome = %#v", outcome)
	}
}

func TestFailedFetchLeavesPendingStash(t *testing.T) {
	baseRoot := testCID(t, "base")
	candidateRoot := testCID(t, "candidate")
	now := time.Now().UTC()
	gateway := &fakeGateway{head: testHead("cmt_base", baseRoot, 1, now)}
	service, err := Open(filepath.Join(t.TempDir(), "buckets.json"), gateway, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}
	base, err := service.CurrentBase(baseRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Stage(candidateRoot, base, cid.Undef, "offline edit"); err != nil {
		t.Fatal(err)
	}
	gateway.headErr = errors.New("offline")
	if _, err := service.Push(t.Context(), candidateRoot, cid.Undef, "offline edit"); err == nil {
		t.Fatal("Push succeeded while fetch was offline")
	}
	workspace, err := service.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Stashes) != 1 || workspace.Stashes[0].CandidateRoot != candidateRoot.String() || workspace.Stashes[0].Status != "pending" {
		t.Fatalf("pending stash = %#v", workspace.Stashes)
	}
}

func TestPushRequiresAnObservedBase(t *testing.T) {
	gateway := &fakeGateway{}
	service, err := Open(filepath.Join(t.TempDir(), "buckets.json"), gateway, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Push(t.Context(), testCID(t, "candidate"), cid.Undef, ""); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Push error = %v", err)
	}
}

func TestPushRequiresCandidateStagedAgainstCapturedBase(t *testing.T) {
	baseRoot := testCID(t, "base")
	remoteRoot := testCID(t, "remote")
	candidateRoot := testCID(t, "candidate")
	now := time.Now().UTC()
	gateway := &fakeGateway{head: testHead("cmt_base", baseRoot, 1, now)}
	service, err := Open(filepath.Join(t.TempDir(), "buckets.json"), gateway, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}
	captured, err := service.CurrentBase(baseRoot)
	if err != nil {
		t.Fatal(err)
	}
	gateway.head = testHead("cmt_remote", remoteRoot, 2, now)
	if _, err := service.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Push(t.Context(), candidateRoot, cid.Undef, ""); !errors.Is(err, ErrNotStaged) {
		t.Fatalf("unstaged Push error = %v", err)
	}
	if _, err := service.CurrentBase(baseRoot); err == nil {
		t.Fatal("CurrentBase accepted the stale root after Pull")
	}
	if _, err := service.Stage(candidateRoot, captured, cid.Undef, ""); err != nil {
		t.Fatal(err)
	}
	gateway.result = transport.BucketPushResult{
		Status: "branched", Head: gateway.head,
		Commit: transport.BucketCommit{ID: "cmt_candidate", BucketID: "bkt_one", Root: candidateRoot.String(), Author: "alice", CreatedAt: now},
		Branch: func() *transport.BucketRef {
			value := testHead("cmt_candidate", candidateRoot, 1, now)
			value.Name, value.Kind = "conflicts/alice/one", "conflict"
			return &value
		}(),
	}
	if _, err := service.Push(t.Context(), candidateRoot, cid.Undef, ""); err != nil {
		t.Fatal(err)
	}
	if gateway.lastPush.BaseCommit != captured.CommitID || gateway.lastPush.BaseRoot != captured.Root || gateway.lastPush.ExpectedHeadRevision != captured.Revision {
		t.Fatalf("Push base = %#v, want %#v", gateway.lastPush, captured)
	}
}

func testHead(commit string, root cid.Cid, revision uint64, now time.Time) transport.BucketRef {
	return transport.BucketRef{
		BucketID: "bkt_one", Name: "main", Kind: "main", State: "open", CommitID: commit,
		Root: root.String(), Revision: revision, CreatedAt: now, UpdatedAt: now,
	}
}

func testCID(t *testing.T, value string) cid.Cid {
	t.Helper()
	key, err := clientcas.CIDForBlock(clientcas.Block{Data: []byte(value), Codec: cid.Raw})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
