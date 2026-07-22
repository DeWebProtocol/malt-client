package bucketsync

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
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
	if gateway.lastPush.BaseCommit != "cmt_base" || gateway.lastPush.BaseRoot != baseRoot.String() || gateway.lastPush.BaseRevision != 1 {
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
	if gateway.lastPush.BaseCommit != captured.CommitID || gateway.lastPush.BaseRoot != captured.Root || gateway.lastPush.BaseRevision != captured.Revision {
		t.Fatalf("Push base = %#v, want %#v", gateway.lastPush, captured)
	}
}

type delayedHeadGateway struct {
	head    transport.BucketRef
	started chan<- struct{}
	release <-chan struct{}
}

func (g *delayedHeadGateway) BucketHead(context.Context) (*transport.BucketRef, error) {
	g.started <- struct{}{}
	<-g.release
	value := g.head
	return &value, nil
}

func (*delayedHeadGateway) PushBucket(context.Context, transport.BucketPushRequest) (*transport.BucketPushResult, error) {
	return nil, errors.New("unexpected push")
}

func TestConcurrentPullResponsesDoNotRegressWorkspaceRevision(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "buckets.json")
	initial := &fakeGateway{head: testHead("cmt_one", testCID(t, "one"), 1, now)}
	service, err := Open(path, initial, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	olderGateway := &delayedHeadGateway{
		head: testHead("cmt_two", testCID(t, "two"), 2, now), started: started, release: release,
	}
	older, err := Open(path, olderGateway, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	newer, err := Open(path, &fakeGateway{head: testHead("cmt_three", testCID(t, "three"), 3, now)}, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}

	var workers sync.WaitGroup
	workers.Add(1)
	var olderErr error
	go func() {
		defer workers.Done()
		_, olderErr = older.Pull(t.Context())
	}()
	<-started
	if _, err := newer.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}
	close(release)
	workers.Wait()
	if olderErr != nil {
		t.Fatal(olderErr)
	}

	workspace, err := service.Status()
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Remote.Revision != 3 || workspace.Remote.CommitID != "cmt_three" || workspace.Base.Revision != 3 {
		t.Fatalf("workspace regressed after delayed response: %#v", workspace)
	}
}

type delayedPushGateway struct {
	head    transport.BucketRef
	result  transport.BucketPushResult
	started chan<- struct{}
	release <-chan struct{}
}

func (g *delayedPushGateway) BucketHead(context.Context) (*transport.BucketRef, error) {
	value := g.head
	return &value, nil
}

func (g *delayedPushGateway) PushBucket(_ context.Context, _ transport.BucketPushRequest) (*transport.BucketPushResult, error) {
	g.started <- struct{}{}
	<-g.release
	value := g.result
	return &value, nil
}

func TestDelayedPushResponseDoesNotRegressNewerObservedHead(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "buckets.json")
	baseRoot := testCID(t, "base")
	candidateRoot := testCID(t, "candidate")
	baseHead := testHead("cmt_one", baseRoot, 1, now)
	initial, err := Open(path, &fakeGateway{head: baseHead}, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initial.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}
	base, err := initial.CurrentBase(baseRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initial.Stage(candidateRoot, base, cid.Undef, "delayed push"); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	pushHead := testHead("cmt_two", candidateRoot, 2, now)
	pusher, err := Open(path, &delayedPushGateway{
		head: baseHead, result: transport.BucketPushResult{Status: "fast_forward", Head: pushHead},
		started: started, release: release,
	}, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}

	var workers sync.WaitGroup
	workers.Add(1)
	var pushErr error
	go func() {
		defer workers.Done()
		_, pushErr = pusher.Push(t.Context(), candidateRoot, cid.Undef, "delayed push")
	}()
	<-started
	newerHead := testHead("cmt_three", testCID(t, "newer"), 3, now)
	observer, err := Open(path, &fakeGateway{head: newerHead}, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}
	close(release)
	workers.Wait()
	if pushErr != nil {
		t.Fatal(pushErr)
	}

	workspace, err := initial.Status()
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Remote.Revision != 3 || workspace.Base.Revision != 3 || len(workspace.Stashes) != 0 {
		t.Fatalf("workspace regressed after delayed push response: %#v", workspace)
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
