package bucketsync

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
		Status:    "merged",
		Head:      testHead("cmt_merge", mergedRoot, 3, now),
		Candidate: testCommit("cmt_candidate", candidateRoot, baseRoot, []string{"cmt_base"}, "local edit", now),
		Commit:    testCommit("cmt_merge", mergedRoot, remoteRoot, []string{"cmt_remote", "cmt_candidate"}, "gateway auto-merge", now),
		MergeBase: baseRoot.String(),
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
		Candidate: testCommit("cmt_candidate", candidateRoot, capturedCID(t, captured.Root), []string{captured.CommitID}, "", now),
		Commit:    testCommit("cmt_candidate", candidateRoot, capturedCID(t, captured.Root), []string{captured.CommitID}, "", now),
		Branch: func() *transport.BucketRef {
			value := testHead("cmt_candidate", candidateRoot, 1, now)
			value.Name, value.Kind = "conflicts/alice/one", "conflict"
			return &value
		}(), MergeBase: captured.Root, Conflicts: []transport.BucketConflict{{Coordinate: "docs/readme"}},
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
	candidateCommit := testCommit("cmt_two", candidateRoot, baseRoot, []string{"cmt_one"}, "delayed push", now)
	pusher, err := Open(path, &delayedPushGateway{
		head: baseHead, result: transport.BucketPushResult{Status: "fast_forward", Head: pushHead, Candidate: candidateCommit, Commit: candidateCommit},
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

func TestInvalidPushResultLeavesPendingStash(t *testing.T) {
	now := time.Now().UTC()
	baseRoot := testCID(t, "base")
	candidateRoot := testCID(t, "candidate")
	path := filepath.Join(t.TempDir(), "buckets.json")
	baseHead := testHead("opaque-base", baseRoot, 1, now)
	gateway := &fakeGateway{head: baseHead}
	service, err := Open(path, gateway, "bkt_one")
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
	candidate := testCommit("opaque-candidate", candidateRoot, baseRoot, []string{"opaque-base"}, "local edit", now)
	gateway.result = transport.BucketPushResult{
		Status: "fast_forward", Head: testHead("another-version", candidateRoot, 2, now), Candidate: candidate, Commit: candidate,
	}
	if _, err := service.Push(t.Context(), candidateRoot, cid.Undef, "local edit"); err == nil {
		t.Fatal("Push accepted a result whose main head did not point to the final commit")
	}
	workspace, err := service.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Stashes) != 1 || workspace.Stashes[0].Status != "pending" {
		t.Fatalf("invalid response changed pending stash: %#v", workspace.Stashes)
	}
}

func TestPushResultsDoNotOrderAgainstDescriptiveBaseRevision(t *testing.T) {
	baseRoot := testCID(t, "base")
	candidateRoot := testCID(t, "candidate")
	remoteRoot := testCID(t, "remote")
	mergedRoot := testCID(t, "merged")
	now := time.Now().UTC()
	candidate := testCommit("opaque-candidate", candidateRoot, baseRoot, []string{"opaque-base"}, "local edit", now)

	tests := []struct {
		name       string
		result     transport.BucketPushResult
		wantStatus string
		wantStash  int
	}{
		{
			name: "fast-forward",
			result: transport.BucketPushResult{
				Status: "fast_forward", Head: testHead(candidate.ID, candidateRoot, 2, now), Candidate: candidate, Commit: candidate,
			},
		},
		{
			name: "merged",
			result: transport.BucketPushResult{
				Status:    "merged",
				Head:      testHead("opaque-merge", mergedRoot, 2, now),
				Candidate: candidate,
				Commit:    testCommit("opaque-merge", mergedRoot, remoteRoot, []string{"opaque-remote", candidate.ID}, "gateway auto-merge", now),
				MergeBase: baseRoot.String(),
			},
		},
		{
			name: "branched",
			result: transport.BucketPushResult{
				Status: "branched", Head: testHead("opaque-base", baseRoot, 2, now), Candidate: candidate, Commit: candidate,
				Branch: func() *transport.BucketRef {
					value := testHead(candidate.ID, candidateRoot, 1, now)
					value.Name, value.Kind = "conflicts/alice/one", "conflict"
					return &value
				}(),
				MergeBase: baseRoot.String(), Conflicts: []transport.BucketConflict{{Coordinate: "docs/readme"}},
			},
			wantStatus: "branched",
			wantStash:  1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// The captured revision is deliberately unrelated to the result
			// revision. It describes the observation and is not a CAS token.
			gateway := &fakeGateway{head: testHead("opaque-base", baseRoot, 50, now), result: test.result}
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
			if base.Revision != 50 {
				t.Fatalf("captured base revision = %d", base.Revision)
			}
			if _, err := service.Stage(candidateRoot, base, cid.Undef, "local edit"); err != nil {
				t.Fatal(err)
			}
			outcome, err := service.Push(t.Context(), candidateRoot, cid.Undef, "local edit")
			if err != nil {
				t.Fatalf("Push rejected structurally valid %s replay: %v", test.name, err)
			}
			if gateway.lastPush.BaseRevision != 50 || outcome.Result.Head.Revision != 2 {
				t.Fatalf("%s did not exercise mismatched descriptive revisions: request=%d result=%d", test.name, gateway.lastPush.BaseRevision, outcome.Result.Head.Revision)
			}
			if len(outcome.Workspace.Stashes) != test.wantStash {
				t.Fatalf("stashes after %s = %#v", test.name, outcome.Workspace.Stashes)
			}
			if test.wantStatus != "" && outcome.Workspace.Stashes[0].Status != test.wantStatus {
				t.Fatalf("stash status after %s = %q", test.name, outcome.Workspace.Stashes[0].Status)
			}
		})
	}
}

func TestPushRetryAfterResponseLossReusesFrozenRequest(t *testing.T) {
	now := time.Now().UTC()
	baseRoot := testCID(t, "base")
	candidateRoot := testCID(t, "candidate")
	path := filepath.Join(t.TempDir(), "buckets.json")
	baseHead := testHead("opaque-base", baseRoot, 1, now)
	firstGateway := &fakeGateway{head: baseHead, pushErr: errors.New("connection reset after request commit")}
	first, err := Open(path, firstGateway, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}
	base, err := first.CurrentBase(baseRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Stage(candidateRoot, base, cid.Undef, "staged message"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Push(t.Context(), candidateRoot, cid.Undef, "first request"); err == nil {
		t.Fatal("Push succeeded despite response loss")
	}
	original := firstGateway.lastPush
	if original.PushID == "" || original.Message != "first request" {
		t.Fatalf("first push request = %#v", original)
	}

	candidate := testCommit("opaque-candidate", candidateRoot, baseRoot, []string{"opaque-base"}, "first request", now)
	replayGateway := &fakeGateway{
		head: testHead("opaque-candidate", candidateRoot, 2, now),
		result: transport.BucketPushResult{
			Status: "fast_forward", Head: testHead("opaque-candidate", candidateRoot, 2, now), Candidate: candidate, Commit: candidate,
		},
	}
	reopened, err := Open(path, replayGateway, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Push(t.Context(), candidateRoot, cid.Undef, "different retry"); err == nil || !strings.Contains(err.Error(), "retry message") {
		t.Fatalf("changed retry error = %v", err)
	}
	if replayGateway.lastPush.PushID != "" {
		t.Fatal("changed retry reached the Gateway")
	}
	if _, err := reopened.Push(t.Context(), candidateRoot, cid.Undef, ""); err != nil {
		t.Fatal(err)
	}
	if replayGateway.lastPush != original {
		t.Fatalf("replayed request = %#v, want %#v", replayGateway.lastPush, original)
	}
	workspace, err := reopened.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Stashes) != 0 {
		t.Fatalf("successful replay left stash: %#v", workspace.Stashes)
	}
}

func TestVersionTwoStashFreezesRequestOnFirstPush(t *testing.T) {
	baseRoot := testCID(t, "base")
	candidateRoot := testCID(t, "candidate")
	now := time.Now().UTC()
	gateway := &fakeGateway{head: testHead("opaque-base", baseRoot, 1, now), pushErr: errors.New("offline")}
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
	stash, err := service.Stage(candidateRoot, base, cid.Undef, "newly staged")
	if err != nil {
		t.Fatal(err)
	}
	if stash.RequestFrozen {
		t.Fatal("newly staged request was already frozen")
	}
	data, err := os.ReadFile(service.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"request_frozen": false`) {
		t.Fatalf("version 2 stash did not persist an explicit request_frozen=false: %s", data)
	}
	if _, err := service.Push(t.Context(), candidateRoot, cid.Undef, "first push override"); err == nil {
		t.Fatal("Push succeeded while Gateway was offline")
	}
	workspace, err := service.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Stashes) != 1 || !workspace.Stashes[0].RequestFrozen || workspace.Stashes[0].Message != "first push override" {
		t.Fatalf("first push did not freeze version 2 stash: %#v", workspace.Stashes)
	}
}

func TestVersionOnePendingMigrationPreservesPossiblySentRequest(t *testing.T) {
	baseRoot := testCID(t, "base")
	candidateRoot := testCID(t, "candidate")
	changeSet := testCID(t, "change-set")
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "buckets.json")
	base := Head{CommitID: "opaque-base", Root: baseRoot.String(), Revision: 1}
	writeVersionOneWorkspace(t, path, Workspace{
		BucketID: "bkt_one", Initialized: true, Base: base, Remote: base,
		Stashes: []Stash{{
			ID: "legacy-stash", PushID: "push-original", CandidateRoot: candidateRoot.String(), Base: base,
			ChangeSetCID: changeSet.String(), Message: "message A", Status: "pending", CreatedAt: now, UpdatedAt: now,
		}},
		UpdatedAt: now,
	})

	candidate := testCommit("opaque-candidate", candidateRoot, baseRoot, []string{"opaque-base"}, "message A", now)
	candidate.ChangeSetCID = changeSet.String()
	gateway := &fakeGateway{
		head: testHead("opaque-base", baseRoot, 1, now),
		result: transport.BucketPushResult{
			Status: "fast_forward", Head: testHead(candidate.ID, candidateRoot, 2, now), Candidate: candidate, Commit: candidate,
		},
	}
	service, err := Open(path, gateway, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}

	migrated := readPersistedState(t, path)
	legacy := migrated.Workspaces["bkt_one"].Stashes[0]
	if migrated.Version != bucketWorkspaceVersion || !legacy.RequestFrozen || legacy.Message != "message A" || legacy.ChangeSetCID != changeSet.String() || legacy.PushID != "push-original" || legacy.Base != base {
		t.Fatalf("migrated workspace did not preserve frozen request: %#v", migrated)
	}
	if _, err := service.Push(t.Context(), candidateRoot, cid.Undef, "message B"); err == nil || !strings.Contains(err.Error(), "retry message") {
		t.Fatalf("changed migrated retry error = %v", err)
	}
	if gateway.lastPush.PushID != "" {
		t.Fatal("changed migrated retry reached Gateway")
	}
	afterRejected := readPersistedState(t, path).Workspaces["bkt_one"].Stashes[0]
	if afterRejected.Message != "message A" || afterRejected.ChangeSetCID != changeSet.String() || afterRejected.PushID != "push-original" || !afterRejected.RequestFrozen {
		t.Fatalf("rejected retry altered migrated request: %#v", afterRejected)
	}

	if _, err := service.Push(t.Context(), candidateRoot, cid.Undef, ""); err != nil {
		t.Fatal(err)
	}
	if gateway.lastPush.Message != "message A" || gateway.lastPush.ChangeSetCID != changeSet.String() || gateway.lastPush.PushID != "push-original" || gateway.lastPush.BaseCommit != base.CommitID || gateway.lastPush.BaseRoot != base.Root || gateway.lastPush.BaseRevision != base.Revision {
		t.Fatalf("migrated retry request = %#v", gateway.lastPush)
	}
}

func TestVersionOneNeverSentPendingStashIsConservativelyFrozen(t *testing.T) {
	baseRoot := testCID(t, "base")
	candidateRoot := testCID(t, "candidate")
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "buckets.json")
	base := Head{CommitID: "opaque-base", Root: baseRoot.String(), Revision: 1}
	writeVersionOneWorkspace(t, path, Workspace{
		BucketID: "bkt_one", Initialized: true, Base: base, Remote: base,
		Stashes: []Stash{{
			ID: "never-sent", PushID: "push-never-sent", CandidateRoot: candidateRoot.String(), Base: base,
			Message: "original", Status: "pending", CreatedAt: now, UpdatedAt: now,
		}},
		UpdatedAt: now,
	})

	service, err := Open(path, &fakeGateway{}, "bkt_one")
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := service.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(workspace.Stashes) != 1 || !workspace.Stashes[0].RequestFrozen || workspace.Stashes[0].Message != "original" {
		t.Fatalf("never-sent version 1 stash was not conservatively frozen: %#v", workspace.Stashes)
	}
	persisted := readPersistedState(t, path)
	if persisted.Version != bucketWorkspaceVersion || !persisted.Workspaces["bkt_one"].Stashes[0].RequestFrozen {
		t.Fatalf("version 1 migration was not durable before retry: %#v", persisted)
	}
}

func TestVersionTwoMissingRequestFrozenIsRejected(t *testing.T) {
	baseRoot := testCID(t, "base")
	candidateRoot := testCID(t, "candidate")
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "buckets.json")
	base := Head{CommitID: "opaque-base", Root: baseRoot.String(), Revision: 1}
	writeWorkspaceWithoutRequestFrozen(t, path, bucketWorkspaceVersion, Workspace{
		BucketID: "bkt_one", Initialized: true, Base: base, Remote: base,
		Stashes: []Stash{{
			ID: "incomplete-v2", PushID: "push-incomplete", CandidateRoot: candidateRoot.String(), Base: base,
			Message: "original", Status: "pending", CreatedAt: now, UpdatedAt: now,
		}},
		UpdatedAt: now,
	})

	if _, err := Open(path, &fakeGateway{}, "bkt_one"); err == nil || !strings.Contains(err.Error(), "lacks explicit request_frozen") {
		t.Fatalf("Open error for incomplete version 2 state = %v", err)
	}
}

func testHead(commit string, root cid.Cid, revision uint64, now time.Time) transport.BucketRef {
	return transport.BucketRef{
		BucketID: "bkt_one", Name: "main", Kind: "main", State: "open", CommitID: commit,
		Root: root.String(), Revision: revision, CreatedAt: now, UpdatedAt: now,
	}
}

func writeVersionOneWorkspace(t *testing.T, path string, workspace Workspace) {
	t.Helper()
	writeWorkspaceWithoutRequestFrozen(t, path, 1, workspace)
}

func writeWorkspaceWithoutRequestFrozen(t *testing.T, path string, version int, workspace Workspace) {
	t.Helper()
	state := persistedState{Version: version, Workspaces: map[string]Workspace{workspace.BucketID: workspace}}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	workspaces, ok := legacy["workspaces"].(map[string]any)
	if !ok {
		t.Fatal("version 1 fixture has no workspaces object")
	}
	for _, rawWorkspace := range workspaces {
		workspaceObject, ok := rawWorkspace.(map[string]any)
		if !ok {
			t.Fatal("version 1 fixture has an invalid workspace")
		}
		rawStashes, _ := workspaceObject["stashes"].([]any)
		for _, rawStash := range rawStashes {
			stashObject, ok := rawStash.(map[string]any)
			if !ok {
				t.Fatal("version 1 fixture has an invalid stash")
			}
			delete(stashObject, "request_frozen")
		}
	}
	data, err = json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readPersistedState(t *testing.T, path string) persistedState {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func testCID(t *testing.T, value string) cid.Cid {
	t.Helper()
	key, err := clientcas.CIDForBlock(clientcas.Block{Data: []byte(value), Codec: cid.Raw})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func capturedCID(t *testing.T, value string) cid.Cid {
	t.Helper()
	parsed, err := cid.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func testCommit(id string, root, baseRoot cid.Cid, parents []string, message string, now time.Time) transport.BucketCommit {
	base := ""
	if baseRoot.Defined() {
		base = baseRoot.String()
	}
	return transport.BucketCommit{
		ID: id, BucketID: "bkt_one", Root: root.String(), Parents: parents, BaseRoot: base,
		Author: "alice", Message: message, CreatedAt: now,
	}
}
