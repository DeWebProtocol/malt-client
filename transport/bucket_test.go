package transport_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	client "github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt/auth/proof/prooflist"
	"github.com/dewebprotocol/malt/protocol"
)

func TestBucketClientScopesNativeRoutesAndAcceptsConflictResult(t *testing.T) {
	root := mustBlockCID(t, []byte("root"))
	target := mustBlockCID(t, []byte("target"))
	baseText, err := root.StringOfBase('z') // base58btc instead of CID's default base32
	if err != nil {
		t.Fatal(err)
	}
	candidateText, err := target.StringOfBase('z')
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var receivedPush client.BucketPushRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tenant-secret" {
			t.Fatalf("Authorization = %q", got)
		}
		switch r.URL.Path {
		case "/v1/buckets/bkt_one/resolve":
			_ = json.NewEncoder(w).Encode(protocol.ResolveResult{
				Profile: protocol.ResolveProfile, Target: target.String(), ProofList: prooflist.ProofList{Root: root},
			})
		case "/v1/buckets/bkt_one/head":
			_ = json.NewEncoder(w).Encode(client.BucketRef{
				BucketID: "bkt_one", Name: "main", Kind: "main", State: "open",
				CommitID: "cmt_one", Root: root.String(), Revision: 2, CreatedAt: now, UpdatedAt: now,
			})
		case "/v1/buckets/bkt_one/cas/" + target.String():
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte("target"))
			case http.MethodHead:
				w.WriteHeader(http.StatusNoContent)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		case "/v1/buckets/bkt_one/push":
			if err := json.NewDecoder(r.Body).Decode(&receivedPush); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if receivedPush.PushID == "reused" {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "bucket push ID was already used for a different request"})
				return
			}
			w.WriteHeader(http.StatusConflict)
			branch := client.BucketRef{
				BucketID: "bkt_one", Name: "conflicts/alice/conflict_one", Kind: "conflict", State: "open",
				CommitID: "cmt_candidate", Root: target.String(), Revision: 1, CreatedAt: now, UpdatedAt: now,
			}
			candidate := client.BucketCommit{
				ID: "cmt_candidate", BucketID: "bkt_one", Root: target.String(), Parents: []string{"cmt_one"},
				BaseRoot: root.String(), Author: "alice", CreatedAt: now,
			}
			_ = json.NewEncoder(w).Encode(client.BucketPushResult{
				Status:    "branched",
				Head:      client.BucketRef{BucketID: "bkt_one", Name: "main", Kind: "main", State: "open", CommitID: "cmt_one", Root: root.String(), Revision: 2, CreatedAt: now, UpdatedAt: now},
				Candidate: candidate,
				Commit:    candidate,
				Branch:    &branch, MergeBase: root.String(), Conflicts: []client.BucketConflict{{Coordinate: "docs/readme"}},
			})
		case "/v1/buckets/bkt_one/compat/merkledag/resolve":
			_, _ = w.Write([]byte(`{"profile":"merkledag.resolve/v0alpha1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	transport, err := client.New(client.Options{BaseURL: server.URL, TenantBearerToken: "tenant-secret", BucketID: "bkt_one"})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := transport.Resolve(t.Context(), protocol.ResolveRequest{Profile: protocol.ResolveProfile, Root: root.String(), Segments: []string{"docs"}})
	if err != nil || resolved.Target != target.String() {
		t.Fatalf("resolve result=%#v err=%v", resolved, err)
	}
	if head, err := transport.BucketHead(t.Context()); err != nil || head.Revision != 2 {
		t.Fatalf("head=%#v err=%v", head, err)
	}
	if data, err := transport.Get(t.Context(), target); err != nil || string(data) != "target" {
		t.Fatalf("Bucket CAS Get data=%q err=%v", data, err)
	}
	if present, err := transport.Has(t.Context(), target); err != nil || !present {
		t.Fatalf("Bucket CAS Has present=%v err=%v", present, err)
	}
	if response, err := transport.PostMerkleDAGResolve(t.Context(), []byte(`{"profile":"merkledag.resolve/v0alpha1"}`)); err != nil || len(response) == 0 {
		t.Fatalf("Bucket Merkle DAG resolve response=%q err=%v", response, err)
	}
	result, err := transport.PushBucket(t.Context(), client.BucketPushRequest{
		PushID: "push_one", BaseCommit: "cmt_one", BaseRoot: baseText, CandidateRoot: candidateText, BaseRevision: 2,
	})
	if err != nil || result.Status != "branched" || result.Branch == nil || result.Conflicts[0].Coordinate != "docs/readme" {
		t.Fatalf("push result=%#v err=%v", result, err)
	}
	if receivedPush.BaseRevision != 2 || receivedPush.BaseRoot != root.String() || receivedPush.CandidateRoot != target.String() {
		t.Fatalf("push request was not canonicalized: %#v", receivedPush)
	}
	_, err = transport.PushBucket(t.Context(), client.BucketPushRequest{
		PushID: "reused", BaseCommit: "cmt_one", BaseRoot: root.String(), CandidateRoot: target.String(), BaseRevision: 2,
	})
	var apiErr *client.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || !strings.Contains(apiErr.Message, "already used") {
		t.Fatalf("push ID conflict error = %T %v", err, err)
	}
}

func TestBucketHeadRejectsNonMainRef(t *testing.T) {
	root := mustBlockCID(t, []byte("root"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(client.BucketRef{
			BucketID: "bkt_one", Name: "heads/other", Kind: "explicit", State: "open",
			CommitID: "opaque-version", Root: root.String(), Revision: 1,
		})
	}))
	defer server.Close()

	transport, err := client.New(client.Options{BaseURL: server.URL, TenantBearerToken: "tenant-secret", BucketID: "bkt_one"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.BucketHead(t.Context()); err == nil || !strings.Contains(err.Error(), "main head") {
		t.Fatalf("BucketHead error = %v", err)
	}
}

func TestBucketPushRejectsUnboundGatewayResults(t *testing.T) {
	baseRoot := mustBlockCID(t, []byte("base"))
	candidateRoot := mustBlockCID(t, []byte("candidate"))
	mergedRoot := mustBlockCID(t, []byte("merged"))
	now := time.Now().UTC()
	request := client.BucketPushRequest{
		PushID: "push_one", BaseCommit: "opaque-base", BaseRoot: baseRoot.String(), CandidateRoot: candidateRoot.String(), BaseRevision: 1,
	}
	candidate := client.BucketCommit{
		ID: "opaque-candidate", BucketID: "bkt_one", Root: candidateRoot.String(), Parents: []string{"opaque-base"},
		BaseRoot: baseRoot.String(), Author: "alice", CreatedAt: now,
	}
	fastForwardHead := client.BucketRef{
		BucketID: "bkt_one", Name: "main", Kind: "main", State: "open", CommitID: candidate.ID,
		Root: candidate.Root, Revision: 2, CreatedAt: now, UpdatedAt: now,
	}
	merged := client.BucketCommit{
		ID: "opaque-merge", BucketID: "bkt_one", Root: mergedRoot.String(), Parents: []string{"opaque-remote", candidate.ID},
		BaseRoot: mustBlockCID(t, []byte("remote")).String(), Author: "alice", CreatedAt: now,
	}
	mergedHead := fastForwardHead
	mergedHead.CommitID, mergedHead.Root = merged.ID, merged.Root
	conflictBranch := fastForwardHead
	conflictBranch.Name, conflictBranch.Kind, conflictBranch.Revision = "conflicts/alice/one", "conflict", 1

	tests := []struct {
		name   string
		status int
		value  client.BucketPushResult
	}{
		{
			name: "fast-forward head points elsewhere", status: http.StatusCreated,
			value: client.BucketPushResult{Status: "fast_forward", Head: func() client.BucketRef {
				value := fastForwardHead
				value.CommitID = "another-version"
				return value
			}(), Candidate: candidate, Commit: candidate},
		},
		{
			name: "fast-forward omits candidate", status: http.StatusCreated,
			value: client.BucketPushResult{Status: "fast_forward", Head: fastForwardHead, Commit: candidate},
		},
		{
			name: "merge omits candidate parent", status: http.StatusCreated,
			value: client.BucketPushResult{Status: "merged", Head: mergedHead, Candidate: candidate, Commit: func() client.BucketCommit {
				value := merged
				value.Parents = []string{"opaque-remote", "another-candidate"}
				return value
			}(), MergeBase: baseRoot.String()},
		},
		{
			name: "conflict branch points elsewhere", status: http.StatusConflict,
			value: client.BucketPushResult{Status: "branched", Head: fastForwardHead, Candidate: candidate, Commit: candidate, Branch: func() *client.BucketRef {
				value := conflictBranch
				value.CommitID = "another-version"
				return &value
			}()},
		},
		{
			name: "branched status uses created response", status: http.StatusCreated,
			value: client.BucketPushResult{Status: "branched", Head: fastForwardHead, Candidate: candidate, Commit: candidate, Branch: &conflictBranch},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_ = json.NewEncoder(w).Encode(test.value)
			}))
			defer server.Close()
			transport, err := client.New(client.Options{BaseURL: server.URL, TenantBearerToken: "tenant-secret", BucketID: "bkt_one"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := transport.PushBucket(t.Context(), request); err == nil {
				t.Fatal("PushBucket accepted an unbound Gateway result")
			}
		})
	}
}

func TestBucketOptionsRequireTokenAndSecureRemoteTransport(t *testing.T) {
	if _, err := client.New(client.Options{BaseURL: "https://gateway.example", BucketID: "bkt_one"}); err == nil {
		t.Fatal("client accepted a Bucket without a tenant token")
	}
	if _, err := client.New(client.Options{BaseURL: "http://gateway.example", TenantBearerToken: "secret", BucketID: "bkt_one"}); err == nil {
		t.Fatal("client accepted a tenant token over non-loopback HTTP")
	}
}
