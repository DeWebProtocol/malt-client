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
			_ = json.NewEncoder(w).Encode(client.BucketPushResult{
				Status: "branched",
				Head:   client.BucketRef{BucketID: "bkt_one", Name: "main", Kind: "main", State: "open", CommitID: "cmt_one", Root: root.String(), Revision: 2, CreatedAt: now, UpdatedAt: now},
				Commit: client.BucketCommit{ID: "cmt_candidate", BucketID: "bkt_one", Root: target.String(), Author: "alice", CreatedAt: now},
				Branch: &branch, Conflicts: []client.BucketConflict{{Coordinate: "docs/readme"}},
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
	if response, err := transport.PostMerkleDAGResolve(t.Context(), []byte(`{"profile":"merkledag.resolve/v0alpha1"}`)); err != nil || len(response) == 0 {
		t.Fatalf("Bucket Merkle DAG resolve response=%q err=%v", response, err)
	}
	result, err := transport.PushBucket(t.Context(), client.BucketPushRequest{
		PushID: "push_one", BaseCommit: "cmt_one", BaseRoot: root.String(), CandidateRoot: target.String(), BaseRevision: 2,
	})
	if err != nil || result.Status != "branched" || result.Branch == nil || result.Conflicts[0].Coordinate != "docs/readme" {
		t.Fatalf("push result=%#v err=%v", result, err)
	}
	if receivedPush.BaseRevision != 2 {
		t.Fatalf("push base revision = %d", receivedPush.BaseRevision)
	}
	_, err = transport.PushBucket(t.Context(), client.BucketPushRequest{
		PushID: "reused", BaseCommit: "cmt_one", BaseRoot: root.String(), CandidateRoot: target.String(), BaseRevision: 2,
	})
	var apiErr *client.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || !strings.Contains(apiErr.Message, "already used") {
		t.Fatalf("push ID conflict error = %T %v", err, err)
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
