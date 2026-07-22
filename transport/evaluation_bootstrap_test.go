package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	client "github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	listtree "github.com/dewebprotocol/malt/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestBootstrapEvaluationObjectBindsTokenRequestRootAndAccounting(t *testing.T) {
	target := clientRootRawCID(t, "bootstrap-target")
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	semanticMap, err := mappingradix.NewMap(scheme, materializermemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	root, err := semanticMap.Commit(context.Background(), "bootstrap-map", mapping.NewViewFrom(map[string]cid.Cid{"payload": target}))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapAuthorizationToken := strings.Repeat("b", 64)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/evaluation/client-root/bootstrap-object" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get(client.EvaluationBootstrapAuthorizationTokenHeader) != bootstrapAuthorizationToken ||
			request.Header.Get("X-Malt-Evaluation-Instance-Token") != "" || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request headers = %#v", request.Header)
		}
		var body struct {
			Profile      string `json:"profile"`
			OperationID  string `json:"operation_id"`
			Kind         string `json:"kind"`
			Backend      string `json:"backend"`
			ExpectedRoot string `json:"expected_root"`
			Entries      []struct {
				Path   *string `json:"path"`
				Target string  `json:"target"`
			} `json:"entries"`
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Profile != client.EvaluationClientRootBootstrapProfile || body.OperationID != "bootstrap-1" || body.Kind != "map" || body.Backend != "kzg" || body.ExpectedRoot != root.String() || len(body.Entries) != 1 || body.Entries[0].Path == nil || *body.Entries[0].Path != "payload" || body.Entries[0].Target != target.String() {
			t.Fatalf("bootstrap request = %#v", body)
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "private, no-store")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"profile": client.EvaluationClientRootBootstrapProfile, "root": root.String(),
			"replay_nanos": uint64(11), "persist_nanos": uint64(22), "write_accounting": validWriteAccounting(),
		})
	}))
	defer server.Close()

	transport, err := client.NewWithBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	path := "payload"
	result, err := transport.BootstrapEvaluationObject(t.Context(), bootstrapAuthorizationToken, client.EvaluationBootstrapObject{
		OperationID: "bootstrap-1", Kind: arcset.KindMap, Backend: maltcid.BackendKindKZG, ExpectedRoot: root,
		Entries: []client.EvaluationBootstrapEntry{{Path: &path, Target: target}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Root.Equals(root) || result.ReplayNanos != 11 || result.PersistNanos != 22 || !result.WriteAccounting.Available {
		t.Fatalf("bootstrap result = %#v", result)
	}
}

func TestBootstrapEvaluationObjectRejectsInvalidAuthorizationToken(t *testing.T) {
	root := clientRootRawCID(t, "not-a-semantic-root")
	transport, err := client.NewWithBaseURL("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	path := "payload"
	if _, err := transport.BootstrapEvaluationObject(t.Context(), "not-a-canonical-token", client.EvaluationBootstrapObject{
		OperationID: "bad", Kind: arcset.KindMap, Backend: maltcid.BackendKindKZG, ExpectedRoot: root,
		Entries: []client.EvaluationBootstrapEntry{{Path: &path, Target: root}},
	}); err == nil || !strings.Contains(err.Error(), "canonical SHA-256") {
		t.Fatalf("bootstrap-authorization-token error = %v", err)
	}
}

func TestBootstrapEvaluationObjectRequiresProtectedOrigin(t *testing.T) {
	transport, err := client.NewWithBaseURL("http://192.0.2.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.BootstrapEvaluationObject(t.Context(), strings.Repeat("a", 64), validBootstrapMapObject(t))
	if err == nil || !strings.Contains(err.Error(), "requires HTTPS or a loopback HTTP") {
		t.Fatalf("plaintext non-loopback bootstrap error = %v", err)
	}
}

func TestBootstrapEvaluationObjectRejectsRedirectWithoutLeakingToken(t *testing.T) {
	token := strings.Repeat("a", 64)
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		if got := r.Header.Get(client.EvaluationBootstrapAuthorizationTokenHeader); got != "" {
			t.Errorf("redirect target received bootstrap authorization %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(client.EvaluationBootstrapAuthorizationTokenHeader); got != token {
			t.Errorf("bootstrap source authorization = %q", got)
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	transport, err := client.NewWithBaseURL(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.BootstrapEvaluationObject(t.Context(), token, validBootstrapMapObject(t)); err == nil || !strings.Contains(err.Error(), "refusing evaluation bootstrap redirect") {
		t.Fatalf("bootstrap redirect error = %v", err)
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("bootstrap redirect target received %d requests", got)
	}
}

func TestBootstrapEvaluationObjectAllowsMeasuredZeroByteList(t *testing.T) {
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	predictor, err := listtree.NewList(scheme, materializermemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	root, err := predictor.CommitFixed(t.Context(), "empty-list", nil, 4096, 0)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("f", 64)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body struct {
			Kind      string            `json:"kind"`
			Entries   []json.RawMessage `json:"entries"`
			FixedList struct {
				TotalSize uint64 `json:"total_size"`
				ChunkSize uint64 `json:"chunk_size"`
			} `json:"fixed_list"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Kind != "list" || len(body.Entries) != 0 || body.FixedList.TotalSize != 0 || body.FixedList.ChunkSize != 4096 {
			t.Fatalf("empty-list request = %#v", body)
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"profile": client.EvaluationClientRootBootstrapProfile, "root": root.String(),
			"replay_nanos": uint64(1), "persist_nanos": uint64(1), "write_accounting": validWriteAccounting(),
		})
	}))
	defer server.Close()
	transport, err := client.NewWithBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.BootstrapEvaluationObject(t.Context(), token, client.EvaluationBootstrapObject{
		OperationID: "empty-list", Kind: arcset.KindList, Backend: maltcid.BackendKindKZG, ExpectedRoot: root,
		Entries: []client.EvaluationBootstrapEntry{}, Commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{TotalSize: 0, ChunkSize: 4096}},
	})
	if err != nil || !result.Root.Equals(root) {
		t.Fatalf("empty-list result = %#v err=%v", result, err)
	}
}

func validBootstrapMapObject(t *testing.T) client.EvaluationBootstrapObject {
	t.Helper()
	target := clientRootRawCID(t, "bootstrap-security-target")
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	semanticMap, err := mappingradix.NewMap(scheme, materializermemory.New(true))
	if err != nil {
		t.Fatal(err)
	}
	path := "payload"
	root, err := semanticMap.Commit(t.Context(), "bootstrap-security-map", mapping.NewViewFrom(map[string]cid.Cid{path: target}))
	if err != nil {
		t.Fatal(err)
	}
	return client.EvaluationBootstrapObject{
		OperationID: "bootstrap-security", Kind: arcset.KindMap, Backend: maltcid.BackendKindKZG, ExpectedRoot: root,
		Entries: []client.EvaluationBootstrapEntry{{Path: &path, Target: target}},
	}
}
