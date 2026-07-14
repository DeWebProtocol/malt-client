package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt/auth/proof/prooflist"
	"github.com/dewebprotocol/malt/protocol"
	cid "github.com/ipfs/go-cid"
)

func TestClientUsesGenericResolveContract(t *testing.T) {
	root := mustBlockCID(t, []byte("root"))
	target := mustBlockCID(t, []byte("target"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/resolve" {
			http.NotFound(w, r)
			return
		}
		var request protocol.ResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Root != root.String() || len(request.Segments) != 1 || request.Segments[0] != "name" {
			t.Fatalf("resolve request = %#v", request)
		}
		_ = json.NewEncoder(w).Encode(protocol.ResolveResult{
			Profile: protocol.ResolveProfile,
			Target:  target.String(),
			ProofList: prooflist.ProofList{
				Root: root,
			},
		})
	}))
	defer server.Close()

	client := NewWithBaseURL(server.URL)
	result, err := client.Resolve(t.Context(), protocol.ResolveRequest{
		Profile: protocol.ResolveProfile,
		Root:    root.String(),
		Segments: []string{
			"name",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Target != target.String() {
		t.Fatalf("target = %q, want %q", result.Target, target)
	}
}

func TestClientCASChecksGatewayCIDAndBody(t *testing.T) {
	payload := []byte("payload")
	want, err := cas.CIDForBlock(cas.Block{Data: payload, Codec: cid.Raw})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/cas":
			body, _ := io.ReadAll(r.Body)
			if string(body) != string(payload) {
				t.Fatalf("CAS body = %q", body)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"cid": want.String()})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/cas/"+want.String():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewWithBaseURL(server.URL)
	got, err := client.Put(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equals(want) {
		t.Fatalf("Put() = %s, want %s", got, want)
	}
	body, err := client.Get(t.Context(), want)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(payload) {
		t.Fatalf("Get() = %q, want %q", body, payload)
	}
}

func TestClientRejectsMismatchedCASResponse(t *testing.T) {
	wrong := mustBlockCID(t, []byte("wrong"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"cid": wrong.String()})
	}))
	defer server.Close()

	if _, err := NewWithBaseURL(server.URL).Put(t.Context(), []byte("payload")); err == nil {
		t.Fatal("Put accepted a CID that does not bind the uploaded bytes")
	}
}

func mustBlockCID(t *testing.T, data []byte) cid.Cid {
	t.Helper()
	key, err := cas.CIDForBlock(cas.Block{Data: data, Codec: cid.Raw})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
