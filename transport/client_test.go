package transport_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-client/internal/cas"
	client "github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt/auth/proof/prooflist"
	"github.com/dewebprotocol/malt/protocol"
	cid "github.com/ipfs/go-cid"
)

func TestNewRejectsNonAbsoluteBaseURL(t *testing.T) {
	if _, err := client.New(client.Options{BaseURL: "gateway.local"}); err == nil {
		t.Fatal("New accepted a non-absolute gateway URL")
	}
	if _, err := client.NewWithBaseURL("://bad"); err == nil {
		t.Fatal("NewWithBaseURL accepted an invalid gateway URL")
	}
	if _, err := client.New(client.Options{BaseURL: "ftp://gateway.example"}); err == nil {
		t.Fatal("New accepted a non-HTTP gateway URL")
	}
}

func TestClientExposesFixedMerkleDAGRoutesWithoutArbitraryProfileEscapeHatch(t *testing.T) {
	typ := reflect.TypeOf((*client.Client)(nil))
	if _, ok := typ.MethodByName("PostProfileJSON"); ok {
		t.Fatal("transport client still exposes arbitrary profile route access")
	}
	if _, ok := typ.MethodByName("CreatePayloadRoot"); ok {
		t.Fatal("generic transport client exposes UnixFS payload-root semantics")
	}
	for _, name := range []string{"PostMerkleDAGResolve", "PostMerkleDAGRead"} {
		if _, ok := typ.MethodByName(name); !ok {
			t.Fatalf("transport client is missing fixed capability %s", name)
		}
	}
}

func TestPublicClientUsesGenericContractsAndBindsCASWrites(t *testing.T) {
	root := mustBlockCID(t, []byte("root"))
	target := mustBlockCID(t, []byte("target"))
	payload := []byte("payload")
	payloadCID := mustBlockCID(t, payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/resolve":
			var request protocol.ResolveRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Root != root.String() || len(request.Segments) != 1 || request.Segments[0] != "name" {
				t.Fatalf("resolve request = %#v", request)
			}
			_ = json.NewEncoder(w).Encode(protocol.ResolveResult{Profile: protocol.ResolveProfile, Target: target.String(), ProofList: prooflist.ProofList{Root: root}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/cas":
			body, _ := io.ReadAll(r.Body)
			if string(body) != string(payload) {
				t.Fatalf("CAS body = %q", body)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"cid": payloadCID.String()})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	transport, err := client.NewWithBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.Resolve(t.Context(), protocol.ResolveRequest{Profile: protocol.ResolveProfile, Root: root.String(), Segments: []string{"name"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Target != target.String() {
		t.Fatalf("target = %q, want %q", result.Target, target)
	}
	put, err := transport.Put(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if !put.Equals(payloadCID) {
		t.Fatalf("Put = %s, want %s", put, payloadCID)
	}
}

func TestUnscopedClientRejectsSingleValueCASReadsWithoutHTTP(t *testing.T) {
	payloadCID := mustBlockCID(t, []byte("payload"))
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()

	transport, err := client.NewWithBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Get(t.Context(), payloadCID); err == nil || !strings.Contains(err.Error(), "managed Bucket") {
		t.Fatalf("unscoped Get error = %v", err)
	}
	if _, err := transport.Has(t.Context(), payloadCID); err == nil || !strings.Contains(err.Error(), "managed Bucket") {
		t.Fatalf("unscoped Has error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("unscoped Get/Has sent %d HTTP requests", requests)
	}
}

func TestClientRejectsOversizedAndTrailingResponses(t *testing.T) {
	payloadCID := mustBlockCID(t, []byte("payload"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			_, _ = io.WriteString(w, `{"status":"ok"}{"trailing":true}`)
		case "/v1/buckets/bkt_one/cas/" + payloadCID.String():
			_, _ = w.Write(bytesOf('x', 17))
		case "/v1/buckets/bkt_one/resolve":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(bytesOf('e', 9))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	transport, err := client.New(client.Options{
		BaseURL: server.URL, TenantBearerToken: "tenant-secret", BucketID: "bkt_one",
		MaxJSONResponseBytes: 64, MaxBlobResponseBytes: 16, MaxErrorResponseBytes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Health(t.Context()); err == nil {
		t.Fatal("client accepted trailing JSON content")
	}
	if _, err := transport.Get(t.Context(), payloadCID); err == nil {
		t.Fatal("client accepted an oversized CAS body")
	}
	root := mustBlockCID(t, []byte("root"))
	_, err = transport.Resolve(t.Context(), protocol.ResolveRequest{Profile: protocol.ResolveProfile, Root: root.String(), Segments: []string{"name"}})
	var apiErr *client.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway || apiErr.Message == "" {
		t.Fatalf("oversized error response = %T %v", err, err)
	}
}

func TestClientRejectsOversizedJSONBeforeDecode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytesOf('x', 33))
	}))
	defer server.Close()
	transport, err := client.New(client.Options{BaseURL: server.URL, MaxJSONResponseBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.Health(t.Context()); err == nil {
		t.Fatal("client accepted an oversized JSON response")
	}
}

func TestGetClassifiesOnlyHTTPNotFoundAsCASNotFound(t *testing.T) {
	payloadCID := mustBlockCID(t, []byte("missing"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer server.Close()

	transport, err := client.New(client.Options{BaseURL: server.URL, TenantBearerToken: "tenant-secret", BucketID: "bkt_one"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.Get(t.Context(), payloadCID)
	if !errors.Is(err, cas.ErrNotFound) {
		t.Fatalf("Get error = %v, want cas.ErrNotFound", err)
	}
	var apiErr *client.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("Get error = %T %v, want structured 404", err, err)
	}
}

func bytesOf(value byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = value
	}
	return out
}

func mustBlockCID(t *testing.T, data []byte) cid.Cid {
	t.Helper()
	key, err := cas.CIDForBlock(cas.Block{Data: data, Codec: cid.Raw})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
