package transport_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	client "github.com/dewebprotocol/malt-client/transport"
	cid "github.com/ipfs/go-cid"
)

func TestClientBatchCASAndMetricsContracts(t *testing.T) {
	blocks := []client.Block{{Data: []byte("first"), Codec: cid.Raw}, {Data: []byte("second"), Codec: cid.Raw}}
	keys := make([]cid.Cid, len(blocks))
	var putRequestBytes atomic.Uint64
	var putResponseBytes atomic.Uint64
	for i, block := range blocks {
		var err error
		keys[i], err = clientcas.CIDForBlock(clientcas.Block{Data: block.Data, Codec: block.Codec})
		if err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/cas/batch":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			putRequestBytes.Store(uint64(len(body)))
			var request struct {
				Profile string         `json:"profile"`
				Blocks  []client.Block `json:"blocks"`
			}
			if err := json.Unmarshal(body, &request); err != nil {
				t.Fatal(err)
			}
			if request.Profile != client.CASPutBatchProfile || len(request.Blocks) != 2 {
				t.Fatalf("put-batch request = %#v", request)
			}
			response, err := json.Marshal(map[string]any{
				"profile": client.CASPutBatchProfile,
				"results": []map[string]string{{"cid": keys[0].String(), "status": "stored"}, {"cid": keys[1].String(), "status": "stored"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			putResponseBytes.Store(uint64(len(response)))
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(response)
		case "/v1/cas/has":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile": client.CASHasBatchProfile,
				"results": []map[string]any{{"cid": keys[1].String(), "present": true}, {"cid": keys[0].String(), "present": false}},
			})
		case "/v1/diagnostics/metrics":
			withStorage := r.URL.Query().Get("storage") == "logical"
			var storage *client.StorageMetrics
			if withStorage {
				if r.Header.Get("Authorization") != "Bearer operator-secret" {
					t.Fatalf("storage metrics Authorization = %q", r.Header.Get("Authorization"))
				}
				storage = &client.StorageMetrics{Method: "logical-kv-scan", LogicalBytes: 42, CASBlobBytes: 11}
			}
			_ = json.NewEncoder(w).Encode(client.MetricsSnapshot{
				Profile: client.GatewayMetricsProfile, GeneratedAt: time.Now().UTC(),
				Storage: storage,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	transport, err := client.New(client.Options{BaseURL: server.URL, OperatorBearerToken: "operator-secret"})
	if err != nil {
		t.Fatal(err)
	}
	measurement, err := transport.PutBatchMeasured(t.Context(), blocks)
	if err != nil {
		t.Fatal(err)
	}
	put := measurement.Results
	if len(put) != 2 || !put[1].CID.Equals(keys[1]) {
		t.Fatalf("put results = %#v", put)
	}
	if measurement.RoundTripNS == 0 || measurement.RequestWireBytes != putRequestBytes.Load() ||
		measurement.ResponseWireBytes != putResponseBytes.Load() || measurement.RequestWireBytes == measurement.ResponseWireBytes {
		t.Fatalf("put directional measurement = %#v, request=%d response=%d", measurement, putRequestBytes.Load(), putResponseBytes.Load())
	}
	has, err := transport.HasBatchDetailed(t.Context(), []cid.Cid{keys[1], keys[0]})
	if err != nil {
		t.Fatal(err)
	}
	if len(has) != 2 || !has[0].Present || has[1].Present {
		t.Fatalf("has results = %#v", has)
	}
	metrics, err := transport.Metrics(t.Context())
	if err != nil || metrics.Profile != client.GatewayMetricsProfile || metrics.Storage != nil {
		t.Fatalf("metrics = %#v err=%v", metrics, err)
	}
	metrics, err = transport.MetricsWithStorage(t.Context())
	if err != nil || metrics.Storage == nil || metrics.Storage.LogicalBytes != 42 {
		t.Fatalf("metrics with storage = %#v err=%v", metrics, err)
	}
}

func TestPutBatchMeasuredUsesManagedBucketRouteAndCredential(t *testing.T) {
	block := client.Block{Data: []byte("bucket-payload"), Codec: cid.Raw}
	key, err := clientcas.CIDForBlock(clientcas.Block{Data: block.Data, Codec: block.Codec})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/buckets/bkt_one/cas/batch" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tenant-secret" {
			t.Fatalf("Authorization = %q", got)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile": client.CASPutBatchProfile,
			"results": []map[string]string{{"cid": key.String(), "status": "stored"}},
		})
	}))
	defer server.Close()

	transport, err := client.New(client.Options{
		BaseURL: server.URL, TenantBearerToken: "tenant-secret", BucketID: "bkt_one",
	})
	if err != nil {
		t.Fatal(err)
	}
	measurement, err := transport.PutBatchMeasured(t.Context(), []client.Block{block})
	if err != nil {
		t.Fatal(err)
	}
	if len(measurement.Results) != 1 || !measurement.Results[0].CID.Equals(key) ||
		measurement.RequestWireBytes == 0 || measurement.ResponseWireBytes == 0 || measurement.RoundTripNS == 0 {
		t.Fatalf("measurement = %#v", measurement)
	}
}

func TestMetricsWithStorageRequiresOperatorToken(t *testing.T) {
	transport, err := client.NewWithBaseURL("https://gateway.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.MetricsWithStorage(t.Context()); err == nil {
		t.Fatal("MetricsWithStorage accepted a client without an operator token")
	}
}

func TestNewRejectsOperatorTokenOverNonLoopbackHTTP(t *testing.T) {
	for _, baseURL := range []string{"http://gateway.example", "http://192.0.2.1:8080"} {
		t.Run(baseURL, func(t *testing.T) {
			if _, err := client.New(client.Options{BaseURL: baseURL, OperatorBearerToken: "operator-secret"}); err == nil || !strings.Contains(err.Error(), "requires HTTPS or a loopback HTTP") {
				t.Fatalf("New error = %v, want secure operator-token transport rejection", err)
			}
		})
	}
	for _, baseURL := range []string{"https://gateway.example", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		t.Run("allow "+baseURL, func(t *testing.T) {
			if _, err := client.New(client.Options{BaseURL: baseURL, OperatorBearerToken: "operator-secret"}); err != nil {
				t.Fatalf("New rejected secure or loopback operator-token transport: %v", err)
			}
		})
	}
}

func TestMetricsWithStorageRejectsRedirectWithoutLeakingToken(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("redirect target received Authorization %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer operator-secret" {
			t.Errorf("source Authorization = %q", got)
		}
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	transport, err := client.New(client.Options{
		BaseURL:             source.URL,
		HTTPClient:          source.Client(),
		OperatorBearerToken: "operator-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.MetricsWithStorage(t.Context()); err == nil || !strings.Contains(err.Error(), "refusing credentialed gateway redirect") {
		t.Fatalf("MetricsWithStorage redirect error = %v, want credentialed redirect refusal", err)
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("redirect target requests = %d, want 0", got)
	}
}
