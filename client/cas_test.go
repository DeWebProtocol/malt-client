package client_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	client "github.com/dewebprotocol/malt-client/client"
	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	cid "github.com/ipfs/go-cid"
)

func TestClientBatchCASAndMetricsContracts(t *testing.T) {
	blocks := []client.Block{{Data: []byte("first"), Codec: cid.Raw}, {Data: []byte("second"), Codec: cid.Raw}}
	keys := make([]cid.Cid, len(blocks))
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
			var request struct {
				Profile string         `json:"profile"`
				Blocks  []client.Block `json:"blocks"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Profile != client.CASPutBatchProfile || len(request.Blocks) != 2 {
				t.Fatalf("put-batch request = %#v", request)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile": client.CASPutBatchProfile,
				"results": []map[string]string{{"cid": keys[0].String(), "status": "stored"}, {"cid": keys[1].String(), "status": "stored"}},
			})
		case "/v1/cas/has":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile": client.CASHasBatchProfile,
				"results": []map[string]any{{"cid": keys[1].String(), "present": true}, {"cid": keys[0].String(), "present": false}},
			})
		case "/v1/diagnostics/metrics":
			withStorage := r.URL.Query().Get("storage") == "logical"
			var storage *client.StorageMetrics
			if withStorage {
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
	transport, err := client.NewWithBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	put, err := transport.PutBatch(t.Context(), blocks)
	if err != nil {
		t.Fatal(err)
	}
	if len(put) != 2 || !put[1].CID.Equals(keys[1]) {
		t.Fatalf("put results = %#v", put)
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
