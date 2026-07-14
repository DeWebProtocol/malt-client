package daemon

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-client/internal/truststore"
)

func TestLocalAPIKeepsCandidateSeparate(t *testing.T) {
	store, err := truststore.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	root := "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
	req := httptest.NewRequest(http.MethodPut, "/v1/roots/docs", strings.NewReader(`{"root":"`+root+`","profile":"unixfs"}`))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trust status=%d body=%s", rec.Code, rec.Body.String())
	}
	record, err := store.Get("docs")
	if err != nil || record.AcceptedRoot != root {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}
