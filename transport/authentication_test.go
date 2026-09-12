package transport_test

import (
	"encoding/json"
	"github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticationTransportPreservesUint64AndRejectsChangedReceipt(t *testing.T) {
	descriptor := maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: maltcid.IPA256}
	root, err := maltcid.NewRoot(descriptor, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	index := input.IndexValue(^uint64(0))
	var observed protocol.AuthenticationRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/authentication/query":
			raw := json.NewDecoder(r.Body)
			if err := raw.Decode(&observed); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(protocol.AuthenticationResult{Profile: protocol.AuthenticationProfile, Resolved: root.String(), Traversal: engine.Traversal{}})
		case "/v1/authentication/candidates":
			_ = json.NewEncoder(w).Encode(map[string]string{"profile": protocol.AuthenticationProfile, "root": "bafkqaaa"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := transport.NewWithBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := protocol.AuthenticationRequest{Profile: protocol.AuthenticationProfile, Root: root.String(), Operation: "binding", Input: &index}
	if _, err = client.Authenticate(t.Context(), query); err != nil {
		t.Fatal(err)
	}
	if observed.Input == nil || observed.Input.Number != ^uint64(0) || observed.Root != query.Root {
		t.Fatal("transport changed authentication coordinates")
	}
	candidate := protocol.AuthenticationCandidate{Profile: protocol.AuthenticationProfile, Root: root.String(), State: engine.State{Descriptor: descriptor}}
	if _, err = client.MaterializeAuthentication(t.Context(), candidate); err == nil {
		t.Fatal("accepted a different receipt Root")
	}
}
