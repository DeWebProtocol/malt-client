package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/dewebprotocol/malt-client/internal/cas"
	clientconfig "github.com/dewebprotocol/malt-client/internal/config"
	"github.com/dewebprotocol/malt-client/merkledag"
	cid "github.com/ipfs/go-cid"
)

func TestMerkleDAGCommandsUseExplicitRootAndWriteVerifiedOutput(t *testing.T) {
	payload := []byte("verified Merkle DAG CLI bytes")
	root, err := cas.CIDForBlock(cas.Block{Data: payload, Codec: cid.Raw})
	if err != nil {
		t.Fatal(err)
	}
	evidence := []merkledag.MerkleDAGBlock{{CID: root.String(), Codec: cid.Raw, Data: payload}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/compat/merkledag/resolve":
			var request merkledag.MerkleDAGResolveRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Root != root.String() || request.Segments == nil || len(request.Segments) != 0 {
				t.Fatalf("resolve request = %#v", request)
			}
			_ = json.NewEncoder(w).Encode(merkledag.MerkleDAGResolveResponse{Profile: merkledag.MerkleDAGResolveProfile, Target: root.String(), Kind: "file", Blocks: evidence})
		case "/v1/compat/merkledag/read":
			var request merkledag.MerkleDAGReadRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Root != root.String() || request.Segments == nil || len(request.Segments) != 0 {
				t.Fatalf("read request = %#v", request)
			}
			_ = json.NewEncoder(w).Encode(merkledag.MerkleDAGReadResponse{Profile: merkledag.MerkleDAGReadProfile, Target: root.String(), Kind: "file", TotalSize: uint64(len(payload)), Length: uint64(len(payload)), Data: payload, Blocks: evidence})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	temp := t.TempDir()
	configPath := filepath.Join(temp, "config.json")
	if err := clientconfig.Write(configPath, &clientconfig.Config{
		Gateway: clientconfig.GatewayConfig{BaseURL: server.URL},
		Daemon:  clientconfig.DaemonConfig{SocketPath: filepath.Join(temp, "client.sock"), StatePath: filepath.Join(temp, "roots.json")},
	}); err != nil {
		t.Fatal(err)
	}
	previousConfig := cfgFile
	cfgFile = configPath
	defer func() { cfgFile = previousConfig }()

	var resolveOut bytes.Buffer
	merkleDAGResolveCmd.SetContext(t.Context())
	merkleDAGResolveCmd.SetOut(&resolveOut)
	if err := runMerkleDAGResolve(merkleDAGResolveCmd, []string{root.String()}); err != nil {
		t.Fatal(err)
	}
	var resolved merkledag.MerkleDAGResolveResponse
	if err := json.Unmarshal(resolveOut.Bytes(), &resolved); err != nil {
		t.Fatalf("resolve JSON: %v", err)
	}
	if resolved.Target != root.String() {
		t.Fatalf("resolve target = %s", resolved.Target)
	}

	var catOut bytes.Buffer
	merkleDAGCatCmd.SetContext(t.Context())
	merkleDAGCatCmd.SetOut(&catOut)
	if err := runMerkleDAGCat(merkleDAGCatCmd, []string{root.String()}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(catOut.Bytes(), payload) {
		t.Fatalf("cat output = %q", catOut.Bytes())
	}
	if _, _, err := merkleDAGInputs([]string{"not-a-trusted-alias"}); err == nil {
		t.Fatal("Merkle DAG command accepted a non-CID trust-store alias")
	}
}

func TestMerkleDAGCLIPathRetainsUnixFSStringSyntax(t *testing.T) {
	root := "bafkqaaa"
	for _, rawPath := range []string{".", "..", "/name", "name/", "a//b", "bad\x00name"} {
		if _, _, err := merkleDAGInputs([]string{root, rawPath}); err == nil {
			t.Fatalf("CLI accepted invalid UnixFS path %q", rawPath)
		}
	}
	_, segments, err := merkleDAGInputs([]string{root, "a/b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 2 || segments[0] != "a" || segments[1] != "b" {
		t.Fatalf("CLI slash projection = %#v, want [a b]", segments)
	}
}
