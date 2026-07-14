package manifest_test

import (
	"encoding/json"
	"testing"

	"github.com/dewebprotocol/malt-client/unixfs/model/internal/manifest"
)

func TestParseDirectoryJSON_valid(t *testing.T) {
	data := []byte(`{"entries":["a","b","docs"]}`)
	m, err := manifest.ParseDirectoryJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 3 || m.Entries[0] != "a" {
		t.Fatalf("entries = %#v", m.Entries)
	}
}

func TestParseDirectoryJSON_empty(t *testing.T) {
	m, err := manifest.ParseDirectoryJSON([]byte(`{"entries":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Entries == nil || len(m.Entries) != 0 {
		t.Fatalf("want empty entries, got %#v", m.Entries)
	}
}

func TestParseDirectoryJSON_unknownField(t *testing.T) {
	_, err := manifest.ParseDirectoryJSON([]byte(`{"entries":["a"],"extra":1}`))
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestParseDirectoryJSON_unsorted(t *testing.T) {
	_, err := manifest.ParseDirectoryJSON([]byte(`{"entries":["b","a"]}`))
	if err == nil {
		t.Fatal("expected error for unsorted entries")
	}
}

func TestParseDirectoryJSON_flatPathRejected(t *testing.T) {
	_, err := manifest.ParseDirectoryJSON([]byte(`{"entries":["a/b"]}`))
	if err == nil {
		t.Fatal("expected error for non-immediate name")
	}
}

func TestNormalize(t *testing.T) {
	n := manifest.Normalize(&manifest.DirectoryManifest{Entries: []string{"b", "a", "a"}})
	if len(n.Entries) != 2 || n.Entries[0] != "a" || n.Entries[1] != "b" {
		t.Fatalf("got %#v", n.Entries)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	m := &manifest.DirectoryManifest{Entries: []string{"docs", "readme.md"}}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := manifest.ParseDirectoryJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Entries[0] != "docs" || parsed.Entries[1] != "readme.md" {
		t.Fatalf("got %#v", parsed.Entries)
	}
}
