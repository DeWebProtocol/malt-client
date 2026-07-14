package unixfs_test

import (
	"errors"
	"testing"

	unixfs "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/auth/arcset"
)

func TestParsePathAppliesUnixFSPolicyOutsideCore(t *testing.T) {
	segments, err := unixfs.ParsePath("docs/readme.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 2 || segments[0] != "docs" || segments[1] != "readme.md" {
		t.Fatalf("segments = %v", segments)
	}

	if _, err := unixfs.ParsePath("docs/@payload"); !errors.Is(err, unixfs.ErrReservedPath) {
		t.Fatalf("reserved error = %v", err)
	}
	if _, err := unixfs.ParsePath(".."); !errors.Is(err, unixfs.ErrInvalidPath) {
		t.Fatalf("parent path error = %v", err)
	}

	// Generic MALT coordinates deliberately do not inherit UnixFS path policy.
	if _, err := arcset.NewPath(".."); err != nil {
		t.Fatalf("generic core coordinate rejected by UnixFS policy: %v", err)
	}
}
