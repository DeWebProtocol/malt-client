package architecture_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestPackageBoundaries(t *testing.T) {
	root := moduleRoot(t)
	tests := []struct {
		path   string
		banned []string
	}{
		{path: "transport", banned: []string{"github.com/dewebprotocol/malt-client/application", "github.com/dewebprotocol/malt-client/unixfs", "github.com/dewebprotocol/malt-client/merkledag", "github.com/dewebprotocol/malt-client/trust"}},
		{path: "trust", banned: []string{"github.com/dewebprotocol/malt-client/application", "github.com/dewebprotocol/malt-client/transport", "github.com/dewebprotocol/malt-client/unixfs", "github.com/dewebprotocol/malt-client/merkledag"}},
		{path: "unixfs", banned: []string{"github.com/dewebprotocol/malt-client/merkledag"}},
		{path: "merkledag", banned: []string{"github.com/dewebprotocol/malt-client/transport", "github.com/dewebprotocol/malt/auth/proof", "github.com/dewebprotocol/malt/protocol"}},
		{path: "application", banned: []string{"github.com/dewebprotocol/malt-client/transport", "github.com/spf13/cobra"}},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			checkImports(t, filepath.Join(root, test.path), test.banned)
		})
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate architecture test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func checkImports(t *testing.T, root string, banned []string) {
	t.Helper()
	set := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(set, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			value, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			for _, prefix := range banned {
				if value == prefix || strings.HasPrefix(value, prefix+"/") {
					t.Errorf("%s imports forbidden dependency %s", path, value)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
