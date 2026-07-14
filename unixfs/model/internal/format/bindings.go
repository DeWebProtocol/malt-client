package format

import (
	"strings"

	cid "github.com/ipfs/go-cid"
)

// DirectoryRootBindings builds canonical bindings for a materialized UnixFS
// directory root. Direct children are included by name, and
// nested descendants are included by root-relative path for compatibility with
// existing flattened materialization callers.
func DirectoryRootBindings(payload cid.Cid, children map[string]cid.Cid, descendants map[string]cid.Cid) map[string]string {
	bindings := make(map[string]string, 1+len(children)+len(descendants))
	bindings["@payload"] = payload.String()
	for name, key := range children {
		bindings[name] = key.String()
	}
	for rel, key := range descendants {
		if !strings.Contains(rel, "/") {
			continue
		}
		bindings[rel] = key.String()
	}
	return bindings
}

// CountDefinedBindings counts non-empty targets in a binding map.
func CountDefinedBindings(bindings map[string]string) int {
	count := 0
	for _, target := range bindings {
		if strings.TrimSpace(target) != "" {
			count++
		}
	}
	return count
}
