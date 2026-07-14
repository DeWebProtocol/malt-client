// Package manifest implements the locked directory manifest JSON used by the
// UnixFS application model.
//
// Wire shape (locked):
//
//	{"entries":["docs","readme.md"]}
//
// Rules: top-level object with required "entries"; entries sorted lexicographically;
// each entry is one immediate child name; empty directory is {"entries":[]}.
// Child type and key are not stored; root-relative path resolution derives them
// from the current MALT structure.
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// DirectoryManifest is the JSON payload for a directory object (name-only).
type DirectoryManifest struct {
	Entries []string `json:"entries"`
}

var (
	// ErrInvalidManifest indicates JSON that is not a valid directory manifest.
	ErrInvalidManifest = errors.New("invalid directory manifest")
)

// ParseDirectoryJSON decodes and validates locked directory manifest JSON.
func ParseDirectoryJSON(data []byte) (*DirectoryManifest, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}
	for k := range raw {
		if k != "entries" {
			return nil, fmt.Errorf("%w: unknown field %q", ErrInvalidManifest, k)
		}
	}
	entRaw, ok := raw["entries"]
	if !ok {
		return nil, fmt.Errorf("%w: missing required field \"entries\"", ErrInvalidManifest)
	}
	var entries []string
	if err := json.Unmarshal(entRaw, &entries); err != nil {
		return nil, fmt.Errorf("%w: invalid \"entries\" array: %w", ErrInvalidManifest, err)
	}
	m := &DirectoryManifest{Entries: entries}
	if err := Validate(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Validate checks manifest invariants (sorted unique immediate child names).
func Validate(m *DirectoryManifest) error {
	if m == nil {
		return fmt.Errorf("%w: nil manifest", ErrInvalidManifest)
	}
	if len(m.Entries) == 0 {
		return nil
	}
	prev := ""
	for i, name := range m.Entries {
		if err := validateImmediateChildName(name); err != nil {
			return fmt.Errorf("%w: entries[%d]: %w", ErrInvalidManifest, i, err)
		}
		if name <= prev {
			if name == prev {
				return fmt.Errorf("%w: duplicate entry %q", ErrInvalidManifest, name)
			}
			return fmt.Errorf("%w: entries must be sorted lexicographically ascending", ErrInvalidManifest)
		}
		prev = name
	}
	return nil
}

func validateImmediateChildName(name string) error {
	if name == "" {
		return fmt.Errorf("empty child name")
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("immediate child name must not contain '/': %q", name)
	}
	if strings.Contains(name, "\\") {
		return fmt.Errorf("immediate child name must not contain '\\': %q", name)
	}
	return nil
}

// Normalize returns a copy with entries sorted and de-duplicated (first wins per name).
func Normalize(m *DirectoryManifest) *DirectoryManifest {
	if m == nil || len(m.Entries) == 0 {
		return &DirectoryManifest{Entries: nil}
	}
	uniq := slices.Clone(m.Entries)
	slices.Sort(uniq)
	out := uniq[:0]
	var prev string
	for _, s := range uniq {
		if s == prev {
			continue
		}
		out = append(out, s)
		prev = s
	}
	return &DirectoryManifest{Entries: out}
}

// MarshalJSON encodes the manifest; entries must already satisfy [Validate].
func (m *DirectoryManifest) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte(`{"entries":[]}`), nil
	}
	type alias DirectoryManifest
	return json.Marshal(alias(*m))
}
