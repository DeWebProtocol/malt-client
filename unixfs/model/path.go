package unixfs

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	ErrReservedPath = errors.New("unixfs path uses a reserved segment")
	ErrInvalidPath  = errors.New("unixfs path contains an unsupported segment")
)

// ParsePath applies the UnixFS application model's relative-path policy. This
// policy is intentionally stricter than generic MALT arc coordinates.
func ParsePath(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	if strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return nil, fmt.Errorf("%w: path must be relative and must not end with /", ErrInvalidPath)
	}
	segments := strings.Split(path, "/")
	for _, segment := range segments {
		if strings.HasPrefix(segment, "@") {
			return nil, fmt.Errorf("%w: %s", ErrReservedPath, segment)
		}
		if !isPortableSegment(segment) {
			return nil, fmt.Errorf("%w: %s", ErrInvalidPath, segment)
		}
	}
	return segments, nil
}

func isPortableSegment(segment string) bool {
	if segment == "" || segment == "." || segment == ".." || !utf8.ValidString(segment) {
		return false
	}
	for _, r := range segment {
		if r == 0 || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}
