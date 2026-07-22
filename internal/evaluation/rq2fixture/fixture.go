// Package rq2fixture defines the bounded source fixture used by the paper RQ2
// native and browser writers. The fixture binds the initial accepted root to
// exact source bytes and declares every operation target before measurement.
package rq2fixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt-client/unixfs"
	"github.com/dewebprotocol/malt/auth/arcset"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	SchemaVersion = "malt-rq2-source-fixture/v1"

	KindDirectReplace = "direct-replace"
	KindDirectInsert  = "direct-insert"
	KindDirectDelete  = "direct-delete"
	KindDirectMove    = "direct-move"
	KindListAppend    = "list-append"
	KindListReplace   = "list-replace"
	KindBatchInsert   = "batch-insert"
	KindDocumentEdit  = "document-edit"

	maxFiles        = 4096
	maxOperations   = 256
	maxChunks       = 65536
	maxDecodedBytes = 64 << 20
)

var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type RootBinding struct {
	Backend string `json:"backend"`
	CID     string `json:"cid"`
}

type DirectFile struct {
	Path       string `json:"path"`
	Coordinate string `json:"coordinate"`
	Bytes      []byte `json:"bytes"`
	CID        string `json:"cid"`
}

type ListChunk struct {
	Index uint64 `json:"index"`
	Bytes []byte `json:"bytes"`
	CID   string `json:"cid"`
}

type ListFile struct {
	Path       string      `json:"path"`
	Coordinate string      `json:"coordinate"`
	ChunkSize  uint64      `json:"chunk_size"`
	TotalSize  uint64      `json:"total_size"`
	Chunks     []ListChunk `json:"chunks"`
}

type BatchTarget struct {
	Path         string `json:"path"`
	Coordinate   string `json:"coordinate"`
	PayloadBytes uint64 `json:"payload_bytes"`
}

// Operation fixes the source path and authenticated coordinate affected by an
// evaluator operation. Coordinates are deliberately explicit even though the
// v1 source profile requires them to equal their canonical UnixFS paths.
type Operation struct {
	Name                  string        `json:"name"`
	Kind                  string        `json:"kind"`
	SourcePath            string        `json:"source_path,omitempty"`
	SourceCoordinate      string        `json:"source_coordinate,omitempty"`
	DestinationPath       string        `json:"destination_path,omitempty"`
	DestinationCoordinate string        `json:"destination_coordinate,omitempty"`
	PayloadBytes          uint64        `json:"payload_bytes,omitempty"`
	ListIndex             *uint64       `json:"list_index,omitempty"`
	Batch                 []BatchTarget `json:"batch,omitempty"`
}

type Fixture struct {
	SchemaVersion      string        `json:"schema_version"`
	FixtureID          string        `json:"fixture_id"`
	MutationSeedSHA256 string        `json:"mutation_seed_sha256"`
	InitialRoots       []RootBinding `json:"initial_roots"`
	DirectFiles        []DirectFile  `json:"direct_files"`
	ListFiles          []ListFile    `json:"list_files"`
	Operations         []Operation   `json:"operations"`
}

// Decode accepts exactly one JSON object, rejects unknown fields, and verifies
// all roots, CIDs, source bytes, descriptors, paths, and operation targets.
func Decode(data []byte) (*Fixture, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("decode RQ2 source fixture: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var fixture Fixture
	if err := decoder.Decode(&fixture); err != nil {
		return nil, fmt.Errorf("decode RQ2 source fixture: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("RQ2 source fixture must contain exactly one JSON object")
	}
	if err := fixture.Validate(); err != nil {
		return nil, err
	}
	return &fixture, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if _, duplicate := keys[key]; duplicate {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				keys[key] = struct{}{}
				if err := value(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return fmt.Errorf("unterminated JSON object")
			}
		case '[':
			for decoder.More() {
				if err := value(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return fmt.Errorf("unterminated JSON array")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON contains trailing data")
	}
	return nil
}

func (f *Fixture) Validate() error {
	if f == nil || f.SchemaVersion != SchemaVersion || !identityPattern.MatchString(f.FixtureID) || !canonicalSHA256(f.MutationSeedSHA256) {
		return fmt.Errorf("RQ2 source fixture identity or schema is invalid")
	}
	if len(f.InitialRoots) == 0 || len(f.InitialRoots) > 2 || len(f.DirectFiles)+len(f.ListFiles) == 0 || len(f.DirectFiles)+len(f.ListFiles) > maxFiles {
		return fmt.Errorf("RQ2 source fixture root or file count is outside evaluator bounds")
	}
	roots := make(map[string]cid.Cid, len(f.InitialRoots))
	for _, binding := range f.InitialRoots {
		if binding.Backend != "kzg" && binding.Backend != "ipa" || roots[binding.Backend].Defined() {
			return fmt.Errorf("RQ2 source fixture has an invalid or duplicate backend root")
		}
		root, err := cid.Parse(binding.CID)
		if err != nil || string(maltcid.BackendKindOf(root)) != binding.Backend || root.String() != binding.CID {
			return fmt.Errorf("RQ2 source fixture %s root is not a canonical typed MALT CID", binding.Backend)
		}
		roots[binding.Backend] = root
	}
	paths := make(map[string]string, len(f.DirectFiles)+len(f.ListFiles))
	var decodedBytes uint64
	for _, file := range f.DirectFiles {
		if err := validatePathCoordinate(file.Path, file.Coordinate); err != nil {
			return fmt.Errorf("direct file: %w", err)
		}
		if _, exists := paths[file.Path]; exists {
			return fmt.Errorf("RQ2 source fixture repeats path %q", file.Path)
		}
		if err := validateRawCID(file.Bytes, file.CID); err != nil {
			return fmt.Errorf("direct file %q: %w", file.Path, err)
		}
		paths[file.Path] = "direct"
		decodedBytes += uint64(len(file.Bytes))
	}
	chunkCount := 0
	for _, file := range f.ListFiles {
		if err := validatePathCoordinate(file.Path, file.Coordinate); err != nil {
			return fmt.Errorf("list file: %w", err)
		}
		if _, exists := paths[file.Path]; exists {
			return fmt.Errorf("RQ2 source fixture repeats path %q", file.Path)
		}
		if file.ChunkSize == 0 || file.TotalSize == 0 || len(file.Chunks) == 0 {
			return fmt.Errorf("list file %q has an empty fixed-list descriptor", file.Path)
		}
		var total uint64
		for index, chunk := range file.Chunks {
			if chunk.Index != uint64(index) || len(chunk.Bytes) == 0 || uint64(len(chunk.Bytes)) > file.ChunkSize {
				return fmt.Errorf("list file %q chunk %d is not a bounded contiguous chunk", file.Path, index)
			}
			if index != len(file.Chunks)-1 && uint64(len(chunk.Bytes)) != file.ChunkSize {
				return fmt.Errorf("list file %q has a partial non-final chunk", file.Path)
			}
			if err := validateRawCID(chunk.Bytes, chunk.CID); err != nil {
				return fmt.Errorf("list file %q chunk %d: %w", file.Path, index, err)
			}
			total += uint64(len(chunk.Bytes))
			decodedBytes += uint64(len(chunk.Bytes))
		}
		if total != file.TotalSize {
			return fmt.Errorf("list file %q bytes do not match total_size", file.Path)
		}
		paths[file.Path] = "list"
		chunkCount += len(file.Chunks)
	}
	if chunkCount > maxChunks || decodedBytes == 0 || decodedBytes > maxDecodedBytes {
		return fmt.Errorf("RQ2 source fixture decoded bytes or chunk count is outside evaluator bounds")
	}
	if len(f.Operations) == 0 || len(f.Operations) > maxOperations {
		return fmt.Errorf("RQ2 source fixture operation count is outside evaluator bounds")
	}
	operations := make(map[string]struct{}, len(f.Operations))
	for _, operation := range f.Operations {
		if !identityPattern.MatchString(operation.Name) {
			return fmt.Errorf("RQ2 source fixture operation name %q is invalid", operation.Name)
		}
		if _, exists := operations[operation.Name]; exists {
			return fmt.Errorf("RQ2 source fixture repeats operation %q", operation.Name)
		}
		operations[operation.Name] = struct{}{}
		if err := validateOperation(operation, paths); err != nil {
			return fmt.Errorf("operation %q: %w", operation.Name, err)
		}
		if operation.Kind == KindListAppend || operation.Kind == KindListReplace {
			list, ok := f.List(operation.SourcePath)
			if !ok {
				return fmt.Errorf("operation %q: list source is not declared", operation.Name)
			}
			if operation.Kind == KindListAppend && operation.PayloadBytes != list.ChunkSize {
				return fmt.Errorf("operation %q: fixed-list append payload must equal chunk_size", operation.Name)
			}
			if operation.Kind == KindListReplace {
				if operation.ListIndex == nil || *operation.ListIndex >= uint64(len(list.Chunks)) || operation.PayloadBytes != uint64(len(list.Chunks[*operation.ListIndex].Bytes)) {
					return fmt.Errorf("operation %q: replacement must target one declared chunk with the same byte length", operation.Name)
				}
			}
		}
	}
	return nil
}

func validateOperation(operation Operation, initialPaths map[string]string) error {
	source := func(kind string) error {
		if err := validatePathCoordinate(operation.SourcePath, operation.SourceCoordinate); err != nil {
			return err
		}
		if initialPaths[operation.SourcePath] != kind {
			return fmt.Errorf("source %q is not an initial %s file", operation.SourcePath, kind)
		}
		return nil
	}
	destination := func() error {
		if err := validatePathCoordinate(operation.DestinationPath, operation.DestinationCoordinate); err != nil {
			return err
		}
		if _, exists := initialPaths[operation.DestinationPath]; exists {
			return fmt.Errorf("destination %q already exists initially", operation.DestinationPath)
		}
		return nil
	}
	switch operation.Kind {
	case KindDirectReplace:
		if err := source("direct"); err != nil {
			return err
		}
		return requirePayload(operation.PayloadBytes)
	case KindDocumentEdit:
		if err := source("direct"); err != nil {
			return err
		}
		return requirePayload(operation.PayloadBytes)
	case KindDirectInsert:
		if err := destination(); err != nil {
			return err
		}
		return requirePayload(operation.PayloadBytes)
	case KindDirectDelete:
		if err := source("direct"); err != nil {
			return err
		}
		if operation.PayloadBytes != 0 {
			return fmt.Errorf("delete declares payload bytes")
		}
	case KindDirectMove:
		if err := source("direct"); err != nil {
			return err
		}
		if err := destination(); err != nil {
			return err
		}
		if operation.PayloadBytes != 0 {
			return fmt.Errorf("move declares payload bytes")
		}
	case KindListAppend:
		if err := source("list"); err != nil {
			return err
		}
		if operation.ListIndex != nil {
			return fmt.Errorf("append declares a list index")
		}
		return requirePayload(operation.PayloadBytes)
	case KindListReplace:
		if err := source("list"); err != nil {
			return err
		}
		if operation.ListIndex == nil {
			return fmt.Errorf("list replacement omits its exact index")
		}
		return requirePayload(operation.PayloadBytes)
	case KindBatchInsert:
		if len(operation.Batch) == 0 || len(operation.Batch) > 64 || operation.PayloadBytes != 0 {
			return fmt.Errorf("batch target count or aggregate payload declaration is invalid")
		}
		seen := make(map[string]struct{}, len(operation.Batch))
		for _, target := range operation.Batch {
			if err := validatePathCoordinate(target.Path, target.Coordinate); err != nil {
				return err
			}
			if _, exists := initialPaths[target.Path]; exists {
				return fmt.Errorf("batch destination %q already exists initially", target.Path)
			}
			if _, exists := seen[target.Path]; exists {
				return fmt.Errorf("batch repeats destination %q", target.Path)
			}
			seen[target.Path] = struct{}{}
			if err := requirePayload(target.PayloadBytes); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported operation kind %q", operation.Kind)
	}
	return nil
}

func requirePayload(size uint64) error {
	if size == 0 || size > maxDecodedBytes {
		return fmt.Errorf("payload size is outside evaluator bounds")
	}
	return nil
}

func validatePathCoordinate(path, coordinate string) error {
	if path == "" || path != coordinate {
		return fmt.Errorf("source path and authenticated coordinate must be identical and non-empty")
	}
	_, err := unixfs.ParseCanonicalStagedPath(path)
	if err != nil {
		return fmt.Errorf("path %q is not a canonical relative UnixFS path", path)
	}
	canonical, err := arcset.NewMapCoordinate(path)
	if err != nil || canonical.String() != coordinate {
		return fmt.Errorf("coordinate %q is not canonical", coordinate)
	}
	return nil
}

func validateRawCID(data []byte, encoded string) error {
	parsed, err := cid.Parse(encoded)
	if err != nil || parsed.Type() != cid.Raw || parsed.String() != encoded {
		return fmt.Errorf("CID is not one canonical raw CID")
	}
	expected, err := clientcas.CIDForBlock(clientcas.Block{Codec: cid.Raw, Data: data})
	if err != nil || !expected.Equals(parsed) {
		return fmt.Errorf("CID does not bind the declared bytes")
	}
	return nil
}

func canonicalSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (f *Fixture) Root(backend string) (cid.Cid, error) {
	for _, binding := range f.InitialRoots {
		if binding.Backend == backend {
			root, _ := cid.Parse(binding.CID)
			return root, nil
		}
	}
	return cid.Undef, fmt.Errorf("RQ2 source fixture has no %s initial root", backend)
}

func (f *Fixture) Operation(name string) (Operation, error) {
	for _, operation := range f.Operations {
		if operation.Name == name {
			return operation, nil
		}
	}
	return Operation{}, fmt.Errorf("RQ2 source fixture does not declare operation %q", name)
}

func (f *Fixture) RequireOperations(names []string) error {
	want := append([]string(nil), names...)
	slices.Sort(want)
	want = slices.Compact(want)
	for _, name := range want {
		if _, err := f.Operation(name); err != nil {
			return err
		}
	}
	return nil
}

func (f *Fixture) InitialSource() map[string][]byte {
	result := make(map[string][]byte, len(f.DirectFiles)+len(f.ListFiles))
	for _, file := range f.DirectFiles {
		result[file.Path] = append([]byte(nil), file.Bytes...)
	}
	for _, file := range f.ListFiles {
		for _, chunk := range file.Chunks {
			result[file.Path] = append(result[file.Path], chunk.Bytes...)
		}
	}
	return result
}

func (f *Fixture) List(path string) (ListFile, bool) {
	for _, file := range f.ListFiles {
		if file.Path == path {
			return file, true
		}
	}
	return ListFile{}, false
}

// Payload derives the exact operation payload from the pinned mutation seed.
// This keeps repeated browser sessions bounded without letting a worker invent
// target paths or unregistered source material.
func (f *Fixture) Payload(operation string, ordinal uint64, target int, size uint64) ([]byte, error) {
	if size == 0 || size > maxDecodedBytes || target < 0 || target > 64 {
		return nil, fmt.Errorf("RQ2 derived payload request is outside evaluator bounds")
	}
	seed, err := hex.DecodeString(f.MutationSeedSHA256)
	if err != nil {
		return nil, err
	}
	label := fmt.Sprintf("%s\x00%d\x00%d", operation, ordinal, target)
	base := sha256.Sum256(append(seed, []byte(label)...))
	output := make([]byte, int(size))
	for offset, counter := 0, uint64(0); offset < len(output); counter++ {
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], counter)
		block := sha256.Sum256(append(base[:], raw[:]...))
		offset += copy(output[offset:], block[:])
	}
	return output, nil
}

func CloneSource(source map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(source))
	for path, data := range source {
		clone[path] = append([]byte(nil), data...)
	}
	return clone
}

// ApplySourceOperation returns the exact post-image and the changed payloads
// in the same order in which the operation's intent must consume their CIDs.
func (f *Fixture) ApplySourceOperation(source map[string][]byte, operation Operation, ordinal uint64) (map[string][]byte, [][]byte, error) {
	post := CloneSource(source)
	payload := func(index int, size uint64) ([]byte, error) { return f.Payload(operation.Name, ordinal, index, size) }
	switch operation.Kind {
	case KindDirectReplace:
		if _, exists := post[operation.SourcePath]; !exists {
			return nil, nil, fmt.Errorf("source %q does not exist", operation.SourcePath)
		}
		data, err := payload(0, operation.PayloadBytes)
		if err != nil {
			return nil, nil, err
		}
		post[operation.SourcePath] = data
		return post, [][]byte{data}, nil
	case KindDocumentEdit:
		old, exists := post[operation.SourcePath]
		if !exists {
			return nil, nil, fmt.Errorf("document source %q does not exist", operation.SourcePath)
		}
		edit, err := payload(0, operation.PayloadBytes)
		if err != nil {
			return nil, nil, err
		}
		data := append(append([]byte(nil), old...), edit...)
		post[operation.SourcePath] = data
		return post, [][]byte{data}, nil
	case KindDirectInsert:
		if _, exists := post[operation.DestinationPath]; exists {
			return nil, nil, fmt.Errorf("destination %q already exists", operation.DestinationPath)
		}
		data, err := payload(0, operation.PayloadBytes)
		if err != nil {
			return nil, nil, err
		}
		post[operation.DestinationPath] = data
		return post, [][]byte{data}, nil
	case KindDirectDelete:
		if _, exists := post[operation.SourcePath]; !exists {
			return nil, nil, fmt.Errorf("delete source %q does not exist", operation.SourcePath)
		}
		delete(post, operation.SourcePath)
		return post, nil, nil
	case KindDirectMove:
		data, exists := post[operation.SourcePath]
		if !exists {
			return nil, nil, fmt.Errorf("move source %q does not exist", operation.SourcePath)
		}
		if _, exists := post[operation.DestinationPath]; exists {
			return nil, nil, fmt.Errorf("move destination %q already exists", operation.DestinationPath)
		}
		delete(post, operation.SourcePath)
		post[operation.DestinationPath] = data
		return post, nil, nil
	case KindListAppend:
		old, exists := post[operation.SourcePath]
		if !exists {
			return nil, nil, fmt.Errorf("list source %q does not exist", operation.SourcePath)
		}
		data, err := payload(0, operation.PayloadBytes)
		if err != nil {
			return nil, nil, err
		}
		post[operation.SourcePath] = append(append([]byte(nil), old...), data...)
		return post, [][]byte{data}, nil
	case KindListReplace:
		old, exists := post[operation.SourcePath]
		list, listExists := f.List(operation.SourcePath)
		if !exists || !listExists || operation.ListIndex == nil {
			return nil, nil, fmt.Errorf("list replacement source is unavailable")
		}
		data, err := payload(0, operation.PayloadBytes)
		if err != nil {
			return nil, nil, err
		}
		offset := *operation.ListIndex * list.ChunkSize
		if offset+uint64(len(data)) > uint64(len(old)) {
			return nil, nil, fmt.Errorf("list replacement exceeds current source bytes")
		}
		old = append([]byte(nil), old...)
		copy(old[offset:offset+uint64(len(data))], data)
		post[operation.SourcePath] = old
		return post, [][]byte{data}, nil
	case KindBatchInsert:
		values := make([][]byte, len(operation.Batch))
		for index, target := range operation.Batch {
			if _, exists := post[target.Path]; exists {
				return nil, nil, fmt.Errorf("batch destination %q already exists", target.Path)
			}
			data, err := payload(index, target.PayloadBytes)
			if err != nil {
				return nil, nil, err
			}
			post[target.Path], values[index] = data, data
		}
		return post, values, nil
	default:
		return nil, nil, fmt.Errorf("unsupported RQ2 source operation kind %q", operation.Kind)
	}
}

// ValidateInitialView proves that the fixture's declared source bytes map to
// the campaign's exact initial accepted root for the selected backend.
func (f *Fixture) ValidateInitialView(view mutation.UpdateView, backend string) error {
	expected, err := f.Root(backend)
	if err != nil {
		return err
	}
	if !view.BaseRoot.Equals(expected) {
		return fmt.Errorf("update-view root %s does not equal fixture %s root %s", view.BaseRoot, backend, expected)
	}
	return f.ValidateViewAgainstSource(view, backend, f.InitialSource())
}
