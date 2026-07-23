package rq2fixture

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	cid "github.com/ipfs/go-cid"
)

const SourceSchemaVersion = "malt-rq2-source-definition/v1"

//go:embed source-definition.schema.json
var SourceSchemaJSON []byte

type SourceDirectFile struct {
	Path       string `json:"path"`
	Coordinate string `json:"coordinate"`
	Bytes      []byte `json:"bytes"`
}

type SourceListChunk struct {
	Index uint64 `json:"index"`
	Bytes []byte `json:"bytes"`
}

type SourceListFile struct {
	Path       string            `json:"path"`
	Coordinate string            `json:"coordinate"`
	ChunkSize  uint64            `json:"chunk_size"`
	TotalSize  uint64            `json:"total_size"`
	Chunks     []SourceListChunk `json:"chunks"`
}

// SourceDefinition is the human-authored input to the production fixture
// builder. It contains source bytes and operation targets, but never roots or
// CIDs: those are independently computed for KZG and IPA by the builder.
type SourceDefinition struct {
	SchemaVersion      string             `json:"schema_version"`
	FixtureID          string             `json:"fixture_id"`
	MutationSeedSHA256 string             `json:"mutation_seed_sha256"`
	DirectFiles        []SourceDirectFile `json:"direct_files"`
	ListFiles          []SourceListFile   `json:"list_files"`
	Operations         []Operation        `json:"operations"`
}

func DecodeSource(data []byte) (*SourceDefinition, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("decode RQ2 source definition: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var source SourceDefinition
	if err := decoder.Decode(&source); err != nil {
		return nil, fmt.Errorf("decode RQ2 source definition: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("RQ2 source definition must contain exactly one JSON object")
	}
	if err := source.Validate(); err != nil {
		return nil, err
	}
	return &source, nil
}

func (s *SourceDefinition) Validate() error {
	if s == nil || s.SchemaVersion != SourceSchemaVersion || !identityPattern.MatchString(s.FixtureID) || !canonicalSHA256(s.MutationSeedSHA256) {
		return fmt.Errorf("RQ2 source definition identity or schema is invalid")
	}
	if len(s.DirectFiles)+len(s.ListFiles) == 0 || len(s.DirectFiles)+len(s.ListFiles) > maxFiles || len(s.Operations) == 0 || len(s.Operations) > maxOperations {
		return fmt.Errorf("RQ2 source definition file or operation count is outside evaluator bounds")
	}
	paths := make(map[string]string, len(s.DirectFiles)+len(s.ListFiles))
	var decodedBytes uint64
	for _, file := range s.DirectFiles {
		if err := validatePathCoordinate(file.Path, file.Coordinate); err != nil {
			return fmt.Errorf("direct file: %w", err)
		}
		if _, duplicate := paths[file.Path]; duplicate {
			return fmt.Errorf("RQ2 source definition repeats path %q", file.Path)
		}
		paths[file.Path] = "direct"
		decodedBytes += uint64(len(file.Bytes))
	}
	chunkCount := 0
	for _, file := range s.ListFiles {
		if err := validatePathCoordinate(file.Path, file.Coordinate); err != nil {
			return fmt.Errorf("list file: %w", err)
		}
		if _, duplicate := paths[file.Path]; duplicate || file.ChunkSize == 0 || file.TotalSize == 0 || len(file.Chunks) == 0 {
			return fmt.Errorf("list file %q identity or descriptor is invalid", file.Path)
		}
		var total uint64
		for index, chunk := range file.Chunks {
			if chunk.Index != uint64(index) || len(chunk.Bytes) == 0 || uint64(len(chunk.Bytes)) > file.ChunkSize || index != len(file.Chunks)-1 && uint64(len(chunk.Bytes)) != file.ChunkSize {
				return fmt.Errorf("list file %q chunk %d is not a bounded contiguous chunk", file.Path, index)
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
	if decodedBytes == 0 || decodedBytes > maxDecodedBytes || chunkCount > maxChunks {
		return fmt.Errorf("RQ2 source definition decoded bytes or chunks exceed evaluator bounds")
	}
	operations := make(map[string]struct{}, len(s.Operations))
	for _, operation := range s.Operations {
		if !identityPattern.MatchString(operation.Name) {
			return fmt.Errorf("RQ2 source definition operation name %q is invalid", operation.Name)
		}
		if _, duplicate := operations[operation.Name]; duplicate {
			return fmt.Errorf("RQ2 source definition repeats operation %q", operation.Name)
		}
		operations[operation.Name] = struct{}{}
		if err := validateOperation(operation, paths); err != nil {
			return fmt.Errorf("operation %q: %w", operation.Name, err)
		}
		if operation.Kind == KindListAppend || operation.Kind == KindListReplace {
			list, ok := s.list(operation.SourcePath)
			if !ok || operation.Kind == KindListAppend && operation.PayloadBytes != list.ChunkSize {
				return fmt.Errorf("operation %q does not match its fixed-list source", operation.Name)
			}
			if operation.Kind == KindListReplace && (operation.ListIndex == nil || *operation.ListIndex >= uint64(len(list.Chunks)) || operation.PayloadBytes != uint64(len(list.Chunks[*operation.ListIndex].Bytes))) {
				return fmt.Errorf("operation %q replacement does not match its declared chunk", operation.Name)
			}
		}
	}
	return nil
}

func (s *SourceDefinition) list(path string) (SourceListFile, bool) {
	for _, file := range s.ListFiles {
		if file.Path == path {
			return file, true
		}
	}
	return SourceListFile{}, false
}

func (s *SourceDefinition) Fixture(roots []RootBinding) (*Fixture, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	fixture := &Fixture{
		SchemaVersion: SchemaVersion, FixtureID: s.FixtureID, MutationSeedSHA256: s.MutationSeedSHA256,
		InitialRoots: append([]RootBinding(nil), roots...), Operations: append([]Operation(nil), s.Operations...),
		DirectFiles: make([]DirectFile, len(s.DirectFiles)), ListFiles: make([]ListFile, len(s.ListFiles)),
	}
	for index, file := range s.DirectFiles {
		key, err := rawCID(file.Bytes)
		if err != nil {
			return nil, err
		}
		fixture.DirectFiles[index] = DirectFile{Path: file.Path, Coordinate: file.Coordinate, Bytes: append([]byte(nil), file.Bytes...), CID: key.String()}
	}
	for index, file := range s.ListFiles {
		result := ListFile{Path: file.Path, Coordinate: file.Coordinate, ChunkSize: file.ChunkSize, TotalSize: file.TotalSize, Chunks: make([]ListChunk, len(file.Chunks))}
		for chunkIndex, chunk := range file.Chunks {
			key, err := rawCID(chunk.Bytes)
			if err != nil {
				return nil, err
			}
			result.Chunks[chunkIndex] = ListChunk{Index: chunk.Index, Bytes: append([]byte(nil), chunk.Bytes...), CID: key.String()}
		}
		fixture.ListFiles[index] = result
	}
	if err := fixture.Validate(); err != nil {
		return nil, err
	}
	return fixture, nil
}

func rawCID(data []byte) (cid.Cid, error) {
	return clientcas.CIDForBlock(clientcas.Block{Codec: cid.Raw, Data: data})
}
