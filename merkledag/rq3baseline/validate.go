package rq3baseline

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

const (
	maxFiles           = 10_000
	maxCommits         = 4_096
	maxMutations       = 65_536
	maxPayloadBytes    = 32 << 20
	maxChunkSizeBytes  = 16 << 20
	maxProjectedChunks = 250_000
	maxPathBytes       = 4_096
	maxPathSegments    = 256
	maxCommitIDBytes   = 256
)

// UnsupportedError identifies a request that the current implementation
// cannot measure without inventing behavior.
type UnsupportedError struct {
	Gap     string
	Message string
}

func (e *UnsupportedError) Error() string { return e.Message }

type preparedRun struct {
	spec     RunSpec
	snapshot []preparedFile
	commits  []preparedCommit
	digest   string
}

type preparedFile struct {
	path string
	data []byte
	mode uint32
	hash string
}

type preparedCommit struct {
	id        string
	mutations []preparedMutation
}

type preparedMutation struct {
	mutation Mutation
	data     []byte
}

type logicalFile struct {
	data []byte
	mode uint32
	hash string
}

// ValidateAndAccountSource validates the entire frozen workload without
// creating an Editor or CAS state, and returns system-neutral per-commit
// source accounting. In particular, it does not execute the UnixFS baseline
// and is safe to use before another adapter's measured path.
func ValidateAndAccountSource(spec RunSpec) ([]SourceCommitAccounting, error) {
	prepared, err := prepare(spec)
	if err != nil {
		return nil, err
	}
	return accountPreparedSource(prepared), nil
}

func accountPreparedSource(prepared *preparedRun) []SourceCommitAccounting {
	result := make([]SourceCommitAccounting, 0, len(prepared.commits)+1)
	var snapshotBytes int64
	for _, file := range prepared.snapshot {
		snapshotBytes += int64(len(file.data))
	}
	result = append(result, SourceCommitAccounting{
		CommitID: prepared.spec.Snapshot.CommitID, LogicalObjectsChanged: len(prepared.snapshot),
		LogicalBindingsChanged: len(prepared.snapshot), AdapterPayloadInputBytes: snapshotBytes,
	})
	for _, commit := range prepared.commits {
		accounting := SourceCommitAccounting{CommitID: commit.id, LogicalObjectsChanged: len(commit.mutations)}
		for _, mutation := range commit.mutations {
			switch mutation.mutation.Kind {
			case MutationRename, MutationMove:
				accounting.LogicalBindingsChanged += 2
			default:
				accounting.LogicalBindingsChanged++
			}
			switch mutation.mutation.Kind {
			case MutationInsert, MutationReplace, MutationAppend:
				accounting.AdapterPayloadInputBytes += int64(len(mutation.data))
			}
		}
		result = append(result, accounting)
	}
	return result
}

func prepare(spec RunSpec) (*preparedRun, error) {
	if err := validateLayout(spec.System, spec.Layout); err != nil {
		return nil, err
	}
	if err := validateCommitID("snapshot commit_id", spec.Snapshot.CommitID); err != nil {
		return nil, err
	}
	if spec.Snapshot.Files == nil {
		return nil, fmt.Errorf("snapshot files must be an explicit array")
	}
	if len(spec.Snapshot.Files) == 0 {
		return nil, &UnsupportedError{Gap: "empty_snapshot", Message: "empty snapshot is unsupported because the current Editor cannot materialize or resume an empty directory root"}
	}
	if len(spec.Snapshot.Files) > maxFiles {
		return nil, fmt.Errorf("snapshot has %d files; maximum is %d", len(spec.Snapshot.Files), maxFiles)
	}
	if spec.Commits == nil {
		return nil, fmt.Errorf("commits must be an explicit array")
	}
	if len(spec.Commits) > maxCommits {
		return nil, fmt.Errorf("run has %d commits; maximum is %d", len(spec.Commits), maxCommits)
	}

	state := make(map[string]logicalFile, len(spec.Snapshot.Files))
	preparedSnapshot := make([]preparedFile, 0, len(spec.Snapshot.Files))
	totalPayload := 0
	totalProjectedChunks := 0
	previousPath := ""
	for i, file := range spec.Snapshot.Files {
		if err := validateFileKind(fmt.Sprintf("snapshot files[%d].file_kind", i), file.FileKind); err != nil {
			return nil, err
		}
		if err := validateCanonicalPath(fmt.Sprintf("snapshot files[%d].path", i), file.Path); err != nil {
			return nil, err
		}
		if i > 0 && file.Path <= previousPath {
			return nil, fmt.Errorf("snapshot files must be strictly sorted by path; %q follows %q", file.Path, previousPath)
		}
		previousPath = file.Path
		mode, err := validateMode(fmt.Sprintf("snapshot files[%d].mode", i), file.Mode)
		if err != nil {
			return nil, err
		}
		data, err := decodePayload(fmt.Sprintf("snapshot files[%d]", i), file.PayloadBase64, file.PayloadSHA256)
		if err != nil {
			return nil, err
		}
		totalPayload += len(data)
		if totalPayload > maxPayloadBytes {
			return nil, fmt.Errorf("decoded payload bytes exceed %d", maxPayloadBytes)
		}
		totalProjectedChunks += projectedChunks(len(data), spec.Layout.Chunking.SizeBytes)
		if totalProjectedChunks > maxProjectedChunks {
			return nil, fmt.Errorf("projected payload chunks exceed %d", maxProjectedChunks)
		}
		if conflict := conflictingPath(state, file.Path, ""); conflict != "" {
			return nil, fmt.Errorf("snapshot path %q conflicts with file path %q", file.Path, conflict)
		}
		state[file.Path] = logicalFile{data: cloneBytes(data), mode: mode, hash: file.PayloadSHA256}
		preparedSnapshot = append(preparedSnapshot, preparedFile{path: file.Path, data: data, mode: mode, hash: file.PayloadSHA256})
	}

	seenCommits := map[string]struct{}{spec.Snapshot.CommitID: {}}
	preparedCommits := make([]preparedCommit, 0, len(spec.Commits))
	mutationCount := 0
	for commitIndex, commit := range spec.Commits {
		if err := validateCommitID(fmt.Sprintf("commits[%d].commit_id", commitIndex), commit.CommitID); err != nil {
			return nil, err
		}
		if _, exists := seenCommits[commit.CommitID]; exists {
			return nil, fmt.Errorf("duplicate commit_id %q", commit.CommitID)
		}
		seenCommits[commit.CommitID] = struct{}{}
		if commit.Mutations == nil || len(commit.Mutations) == 0 {
			return nil, fmt.Errorf("commit %q must contain at least one mutation", commit.CommitID)
		}
		mutationCount += len(commit.Mutations)
		if mutationCount > maxMutations {
			return nil, fmt.Errorf("run has more than %d mutations", maxMutations)
		}
		prepared := preparedCommit{id: commit.CommitID, mutations: make([]preparedMutation, 0, len(commit.Mutations))}
		for mutationIndex, mutation := range commit.Mutations {
			decoded, addedPayload, err := validateAndApplyMutation(state, commit.CommitID, mutationIndex, mutation)
			if err != nil {
				return nil, err
			}
			totalPayload += addedPayload
			if totalPayload > maxPayloadBytes {
				return nil, fmt.Errorf("decoded payload bytes exceed %d", maxPayloadBytes)
			}
			if mutation.Kind == MutationInsert || mutation.Kind == MutationReplace || mutation.Kind == MutationAppend {
				totalProjectedChunks += projectedChunks(len(decoded), spec.Layout.Chunking.SizeBytes)
				if totalProjectedChunks > maxProjectedChunks {
					return nil, fmt.Errorf("projected payload chunks exceed %d", maxProjectedChunks)
				}
			}
			prepared.mutations = append(prepared.mutations, preparedMutation{mutation: mutation, data: decoded})
		}
		preparedCommits = append(preparedCommits, prepared)
	}

	encoded, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("encode canonical workload: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return &preparedRun{
		spec:     spec,
		snapshot: preparedSnapshot,
		commits:  preparedCommits,
		digest:   hex.EncodeToString(digest[:]),
	}, nil
}

func validateLayout(system string, layout LayoutSpec) error {
	if layout.Model != "unixfs" {
		return fmt.Errorf("layout model must be %q", "unixfs")
	}
	if layout.FileLayout != "balanced" && layout.FileLayout != "trickle" {
		return fmt.Errorf("unsupported file_layout %q", layout.FileLayout)
	}
	if layout.Chunking.Algorithm != "fixed" {
		return fmt.Errorf("chunking algorithm must be %q", "fixed")
	}
	if layout.Chunking.SizeBytes <= 0 || layout.Chunking.SizeBytes > maxChunkSizeBytes {
		return fmt.Errorf("chunking size_bytes must be in [1,%d]", maxChunkSizeBytes)
	}
	if layout.RawFileLeaf == nil {
		return fmt.Errorf("raw_file_leaf must be explicit")
	}
	switch system {
	case SystemMerkleDAGUnixFS:
		if layout.DirectoryLayout != "basic" {
			return fmt.Errorf("system %q requires directory_layout %q", system, "basic")
		}
		if layout.HAMTFanout != 0 {
			return fmt.Errorf("system %q requires hamt_fanout=0", system)
		}
	case SystemHAMTUnixFS:
		if layout.DirectoryLayout != "hamt" {
			return fmt.Errorf("system %q requires directory_layout %q", system, "hamt")
		}
		if layout.HAMTFanout < 8 || layout.HAMTFanout > 65_536 || layout.HAMTFanout%8 != 0 || layout.HAMTFanout&(layout.HAMTFanout-1) != 0 {
			return fmt.Errorf("hamt_fanout must be a power of two and multiple of 8 in [8,65536]")
		}
	default:
		return fmt.Errorf("unsupported system %q", system)
	}
	return nil
}

func validateAndApplyMutation(state map[string]logicalFile, commitID string, index int, mutation Mutation) ([]byte, int, error) {
	label := fmt.Sprintf("commit %q mutation[%d]", commitID, index)
	if err := validateFileKind(label+".file_kind", mutation.FileKind); err != nil {
		return nil, 0, err
	}
	if err := validateCanonicalPath(label+".path", mutation.Path); err != nil {
		return nil, 0, err
	}
	old, exists := state[mutation.Path]
	switch mutation.Kind {
	case MutationInsert:
		if mutation.Destination != "" || mutation.ExpectedOldSHA256 != "" || mutation.ExpectedOldMode != nil {
			return nil, 0, fmt.Errorf("%s insert has fields that are not applicable", label)
		}
		mode, err := validateMode(label+".mode", mutation.Mode)
		if err != nil {
			return nil, 0, err
		}
		if exists {
			return nil, 0, fmt.Errorf("%s insert target already exists", label)
		}
		if conflict := conflictingPath(state, mutation.Path, ""); conflict != "" {
			return nil, 0, fmt.Errorf("%s insert path conflicts with file %q", label, conflict)
		}
		data, err := decodePayload(label, mutation.PayloadBase64, mutation.PayloadSHA256)
		if err != nil {
			return nil, 0, err
		}
		state[mutation.Path] = logicalFile{data: cloneBytes(data), mode: mode, hash: mutation.PayloadSHA256}
		return data, len(data), nil

	case MutationReplace, MutationAppend:
		if mutation.Destination != "" {
			return nil, 0, fmt.Errorf("%s %s has a destination", label, mutation.Kind)
		}
		mode, err := validateMode(label+".mode", mutation.Mode)
		if err != nil {
			return nil, 0, err
		}
		expectedMode, err := validateMode(label+".expected_old_mode", mutation.ExpectedOldMode)
		if err != nil {
			return nil, 0, err
		}
		if err := requireOldFile(state, mutation.Path, old, exists, mutation.ExpectedOldSHA256, expectedMode, label); err != nil {
			return nil, 0, err
		}
		data, err := decodePayload(label, mutation.PayloadBase64, mutation.PayloadSHA256)
		if err != nil {
			return nil, 0, err
		}
		if mutation.Kind == MutationAppend {
			if len(data) <= len(old.data) || !bytes.Equal(data[:len(old.data)], old.data) {
				return nil, 0, fmt.Errorf("%s append payload must strictly extend the old payload", label)
			}
		}
		state[mutation.Path] = logicalFile{data: cloneBytes(data), mode: mode, hash: mutation.PayloadSHA256}
		return data, len(data), nil

	case MutationModeChange:
		if mutation.Destination != "" || mutation.PayloadBase64 != "" || mutation.PayloadSHA256 != "" {
			return nil, 0, fmt.Errorf("%s mode-change has fields that are not applicable", label)
		}
		mode, err := validateMode(label+".mode", mutation.Mode)
		if err != nil {
			return nil, 0, err
		}
		expectedMode, err := validateMode(label+".expected_old_mode", mutation.ExpectedOldMode)
		if err != nil {
			return nil, 0, err
		}
		if err := requireOldFile(state, mutation.Path, old, exists, mutation.ExpectedOldSHA256, expectedMode, label); err != nil {
			return nil, 0, err
		}
		if mode == expectedMode {
			return nil, 0, fmt.Errorf("%s mode-change must change the mode", label)
		}
		state[mutation.Path] = logicalFile{data: cloneBytes(old.data), mode: mode, hash: old.hash}
		return nil, 0, nil

	case MutationDelete:
		if mutation.Destination != "" || mutation.PayloadBase64 != "" || mutation.PayloadSHA256 != "" || mutation.Mode != nil {
			return nil, 0, fmt.Errorf("%s delete has fields that are not applicable", label)
		}
		expectedMode, err := validateMode(label+".expected_old_mode", mutation.ExpectedOldMode)
		if err != nil {
			return nil, 0, err
		}
		if err := requireOldFile(state, mutation.Path, old, exists, mutation.ExpectedOldSHA256, expectedMode, label); err != nil {
			return nil, 0, err
		}
		delete(state, mutation.Path)
		return nil, 0, nil

	case MutationRename, MutationMove:
		if mutation.PayloadBase64 != "" || mutation.PayloadSHA256 != "" {
			return nil, 0, fmt.Errorf("%s %s has payload fields", label, mutation.Kind)
		}
		mode, err := validateMode(label+".mode", mutation.Mode)
		if err != nil {
			return nil, 0, err
		}
		expectedMode, err := validateMode(label+".expected_old_mode", mutation.ExpectedOldMode)
		if err != nil {
			return nil, 0, err
		}
		if mode != expectedMode {
			return nil, 0, fmt.Errorf("%s %s cannot also change file mode", label, mutation.Kind)
		}
		if err := requireOldFile(state, mutation.Path, old, exists, mutation.ExpectedOldSHA256, expectedMode, label); err != nil {
			return nil, 0, err
		}
		if err := validateCanonicalPath(label+".destination", mutation.Destination); err != nil {
			return nil, 0, err
		}
		if mutation.Destination == mutation.Path {
			return nil, 0, fmt.Errorf("%s destination equals source", label)
		}
		if mutation.Kind == MutationRename && path.Dir(mutation.Path) != path.Dir(mutation.Destination) {
			return nil, 0, fmt.Errorf("%s rename must remain in the same parent directory; use move", label)
		}
		if mutation.Kind == MutationMove && path.Dir(mutation.Path) == path.Dir(mutation.Destination) {
			return nil, 0, fmt.Errorf("%s move must change parent directory; use rename", label)
		}
		if _, destinationExists := state[mutation.Destination]; destinationExists {
			return nil, 0, fmt.Errorf("%s destination already exists", label)
		}
		if conflict := conflictingPath(state, mutation.Destination, mutation.Path); conflict != "" {
			return nil, 0, fmt.Errorf("%s destination conflicts with file %q", label, conflict)
		}
		delete(state, mutation.Path)
		state[mutation.Destination] = logicalFile{data: cloneBytes(old.data), mode: old.mode, hash: old.hash}
		return nil, 0, nil

	default:
		return nil, 0, fmt.Errorf("%s has unsupported kind %q", label, mutation.Kind)
	}
}

func requireOldFile(state map[string]logicalFile, filePath string, old logicalFile, exists bool, digest string, mode uint32, label string) error {
	if !exists {
		for existing := range state {
			if strings.HasPrefix(existing, filePath+"/") {
				return &UnsupportedError{Gap: "directory_subtree_mutation", Message: fmt.Sprintf("%s selects directory or subtree %q", label, filePath)}
			}
		}
		return fmt.Errorf("%s source does not exist", label)
	}
	if err := validateDigest(label+".expected_old_sha256", digest); err != nil {
		return err
	}
	if old.hash != digest {
		return fmt.Errorf("%s old payload digest mismatch", label)
	}
	if old.mode != mode {
		return fmt.Errorf("%s old mode mismatch: got %04o, expected %04o", label, mode, old.mode)
	}
	return nil
}

func validateCanonicalPath(label, raw string) error {
	if raw == "" || len(raw) > maxPathBytes || !utf8.ValidString(raw) || strings.ContainsRune(raw, '\x00') || strings.ContainsRune(raw, '\\') {
		return fmt.Errorf("%s is not a valid UTF-8 relative path", label)
	}
	if strings.Count(raw, "/")+1 > maxPathSegments {
		return fmt.Errorf("%s has more than %d path segments", label, maxPathSegments)
	}
	clean := path.Clean(raw)
	if raw != clean || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return fmt.Errorf("%s must be a canonical relative path", label)
	}
	return nil
}

func validateMode(label string, mode *uint32) (uint32, error) {
	if mode == nil {
		return 0, fmt.Errorf("%s must be explicit", label)
	}
	if *mode == 0 || *mode > 0o777 {
		return 0, fmt.Errorf("%s must contain only non-zero Unix permission bits", label)
	}
	return *mode, nil
}

func validateFileKind(label, kind string) error {
	if kind == "" {
		return fmt.Errorf("%s must be explicit", label)
	}
	if kind != FileKindRegular {
		return &UnsupportedError{Gap: "symlink_and_special_file_mutation", Message: fmt.Sprintf("%s %q is unsupported; only regular files can use the current Editor primitive", label, kind)}
	}
	return nil
}

func validateCommitID(label, id string) error {
	if strings.TrimSpace(id) != id || id == "" || len(id) > maxCommitIDBytes || !utf8.ValidString(id) {
		return fmt.Errorf("%s must be a non-empty bounded canonical string", label)
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}

func decodePayload(label, encoded, digest string) ([]byte, error) {
	if err := validateDigest(label+".payload_sha256", digest); err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(data) != encoded {
		return nil, fmt.Errorf("%s.payload_base64 is not canonical standard base64", label)
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != digest {
		return nil, fmt.Errorf("%s payload SHA-256 mismatch", label)
	}
	return data, nil
}

func validateDigest(label, digest string) error {
	if len(digest) != sha256.Size*2 || strings.ToLower(digest) != digest {
		return fmt.Errorf("%s must be a lowercase SHA-256 hex digest", label)
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("%s must be a lowercase SHA-256 hex digest", label)
	}
	return nil
}

func conflictingPath(state map[string]logicalFile, candidate, ignored string) string {
	for existing := range state {
		if existing == ignored {
			continue
		}
		if strings.HasPrefix(candidate, existing+"/") || strings.HasPrefix(existing, candidate+"/") {
			return existing
		}
	}
	return ""
}

func cloneBytes(value []byte) []byte { return append([]byte(nil), value...) }

func projectedChunks(payloadBytes, chunkSize int) int {
	if payloadBytes == 0 {
		return 1
	}
	return (payloadBytes + chunkSize - 1) / chunkSize
}
