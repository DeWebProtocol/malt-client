package unixfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"slices"

	malt "github.com/dewebprotocol/malt"
	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/protocol"
	clientverifier "github.com/dewebprotocol/malt/sdk/verifier"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

var (
	ErrNotFound     = errors.New("unixfs path not found")
	ErrNotDirectory = errors.New("unixfs path is not a directory")
	ErrNotFile      = errors.New("unixfs path is not a file")
)

// Remote is the minimal untrusted graph execution transport consumed by the
// verified UnixFS facade. Implementations perform I/O only; they do not decide
// whether a root, target, proof, or payload is trusted.
type Remote interface {
	Resolve(context.Context, protocol.ResolveRequest) (*protocol.ResolveResult, error)
	Read(context.Context, protocol.ReadRequest) (*protocol.ReadResult, error)
}

// LocalVerifier verifies gateway results against independently constructed,
// caller-selected requests.
type LocalVerifier interface {
	VerifyResolve(context.Context, protocol.ResolveVerification) error
	VerifyRead(context.Context, protocol.ReadVerification) error
}

// BlockStore is the immutable payload capability needed by the writer. Get and
// Put implementations must bind bytes to their returned/requested CID.
type BlockStore interface {
	BlockGetter
	StagedBlockStore
}

// Resolution records the locally verified path derivation. Request contains
// the caller-selected trusted root and UnixFS segments; Result is untrusted
// gateway data that has passed local verification.
type Resolution struct {
	Request protocol.ResolveRequest `json:"request"`
	Result  protocol.ResolveResult  `json:"result"`
	Target  cid.Cid                 `json:"target"`
}

// Stat is the verified UnixFS projection of one path.
type Stat struct {
	Kind           string               `json:"kind"`
	NodeRoot       cid.Cid              `json:"node_root"`
	Payload        cid.Cid              `json:"payload"`
	StorageKind    string               `json:"storage_kind"`
	Size           uint64               `json:"size,omitempty"`
	ChunkSize      uint64               `json:"chunk_size,omitempty"`
	Entries        []string             `json:"entries,omitempty"`
	Resolution     Resolution           `json:"resolution"`
	PayloadBinding *Resolution          `json:"payload_binding,omitempty"`
	MetadataRead   *protocol.ReadResult `json:"metadata_read,omitempty"`
}

// ReadResult contains only bytes that have been bound to locally verified
// MALT evidence and authenticated payload CIDs.
type ReadResult struct {
	Body       []byte               `json:"-"`
	Target     cid.Cid              `json:"target"`
	Offset     uint64               `json:"offset"`
	End        uint64               `json:"end"`
	TotalSize  uint64               `json:"total_size"`
	ChunkSize  uint64               `json:"chunk_size,omitempty"`
	Resolution *Resolution          `json:"resolution,omitempty"`
	Read       *protocol.ReadResult `json:"read,omitempty"`
}

// RemoveResult identifies an independently checked candidate root. Accepted
// is always false; root acceptance remains an explicit local policy action.
type RemoveResult struct {
	BaseRoot         cid.Cid `json:"base_root"`
	CandidateRoot    cid.Cid `json:"candidate_root"`
	Accepted         bool    `json:"accepted"`
	ImmutableObjects int     `json:"immutable_objects"`
	MALTObjects      int     `json:"malt_objects"`
	ArcCount         int     `json:"arc_count"`
}

// WriteResult identifies an independently checked UnixFS candidate root.
// Receiving this value never promotes CandidateRoot into local trusted-root
// policy; callers must explicitly publish or accept it.
type WriteResult struct {
	BaseRoot         cid.Cid `json:"base_root"`
	CandidateRoot    cid.Cid `json:"candidate_root"`
	Path             string  `json:"path,omitempty"`
	Kind             string  `json:"kind"`
	Size             uint64  `json:"size,omitempty"`
	Accepted         bool    `json:"accepted"`
	ImmutableObjects int     `json:"immutable_objects"`
	MALTObjects      int     `json:"malt_objects"`
	ArcCount         int     `json:"arc_count"`
}

// Reader is the transport-neutral, locally verified UnixFS read facade.
type Reader interface {
	Resolve(context.Context, cid.Cid, string) (*Resolution, error)
	Stat(context.Context, cid.Cid, string) (*Stat, error)
	ReadFile(context.Context, cid.Cid, string) (*ReadResult, error)
	ReadFileRange(context.Context, cid.Cid, string, uint64, uint64) (*ReadResult, error)
	ReadListPayloadRange(context.Context, cid.Cid, uint64, uint64) (*ReadResult, error)
}

// Writer extends Reader with immutable candidate-root materialization.
type Writer interface {
	Reader
	EmptyDirectory(context.Context) (*WriteResult, error)
	AddDirectory(context.Context, cid.Cid, string) (*WriteResult, error)
	AddFile(context.Context, cid.Cid, string, []byte) (*WriteResult, error)
	AddFileStream(context.Context, cid.Cid, string, io.Reader) (*WriteResult, error)
	AddFileSized(context.Context, cid.Cid, string, io.Reader, int64) (*WriteResult, error)
	RemovePath(context.Context, cid.Cid, string) (*RemoveResult, error)
}

type ReaderOptions struct {
	Remote   Remote
	Blocks   BlockGetter
	Verifier LocalVerifier
}

type WriterOptions struct {
	Remote    Remote
	Blocks    BlockStore
	Verifier  LocalVerifier
	Roots     StagedRootCreator
	Lists     FixedListPayloadWriter
	ChunkSize int
	TempDir   string
}

type verifiedReader struct {
	remote   Remote
	blocks   BlockGetter
	verifier LocalVerifier
}

type verifiedWriter struct {
	*verifiedReader
	store     BlockStore
	roots     StagedRootCreator
	lists     FixedListPayloadWriter
	chunkSize int
	tempDir   string
}

// NewReader constructs a facade that verifies every resolve/read result
// locally and validates every fetched payload against its authenticated CID.
func NewReader(opts ReaderOptions) (Reader, error) {
	if opts.Remote == nil {
		return nil, fmt.Errorf("unixfs remote is nil")
	}
	if opts.Blocks == nil {
		return nil, fmt.Errorf("unixfs block getter is nil")
	}
	verifier := opts.Verifier
	if verifier == nil {
		var err error
		verifier, err = clientverifier.NewDefault()
		if err != nil {
			return nil, fmt.Errorf("initialize local MALT verifier: %w", err)
		}
	}
	return &verifiedReader{remote: opts.Remote, blocks: opts.Blocks, verifier: verifier}, nil
}

// NewWriter constructs a verified reader plus the narrowly scoped immutable
// block/root capabilities required to materialize write candidates.
func NewWriter(opts WriterOptions) (Writer, error) {
	reader, err := NewReader(ReaderOptions{Remote: opts.Remote, Blocks: opts.Blocks, Verifier: opts.Verifier})
	if err != nil {
		return nil, err
	}
	if opts.Blocks == nil {
		return nil, fmt.Errorf("unixfs block store is nil")
	}
	if opts.Roots == nil {
		return nil, fmt.Errorf("unixfs root creator is nil")
	}
	lists := opts.Lists
	if lists == nil {
		lists, _ = opts.Roots.(FixedListPayloadWriter)
	}
	if lists == nil {
		return nil, fmt.Errorf("unixfs fixed-list payload writer is nil")
	}
	chunkSize := opts.ChunkSize
	if chunkSize == 0 {
		chunkSize = unixfsmodel.DefaultChunkSize
	}
	if chunkSize < 0 {
		return nil, fmt.Errorf("unixfs chunk size must be positive")
	}
	return &verifiedWriter{
		verifiedReader: reader.(*verifiedReader), store: opts.Blocks,
		roots: opts.Roots, lists: lists, chunkSize: chunkSize, tempDir: opts.TempDir,
	}, nil
}

func (r *verifiedReader) Resolve(ctx context.Context, trustedRoot cid.Cid, rawPath string) (*Resolution, error) {
	segments, err := unixfsmodel.ParsePath(rawPath)
	if err != nil {
		return nil, err
	}
	return r.resolveSegments(ctx, trustedRoot, segments)
}

func (r *verifiedReader) resolveSegments(ctx context.Context, trustedRoot cid.Cid, segments []string) (*Resolution, error) {
	request, err := protocol.NewResolveRequest(malt.ResolveRequest{Root: trustedRoot, Segments: append([]string(nil), segments...)})
	if err != nil {
		return nil, err
	}
	result, err := r.remote.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("gateway returned a nil resolve result")
	}
	if err := r.verifier.VerifyResolve(ctx, protocol.ResolveVerification{Request: request, Result: *result}); err != nil {
		return nil, fmt.Errorf("verify UnixFS resolve locally: %w", err)
	}
	target, err := cid.Parse(result.Target)
	if err != nil {
		return nil, fmt.Errorf("decode verified resolve target: %w", err)
	}
	return &Resolution{Request: request, Result: *result, Target: target}, nil
}

func (r *verifiedReader) Stat(ctx context.Context, trustedRoot cid.Cid, rawPath string) (*Stat, error) {
	resolution, err := r.Resolve(ctx, trustedRoot, rawPath)
	if err != nil {
		return nil, err
	}
	stat := &Stat{NodeRoot: resolution.Target, Payload: resolution.Target, StorageKind: unixfsmodel.StorageKindFromCID(resolution.Target), Resolution: *resolution}
	switch maltcid.SemanticKindOf(resolution.Target) {
	case maltcid.SemanticKindMap:
		segments := append([]string(nil), resolution.Request.Segments...)
		segments = append(segments, "@payload")
		payloadBinding, err := r.resolveSegments(ctx, trustedRoot, segments)
		if err != nil {
			return nil, fmt.Errorf("resolve directory manifest: %w", err)
		}
		manifest, err := r.getBoundBlock(ctx, payloadBinding.Target)
		if err != nil {
			return nil, fmt.Errorf("fetch directory manifest: %w", err)
		}
		entries, err := unixfsmodel.ParseDirectoryManifest(manifest)
		if err != nil {
			return nil, fmt.Errorf("parse authenticated directory manifest: %w", err)
		}
		stat.Kind = StagedKindDirectory
		stat.Payload = payloadBinding.Target
		stat.StorageKind = "map"
		stat.Entries = entries
		stat.PayloadBinding = payloadBinding
		return stat, nil
	case maltcid.SemanticKindList:
		metadata, totalSize, chunkSize, err := r.readListMetadata(ctx, resolution.Target)
		if err != nil {
			return nil, err
		}
		stat.Kind = StagedKindFile
		stat.StorageKind = "list"
		stat.Size = totalSize
		stat.ChunkSize = chunkSize
		stat.MetadataRead = metadata
		return stat, nil
	case maltcid.SemanticKindUnknown:
		body, err := r.getBoundBlock(ctx, resolution.Target)
		if err != nil {
			return nil, fmt.Errorf("fetch raw file payload: %w", err)
		}
		stat.Kind = StagedKindFile
		stat.StorageKind = "raw"
		stat.Size = uint64(len(body))
		return stat, nil
	default:
		return nil, fmt.Errorf("unsupported UnixFS target kind for %s", resolution.Target)
	}
}

func (r *verifiedReader) ReadFile(ctx context.Context, trustedRoot cid.Cid, rawPath string) (*ReadResult, error) {
	resolution, err := r.Resolve(ctx, trustedRoot, rawPath)
	if err != nil {
		return nil, err
	}
	return r.readResolvedFile(ctx, resolution, 0, nil)
}

func (r *verifiedReader) ReadFileRange(ctx context.Context, trustedRoot cid.Cid, rawPath string, offset, length uint64) (*ReadResult, error) {
	resolution, err := r.Resolve(ctx, trustedRoot, rawPath)
	if err != nil {
		return nil, err
	}
	return r.readResolvedFile(ctx, resolution, offset, &length)
}

func (r *verifiedReader) readResolvedFile(ctx context.Context, resolution *Resolution, offset uint64, length *uint64) (*ReadResult, error) {
	if maltcid.SemanticKindOf(resolution.Target) == maltcid.SemanticKindMap {
		return nil, ErrNotFile
	}
	if maltcid.SemanticKindOf(resolution.Target) == maltcid.SemanticKindList {
		result, err := r.readListPayload(ctx, resolution.Target, offset, length)
		if err != nil {
			return nil, err
		}
		result.Resolution = resolution
		return result, nil
	}
	body, err := r.getBoundBlock(ctx, resolution.Target)
	if err != nil {
		return nil, fmt.Errorf("fetch raw file payload: %w", err)
	}
	total := uint64(len(body))
	end := total
	if length != nil {
		if offset >= total || *length == 0 {
			end = offset
			body = nil
		} else {
			end = saturatingAdd(offset, *length)
			if end > total {
				end = total
			}
			body = append([]byte(nil), body[offset:end]...)
		}
	} else if offset > 0 {
		if offset >= total {
			end = offset
			body = nil
		} else {
			body = append([]byte(nil), body[offset:]...)
		}
	}
	return &ReadResult{Body: body, Target: resolution.Target, Offset: offset, End: end, TotalSize: total, Resolution: resolution}, nil
}

func (r *verifiedReader) ReadListPayloadRange(ctx context.Context, trustedListRoot cid.Cid, offset, length uint64) (*ReadResult, error) {
	if maltcid.SemanticKindOf(trustedListRoot) != maltcid.SemanticKindList {
		return nil, fmt.Errorf("%w: target %s is not a MALT list", ErrNotFile, trustedListRoot)
	}
	return r.readListPayload(ctx, trustedListRoot, offset, &length)
}

func (r *verifiedReader) readListPayload(ctx context.Context, root cid.Cid, offset uint64, length *uint64) (*ReadResult, error) {
	metadata, totalSize, chunkSize, err := r.readListMetadata(ctx, root)
	if err != nil {
		return nil, err
	}
	if offset >= totalSize || (length != nil && *length == 0) {
		return &ReadResult{Target: root, Offset: offset, End: offset, TotalSize: totalSize, ChunkSize: chunkSize, Read: metadata}, nil
	}
	end := totalSize
	var read *protocol.ReadResult
	if length != nil {
		end = saturatingAdd(offset, *length)
		if end > totalSize {
			end = totalSize
		}
		read, err = r.verifiedListRead(ctx, root, offset, &end)
		if err != nil {
			return nil, err
		}
	} else {
		read, err = r.verifiedListRead(ctx, root, offset, nil)
		if err != nil {
			return nil, err
		}
	}
	readTotal, readChunk, err := listReadMetadata(*read)
	if err != nil {
		return nil, err
	}
	if readTotal != totalSize || readChunk != chunkSize {
		return nil, fmt.Errorf("authenticated list metadata changed between size and range reads")
	}
	body, err := r.assembleRange(ctx, *read, offset, end, chunkSize)
	if err != nil {
		return nil, err
	}
	return &ReadResult{Body: body, Target: root, Offset: offset, End: end, TotalSize: totalSize, ChunkSize: chunkSize, Read: read}, nil
}

func (r *verifiedReader) readListMetadata(ctx context.Context, root cid.Cid) (*protocol.ReadResult, uint64, uint64, error) {
	one := uint64(1)
	result, err := r.verifiedListRead(ctx, root, 0, &one)
	if err != nil {
		return nil, 0, 0, err
	}
	totalSize, chunkSize, err := listReadMetadata(*result)
	if err != nil {
		return nil, 0, 0, err
	}
	return result, totalSize, chunkSize, nil
}

func listReadMetadata(result protocol.ReadResult) (uint64, uint64, error) {
	if len(result.ProofList.Steps) != 1 {
		return 0, 0, fmt.Errorf("verified list metadata has %d proof steps", len(result.ProofList.Steps))
	}
	step := result.ProofList.Steps[0]
	if step.TotalSize == nil || step.ChunkSize == nil || *step.ChunkSize == 0 {
		return 0, 0, fmt.Errorf("verified list metadata is incomplete")
	}
	return *step.TotalSize, *step.ChunkSize, nil
}

func (r *verifiedReader) verifiedListRead(ctx context.Context, root cid.Cid, start uint64, end *uint64) (*protocol.ReadResult, error) {
	query, err := malt.ListRangeQuery(start, end)
	if err != nil {
		return nil, err
	}
	request, err := protocol.NewReadRequest(malt.ReadRequest{Root: root, Query: query})
	if err != nil {
		return nil, err
	}
	result, err := r.remote.Read(ctx, request)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("gateway returned a nil read result")
	}
	if err := r.verifier.VerifyRead(ctx, protocol.ReadVerification{Request: request, Result: *result}); err != nil {
		return nil, fmt.Errorf("verify UnixFS list read locally: %w", err)
	}
	if result.Target != root.String() {
		return nil, fmt.Errorf("verified list read target %s does not match resolved payload %s", result.Target, root)
	}
	return result, nil
}

func (r *verifiedReader) assembleRange(ctx context.Context, read protocol.ReadResult, start, end, chunkSize uint64) ([]byte, error) {
	assembled := make([]byte, 0)
	for i, raw := range read.RangeSegments {
		segment, err := cid.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("decode authenticated range segment %d: %w", i, err)
		}
		data, err := r.getBoundBlock(ctx, segment)
		if err != nil {
			return nil, fmt.Errorf("fetch authenticated range segment %d: %w", i, err)
		}
		assembled = append(assembled, data...)
	}
	offset := start % chunkSize
	length := end - start
	if uint64(len(assembled)) < offset+length {
		return nil, fmt.Errorf("authenticated range segments contain %d bytes, need %d", len(assembled), offset+length)
	}
	body := append([]byte(nil), assembled[offset:offset+length]...)
	if err := VerifyRangeBody(read.ProofList, body, start, end, func(key cid.Cid) ([]byte, error) {
		return r.getBoundBlock(ctx, key)
	}); err != nil {
		return nil, fmt.Errorf("bind list range body: %w", err)
	}
	return body, nil
}

func (r *verifiedReader) getBoundBlock(ctx context.Context, key cid.Cid) ([]byte, error) {
	data, err := r.blocks.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	computed, err := key.Prefix().Sum(data)
	if err != nil {
		return nil, fmt.Errorf("compute payload CID: %w", err)
	}
	if !computed.Equals(key) {
		return nil, fmt.Errorf("payload bytes do not match authenticated CID %s", key)
	}
	return data, nil
}

// EmptyDirectory materializes and verifies a new empty UnixFS directory. The
// returned root is a candidate until the caller explicitly accepts it.
func (w *verifiedWriter) EmptyDirectory(ctx context.Context) (*WriteResult, error) {
	current := NewStagedDirectory()
	current.Changed = true
	return w.materializeWrite(ctx, cid.Undef, "", StagedKindDirectory, 0, current)
}

// AddDirectory ensures that rawPath is a directory below trustedRoot. Existing
// files on the path are rejected instead of silently replaced.
func (w *verifiedWriter) AddDirectory(ctx context.Context, trustedRoot cid.Cid, rawPath string) (*WriteResult, error) {
	segments, err := unixfsmodel.ParsePath(rawPath)
	if err != nil {
		return nil, err
	}
	current, err := w.loadWritableTree(ctx, trustedRoot)
	if err != nil {
		return nil, err
	}
	if err := requireDirectoryPath(current, segments); err != nil {
		return nil, err
	}
	canonical := path.Join(segments...)
	EnsureStagedDirectory(current, canonical)
	return w.materializeWrite(ctx, trustedRoot, canonical, StagedKindDirectory, 0, current)
}

// AddFile writes a byte slice using the same bounded-memory materializer as
// AddFileSized.
func (w *verifiedWriter) AddFile(ctx context.Context, trustedRoot cid.Cid, rawPath string, data []byte) (*WriteResult, error) {
	return w.AddFileSized(ctx, trustedRoot, rawPath, bytes.NewReader(data), int64(len(data)))
}

// AddFileStream accepts a stream whose size is not known in advance. It spools
// to a private temporary file, so memory use stays bounded before the normal
// fixed-list streaming path applies backpressure through BlockStore.Put.
func (w *verifiedWriter) AddFileStream(ctx context.Context, trustedRoot cid.Cid, rawPath string, src io.Reader) (*WriteResult, error) {
	if src == nil {
		return nil, fmt.Errorf("unixfs file stream is nil")
	}
	staged, err := os.CreateTemp(w.tempDir, "malt-client-unixfs-*")
	if err != nil {
		return nil, fmt.Errorf("create UnixFS stream spool: %w", err)
	}
	name := staged.Name()
	defer os.Remove(name)
	defer staged.Close()
	size, err := io.Copy(staged, src)
	if err != nil {
		return nil, fmt.Errorf("spool UnixFS file stream: %w", err)
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind UnixFS file stream: %w", err)
	}
	return w.AddFileSized(ctx, trustedRoot, rawPath, staged, size)
}

// AddFileSized streams exactly size bytes into immutable CAS blocks and then
// materializes the changed directory ancestry. A short or overlong stream is
// rejected before a candidate root is returned.
func (w *verifiedWriter) AddFileSized(ctx context.Context, trustedRoot cid.Cid, rawPath string, src io.Reader, size int64) (*WriteResult, error) {
	if src == nil {
		return nil, fmt.Errorf("unixfs file stream is nil")
	}
	if size < 0 {
		return nil, fmt.Errorf("unixfs file size must not be negative")
	}
	if size == math.MaxInt64 {
		return nil, fmt.Errorf("unixfs file size exceeds supported stream limit")
	}
	segments, err := unixfsmodel.ParsePath(rawPath)
	if err != nil {
		return nil, err
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("unixfs file path is empty")
	}
	current, err := w.loadWritableTree(ctx, trustedRoot)
	if err != nil {
		return nil, err
	}
	if err := requireFilePath(current, segments); err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: src, N: size + 1}
	payload, _, err := MaterializeStagedFilePayload(ctx, w.store, w.lists, limited, size, w.chunkSize)
	if err != nil {
		return nil, fmt.Errorf("materialize UnixFS file payload: %w", err)
	}
	consumed := size + 1 - limited.N
	if consumed != size {
		return nil, fmt.Errorf("unixfs file stream contained %d bytes, expected %d", consumed, size)
	}
	canonical := path.Join(segments...)
	if err := SetStagedFile(current, canonical, payload); err != nil {
		return nil, err
	}
	return w.materializeWrite(ctx, trustedRoot, canonical, StagedKindFile, uint64(size), current)
}

func (w *verifiedWriter) loadWritableTree(ctx context.Context, trustedRoot cid.Cid) (*StagedNode, error) {
	if !trustedRoot.Defined() {
		return NewStagedDirectory(), nil
	}
	current, err := LoadStagedCurrentTree(ctx, w, w.store, trustedRoot.String())
	if err != nil {
		return nil, fmt.Errorf("load verified UnixFS tree: %w", err)
	}
	return current, nil
}

func (w *verifiedWriter) materializeWrite(ctx context.Context, base cid.Cid, rawPath, kind string, size uint64, current *StagedNode) (*WriteResult, error) {
	materialized, err := MaterializeStagedDirectory(ctx, w.roots, w.store, current)
	if err != nil {
		return nil, fmt.Errorf("materialize UnixFS candidate: %w", err)
	}
	if err := w.verifyStagedCandidate(ctx, materialized.Key, "", current); err != nil {
		return nil, fmt.Errorf("verify UnixFS candidate root: %w", err)
	}
	return &WriteResult{
		BaseRoot: base, CandidateRoot: materialized.Key, Path: rawPath, Kind: kind,
		Size: size, Accepted: false, ImmutableObjects: materialized.ImmutableObjects,
		MALTObjects: materialized.MALTObjects, ArcCount: materialized.ArcCount,
	}, nil
}

func requireDirectoryPath(root *StagedNode, segments []string) error {
	current := root
	for _, segment := range segments {
		child := current.Children[segment]
		if child == nil {
			return nil
		}
		if child.Kind != StagedKindDirectory {
			return fmt.Errorf("%w: %s", ErrNotDirectory, segment)
		}
		current = child
	}
	return nil
}

func requireFilePath(root *StagedNode, segments []string) error {
	current := root
	for index, segment := range segments {
		child := current.Children[segment]
		if child == nil {
			return nil
		}
		if index == len(segments)-1 {
			if child.Kind == StagedKindDirectory {
				return fmt.Errorf("%w: %s", ErrNotFile, segment)
			}
			return nil
		}
		if child.Kind != StagedKindDirectory {
			return fmt.Errorf("%w: %s", ErrNotDirectory, segment)
		}
		current = child
	}
	return nil
}

func (w *verifiedWriter) RemovePath(ctx context.Context, trustedRoot cid.Cid, rawPath string) (*RemoveResult, error) {
	segments, err := unixfsmodel.ParsePath(rawPath)
	if err != nil {
		return nil, err
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("cannot remove the UnixFS root")
	}
	current, err := LoadStagedCurrentTree(ctx, w, w.store, trustedRoot.String())
	if err != nil {
		return nil, fmt.Errorf("load verified UnixFS tree: %w", err)
	}
	if err := RemoveStagedPath(current, rawPath); err != nil {
		return nil, err
	}
	materialized, err := MaterializeStagedDirectory(ctx, w.roots, w.store, current)
	if err != nil {
		return nil, fmt.Errorf("materialize removal candidate: %w", err)
	}
	// Treat the candidate as a caller-selected input only for consistency
	// checking. This does not promote it into the caller's accepted-root policy.
	if err := w.verifyStagedCandidate(ctx, materialized.Key, "", current); err != nil {
		return nil, fmt.Errorf("verify removal candidate root: %w", err)
	}
	return &RemoveResult{
		BaseRoot: trustedRoot, CandidateRoot: materialized.Key, Accepted: false,
		ImmutableObjects: materialized.ImmutableObjects, MALTObjects: materialized.MALTObjects, ArcCount: materialized.ArcCount,
	}, nil
}

func (w *verifiedWriter) verifyStagedCandidate(ctx context.Context, candidate cid.Cid, currentPath string, expected *StagedNode) error {
	stat, err := w.Stat(ctx, candidate, currentPath)
	if err != nil {
		return err
	}
	if expected == nil || stat.Kind != expected.Kind || !stat.NodeRoot.Equals(expected.Key) {
		return fmt.Errorf("candidate path %q does not match materialized node", currentPath)
	}
	if expected.Kind != StagedKindDirectory {
		return nil
	}
	names := make([]string, 0, len(expected.Children))
	for name := range expected.Children {
		names = append(names, name)
	}
	slices.Sort(names)
	if !slices.Equal(stat.Entries, names) {
		return fmt.Errorf("candidate directory %q entries do not match materialized manifest", currentPath)
	}
	for _, name := range names {
		childPath := name
		if currentPath != "" {
			childPath = path.Join(currentPath, name)
		}
		if err := w.verifyStagedCandidate(ctx, candidate, childPath, expected.Children[name]); err != nil {
			return err
		}
	}
	return nil
}

func (w *verifiedWriter) StatStagedPath(ctx context.Context, root string, path string) (StagedPathStat, error) {
	rootCID, err := cid.Parse(root)
	if err != nil {
		return StagedPathStat{}, err
	}
	stat, err := w.Stat(ctx, rootCID, path)
	if err != nil {
		return StagedPathStat{}, err
	}
	payload := ""
	if stat.Kind == StagedKindDirectory {
		payload = stat.Payload.String()
	}
	return StagedPathStat{Kind: stat.Kind, StorageKind: stat.StorageKind, Key: stat.NodeRoot.String(), Payload: payload}, nil
}

func saturatingAdd(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}

var _ Reader = (*verifiedReader)(nil)
var _ Writer = (*verifiedWriter)(nil)
var _ StagedPathStatter = (*verifiedWriter)(nil)
