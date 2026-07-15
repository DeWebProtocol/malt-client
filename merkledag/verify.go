package merkledag

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"unicode/utf8"

	unixfsio "github.com/ipfs/boxo/ipld/unixfs/io"
	cid "github.com/ipfs/go-cid"
)

func (c *Client) ReadMerkleDAGVerified(ctx context.Context, root cid.Cid, segments []string, offset, length *uint64) (*MerkleDAGReadResponse, error) {
	request := MerkleDAGReadRequest{Profile: MerkleDAGReadProfile, Root: root.String(), Segments: cloneSegments(segments), Offset: cloneUint64(offset), Length: cloneUint64(length)}
	response, err := c.ReadMerkleDAG(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := VerifyMerkleDAGRead(ctx, request, *response); err != nil {
		return nil, err
	}
	return response, nil
}

// VerifyMerkleDAGResolve validates every evidence block CID and replays UnixFS
// path traversal from the caller-selected root. It never emits a ProofList.
func VerifyMerkleDAGResolve(ctx context.Context, request MerkleDAGResolveRequest, response MerkleDAGResolveResponse) error {
	if err := validateMerkleDAGResolveRequest(request); err != nil {
		return err
	}
	if response.Profile != MerkleDAGResolveProfile {
		return fmt.Errorf("unsupported Merkle-DAG resolve response profile %q", response.Profile)
	}
	dag, err := newEvidenceDAG(response.Blocks)
	if err != nil {
		return err
	}
	resolved, err := replayMerkleDAGResolve(ctx, dag, request.Root, request.Segments)
	if err != nil {
		return fmt.Errorf("replay Merkle-DAG resolve: %w", err)
	}
	if response.Target != resolved.key.String() {
		return fmt.Errorf("Merkle-DAG resolve target %q does not match replayed target %s", response.Target, resolved.key)
	}
	if response.Kind != merkleDAGNodeKind(resolved.key, resolved.node) {
		return fmt.Errorf("Merkle-DAG resolve kind %q does not match replayed kind %q", response.Kind, merkleDAGNodeKind(resolved.key, resolved.node))
	}
	return dag.requireAllReachable(request.Root)
}

// VerifyMerkleDAGRead validates every evidence block CID, replays path
// traversal, reconstructs the caller-selected file range, and compares bytes.
func VerifyMerkleDAGRead(ctx context.Context, request MerkleDAGReadRequest, response MerkleDAGReadResponse) error {
	if err := validateMerkleDAGReadRequest(request); err != nil {
		return err
	}
	if response.Profile != MerkleDAGReadProfile {
		return fmt.Errorf("unsupported Merkle-DAG read response profile %q", response.Profile)
	}
	if response.Length > maxMerkleDAGReadBytes || len(response.Data) > maxMerkleDAGReadBytes {
		return fmt.Errorf("Merkle-DAG read exceeds %d-byte profile limit", maxMerkleDAGReadBytes)
	}
	dag, err := newEvidenceDAG(response.Blocks)
	if err != nil {
		return err
	}
	resolved, err := replayMerkleDAGResolve(ctx, dag, request.Root, request.Segments)
	if err != nil {
		return fmt.Errorf("replay Merkle-DAG read path: %w", err)
	}
	if response.Target != resolved.key.String() {
		return fmt.Errorf("Merkle-DAG read target %q does not match replayed target %s", response.Target, resolved.key)
	}
	if response.Kind != merkleDAGNodeKind(resolved.key, resolved.node) {
		return fmt.Errorf("Merkle-DAG read kind %q does not match replayed kind %q", response.Kind, merkleDAGNodeKind(resolved.key, resolved.node))
	}
	if resolved.node == nil {
		return fmt.Errorf("replayed target %s is not a readable UnixFS node", resolved.key)
	}
	reader, err := unixfsio.NewDagReader(ctx, resolved.node, dag)
	if err != nil {
		return fmt.Errorf("open replayed UnixFS file: %w", err)
	}
	defer reader.Close()
	total := reader.Size()
	if response.TotalSize != total {
		return fmt.Errorf("Merkle-DAG read total size %d does not match replayed size %d", response.TotalSize, total)
	}
	offset := uint64(0)
	if request.Offset != nil {
		offset = *request.Offset
	}
	if offset > total {
		return fmt.Errorf("Merkle-DAG read offset %d exceeds replayed size %d", offset, total)
	}
	wantLength := total - offset
	if request.Length != nil && *request.Length < wantLength {
		wantLength = *request.Length
	}
	if wantLength > maxMerkleDAGReadBytes {
		return fmt.Errorf("Merkle-DAG requested range exceeds %d-byte profile limit", maxMerkleDAGReadBytes)
	}
	if response.Offset != offset || response.Length != wantLength || uint64(len(response.Data)) != wantLength {
		return fmt.Errorf("Merkle-DAG read range metadata does not match caller request")
	}
	if offset > uint64(^uint64(0)>>1) {
		return fmt.Errorf("Merkle-DAG read offset exceeds local seek range")
	}
	if _, err := reader.Seek(int64(offset), io.SeekStart); err != nil {
		return fmt.Errorf("seek replayed UnixFS file: %w", err)
	}
	want := make([]byte, int(wantLength))
	if wantLength > 0 {
		if _, err := io.ReadFull(reader, want); err != nil {
			return fmt.Errorf("read replayed UnixFS range: %w", err)
		}
	}
	if !bytes.Equal(response.Data, want) {
		return fmt.Errorf("Merkle-DAG response bytes do not match locally replayed range")
	}
	return dag.requireAllReachable(request.Root)
}

func validateMerkleDAGResolveRequest(request MerkleDAGResolveRequest) error {
	if request.Profile != MerkleDAGResolveProfile {
		return fmt.Errorf("unsupported Merkle-DAG resolve profile %q", request.Profile)
	}
	if _, err := cid.Parse(request.Root); err != nil {
		return fmt.Errorf("invalid caller-selected Merkle-DAG root: %w", err)
	}
	return validateMerkleDAGSegments(request.Segments)
}

func validateMerkleDAGReadRequest(request MerkleDAGReadRequest) error {
	if request.Profile != MerkleDAGReadProfile {
		return fmt.Errorf("unsupported Merkle-DAG read profile %q", request.Profile)
	}
	if _, err := cid.Parse(request.Root); err != nil {
		return fmt.Errorf("invalid caller-selected Merkle-DAG root: %w", err)
	}
	return validateMerkleDAGSegments(request.Segments)
}

func validateMerkleDAGSegments(segments []string) error {
	if segments == nil {
		return fmt.Errorf("Merkle-DAG segments field is required")
	}
	if len(segments) > maxMerkleDAGSegments {
		return fmt.Errorf("too many Merkle-DAG path segments")
	}
	for _, segment := range segments {
		if len(segment) > maxMerkleDAGSegmentSize {
			return fmt.Errorf("Merkle-DAG path segment exceeds %d-byte profile limit", maxMerkleDAGSegmentSize)
		}
		if !utf8.ValidString(segment) {
			return fmt.Errorf("Merkle-DAG path segment is not valid UTF-8")
		}
	}
	return nil
}
