package merkledag

import (
	"context"
	"fmt"

	cid "github.com/ipfs/go-cid"
)

type ProfileTransport interface {
	PostMerkleDAGResolve(context.Context, []byte) ([]byte, error)
	PostMerkleDAGRead(context.Context, []byte) ([]byte, error)
}

// Client owns the Merkle DAG compatibility profile. It replays CID/link
// evidence locally and never represents that evidence as a MALT ProofList.
type Client struct {
	transport ProfileTransport
}

// New constructs a compatibility client over an untrusted profile transport.
func New(remote ProfileTransport) (*Client, error) {
	if remote == nil {
		return nil, fmt.Errorf("Merkle-DAG profile transport is nil")
	}
	return &Client{transport: remote}, nil
}

const (
	MerkleDAGResolveProfile = "merkledag.resolve/v0alpha1"
	MerkleDAGReadProfile    = "merkledag.read/v0alpha1"
	maxMerkleDAGSegments    = 256
	maxMerkleDAGSegmentSize = 1024
	maxMerkleDAGEvidence    = 4096
	maxMerkleDAGEvidenceRaw = 32 << 20
	maxMerkleDAGReadBytes   = 16 << 20
)

// MerkleDAGResolveRequest binds compatibility traversal to a caller-selected
// root. It is deliberately distinct from the MALT resolve profile.
type MerkleDAGResolveRequest struct {
	Profile  string   `json:"profile"`
	Root     string   `json:"root"`
	Segments []string `json:"segments"`
}

// MerkleDAGReadRequest binds a UnixFS file range to a caller-selected root and
// segment sequence. A nil Length means the remainder of the file.
type MerkleDAGReadRequest struct {
	Profile  string   `json:"profile"`
	Root     string   `json:"root"`
	Segments []string `json:"segments"`
	Offset   *uint64  `json:"offset,omitempty"`
	Length   *uint64  `json:"length,omitempty"`
}

// MerkleDAGBlock is CID-bound replay evidence, not a MALT ProofList step.
type MerkleDAGBlock struct {
	CID   string `json:"cid"`
	Codec uint64 `json:"codec"`
	Data  []byte `json:"data"`
}

type MerkleDAGResolveResponse struct {
	Profile string           `json:"profile"`
	Target  string           `json:"target"`
	Kind    string           `json:"kind"`
	Blocks  []MerkleDAGBlock `json:"blocks"`
}

type MerkleDAGReadResponse struct {
	Profile   string           `json:"profile"`
	Target    string           `json:"target"`
	Kind      string           `json:"kind"`
	TotalSize uint64           `json:"total_size"`
	Offset    uint64           `json:"offset"`
	Length    uint64           `json:"length"`
	Data      []byte           `json:"data"`
	Blocks    []MerkleDAGBlock `json:"blocks"`
}

// ResolveMerkleDAG executes the compatibility transport without establishing
// trust. Call VerifyMerkleDAGResolve before accepting Target or Kind.
func (c *Client) ResolveMerkleDAG(ctx context.Context, request MerkleDAGResolveRequest) (*MerkleDAGResolveResponse, error) {
	if err := validateMerkleDAGResolveRequest(request); err != nil {
		return nil, err
	}
	var response MerkleDAGResolveResponse
	if err := c.doMerkleDAG(ctx, "/v1/compat/merkledag/resolve", request, &response); err != nil {
		return nil, err
	}
	if response.Profile != MerkleDAGResolveProfile {
		return nil, fmt.Errorf("unsupported Merkle-DAG resolve response profile %q", response.Profile)
	}
	return &response, nil
}

// ResolveMerkleDAGVerified executes and locally replays a compatibility resolve.
func (c *Client) ResolveMerkleDAGVerified(ctx context.Context, root cid.Cid, segments []string) (*MerkleDAGResolveResponse, error) {
	request := MerkleDAGResolveRequest{Profile: MerkleDAGResolveProfile, Root: root.String(), Segments: cloneSegments(segments)}
	response, err := c.ResolveMerkleDAG(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := VerifyMerkleDAGResolve(ctx, request, *response); err != nil {
		return nil, err
	}
	return response, nil
}

// ReadMerkleDAG executes the compatibility transport without establishing
// trust. Call VerifyMerkleDAGRead before accepting Data or metadata.
func (c *Client) ReadMerkleDAG(ctx context.Context, request MerkleDAGReadRequest) (*MerkleDAGReadResponse, error) {
	if err := validateMerkleDAGReadRequest(request); err != nil {
		return nil, err
	}
	var response MerkleDAGReadResponse
	if err := c.doMerkleDAG(ctx, "/v1/compat/merkledag/read", request, &response); err != nil {
		return nil, err
	}
	if response.Profile != MerkleDAGReadProfile {
		return nil, fmt.Errorf("unsupported Merkle-DAG read response profile %q", response.Profile)
	}
	return &response, nil
}
