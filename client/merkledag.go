package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	merkledag "github.com/ipfs/boxo/ipld/merkledag"
	unixfs "github.com/ipfs/boxo/ipld/unixfs"
	unixfsio "github.com/ipfs/boxo/ipld/unixfs/io"
	blocks "github.com/ipfs/go-block-format"
	cid "github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/codec/dagjson"
	"github.com/ipld/go-ipld-prime/datamodel"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
)

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

type merkleDAGResolveWire struct {
	Profile string                 `json:"profile"`
	Target  string                 `json:"target"`
	Kind    string                 `json:"kind"`
	Blocks  boundedMerkleDAGBlocks `json:"blocks"`
}

type merkleDAGReadWire struct {
	Profile   string                   `json:"profile"`
	Target    string                   `json:"target"`
	Kind      string                   `json:"kind"`
	TotalSize uint64                   `json:"total_size"`
	Offset    uint64                   `json:"offset"`
	Length    uint64                   `json:"length"`
	Data      boundedMerkleDAGReadData `json:"data"`
	Blocks    boundedMerkleDAGBlocks   `json:"blocks"`
}

type boundedMerkleDAGBlocks []MerkleDAGBlock

type boundedMerkleDAGReadData []byte

func (c *Client) doMerkleDAG(ctx context.Context, route string, request, response any) error {
	u, err := c.endpoint(route)
	if err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.responseError(resp)
	}
	data, err := readBounded(resp.Body, c.maxJSONResponseBytes, "gateway Merkle-DAG JSON response")
	if err != nil {
		return err
	}
	switch out := response.(type) {
	case *MerkleDAGResolveResponse:
		var wire merkleDAGResolveWire
		if err := decodeStrictMerkleDAGJSON(data, &wire); err != nil {
			return err
		}
		*out = MerkleDAGResolveResponse{Profile: wire.Profile, Target: wire.Target, Kind: wire.Kind, Blocks: []MerkleDAGBlock(wire.Blocks)}
	case *MerkleDAGReadResponse:
		var wire merkleDAGReadWire
		if err := decodeStrictMerkleDAGJSON(data, &wire); err != nil {
			return err
		}
		*out = MerkleDAGReadResponse{
			Profile: wire.Profile, Target: wire.Target, Kind: wire.Kind,
			TotalSize: wire.TotalSize, Offset: wire.Offset, Length: wire.Length,
			Data: []byte(wire.Data), Blocks: []MerkleDAGBlock(wire.Blocks),
		}
	default:
		return fmt.Errorf("unsupported Merkle-DAG response type %T", response)
	}
	return nil
}

func decodeStrictMerkleDAGJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode gateway Merkle-DAG JSON response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode gateway Merkle-DAG JSON response: expected one JSON object")
	}
	return nil
}

func (blocks *boundedMerkleDAGBlocks) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return fmt.Errorf("Merkle-DAG blocks must be an array")
	}
	result := make([]MerkleDAGBlock, 0, min(maxMerkleDAGEvidence, 64))
	totalBytes := 0
	for decoder.More() {
		if len(result) >= maxMerkleDAGEvidence {
			return fmt.Errorf("Merkle-DAG evidence exceeds %d-block profile limit", maxMerkleDAGEvidence)
		}
		var item struct {
			CID   string          `json:"cid"`
			Codec uint64          `json:"codec"`
			Data  json.RawMessage `json:"data"`
		}
		if err := decoder.Decode(&item); err != nil {
			return err
		}
		if len(item.Data) == 0 {
			return fmt.Errorf("Merkle-DAG evidence block data is required")
		}
		decoded, err := decodeBoundedBase64JSON(item.Data, maxMerkleDAGEvidenceRaw-totalBytes, "Merkle-DAG evidence")
		if err != nil {
			return err
		}
		totalBytes += len(decoded)
		result = append(result, MerkleDAGBlock{CID: item.CID, Codec: item.Codec, Data: decoded})
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("Merkle-DAG blocks contain trailing JSON")
	}
	*blocks = result
	return nil
}

func (data *boundedMerkleDAGReadData) UnmarshalJSON(raw []byte) error {
	decoded, err := decodeBoundedBase64JSON(raw, maxMerkleDAGReadBytes, "Merkle-DAG read data")
	if err != nil {
		return err
	}
	*data = decoded
	return nil
}

func decodeBoundedBase64JSON(raw []byte, limit int, description string) ([]byte, error) {
	if limit < 0 || bytes.Equal(raw, []byte("null")) {
		return nil, fmt.Errorf("%s exceeds its profile limit", description)
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf("%s must be a base64 JSON string: %w", description, err)
	}
	decodedLength := base64.StdEncoding.DecodedLen(len(encoded))
	if strings.HasSuffix(encoded, "==") {
		decodedLength -= 2
	} else if strings.HasSuffix(encoded, "=") {
		decodedLength--
	}
	if decodedLength > limit {
		return nil, fmt.Errorf("%s exceeds %d-byte profile limit", description, limit)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", description, err)
	}
	if len(decoded) > limit {
		return nil, fmt.Errorf("%s exceeds %d-byte profile limit", description, limit)
	}
	return decoded, nil
}

// ReadMerkleDAGVerified executes and locally replays a compatibility read.
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

type replayedMerkleDAGNode struct {
	key  cid.Cid
	node ipld.Node
}

func replayMerkleDAGResolve(ctx context.Context, dag *evidenceDAG, rawRoot string, segments []string) (replayedMerkleDAGNode, error) {
	root, _ := cid.Parse(rawRoot)
	current := root
	remaining := append([]string(nil), segments...)
	for {
		if isLinkIPLDCodec(current.Type()) {
			raw, err := dag.load(ctx, current)
			if err != nil {
				return replayedMerkleDAGNode{}, err
			}
			if len(remaining) == 0 {
				return replayedMerkleDAGNode{key: current}, nil
			}
			next, rest, err := resolveIPLDLink(current.Type(), raw, remaining)
			if err != nil {
				return replayedMerkleDAGNode{}, err
			}
			current, remaining = next, rest
			continue
		}
		node, err := dag.Get(ctx, current)
		if err != nil {
			return replayedMerkleDAGNode{}, err
		}
		if len(remaining) == 0 {
			return replayedMerkleDAGNode{key: current, node: node}, nil
		}
		link, rest, err := unixfsio.ResolveUnixfsOnce(ctx, dag, node, remaining)
		if err != nil || link == nil {
			return replayedMerkleDAGNode{}, fmt.Errorf("UnixFS path not found")
		}
		if len(rest) >= len(remaining) {
			return replayedMerkleDAGNode{}, fmt.Errorf("UnixFS resolver made no progress")
		}
		current, remaining = link.Cid, rest
	}
}

func resolveIPLDLink(codec uint64, raw []byte, segments []string) (cid.Cid, []string, error) {
	builder := basicnode.Prototype.Any.NewBuilder()
	var decode func(datamodel.NodeAssembler, io.Reader) error
	switch codec {
	case cid.DagCBOR:
		decode = dagcbor.Decode
	case cid.DagJSON:
		decode = dagjson.Decode
	default:
		return cid.Undef, nil, fmt.Errorf("unsupported linked IPLD codec %d", codec)
	}
	if err := decode(builder, bytes.NewReader(raw)); err != nil {
		return cid.Undef, nil, fmt.Errorf("invalid linked IPLD evidence: %w", err)
	}
	current := builder.Build()
	for index, segment := range segments {
		var (
			next datamodel.Node
			err  error
		)
		switch current.Kind() {
		case datamodel.Kind_Map:
			next, err = current.LookupByString(segment)
		case datamodel.Kind_List:
			position, parseErr := strconv.ParseInt(segment, 10, 64)
			if parseErr != nil || position < 0 {
				err = fmt.Errorf("invalid IPLD list index")
			} else {
				next, err = current.LookupByIndex(position)
			}
		default:
			err = fmt.Errorf("IPLD path crosses a non-container value")
		}
		if err != nil {
			return cid.Undef, nil, fmt.Errorf("IPLD path not found: %w", err)
		}
		current = next
		if current.Kind() == datamodel.Kind_Link {
			link, err := current.AsLink()
			if err != nil {
				return cid.Undef, nil, fmt.Errorf("invalid IPLD link: %w", err)
			}
			value, ok := link.(cidlink.Link)
			if !ok {
				return cid.Undef, nil, fmt.Errorf("IPLD link is not a CID")
			}
			return value.Cid, segments[index+1:], nil
		}
	}
	return cid.Undef, nil, fmt.Errorf("IPLD path must terminate at a link")
}

func isLinkIPLDCodec(codec uint64) bool { return codec == cid.DagCBOR || codec == cid.DagJSON }

type evidenceDAG struct {
	blocks map[string]blocks.Block
}

func newEvidenceDAG(evidence []MerkleDAGBlock) (*evidenceDAG, error) {
	if len(evidence) == 0 {
		return nil, fmt.Errorf("Merkle-DAG evidence is empty")
	}
	if len(evidence) > maxMerkleDAGEvidence {
		return nil, fmt.Errorf("Merkle-DAG evidence exceeds %d-block profile limit", maxMerkleDAGEvidence)
	}
	totalBytes := 0
	for _, item := range evidence {
		if len(item.Data) > maxMerkleDAGEvidenceRaw-totalBytes {
			return nil, fmt.Errorf("Merkle-DAG evidence exceeds %d-byte profile limit", maxMerkleDAGEvidenceRaw)
		}
		totalBytes += len(item.Data)
	}
	dag := &evidenceDAG{blocks: make(map[string]blocks.Block, len(evidence))}
	for i, item := range evidence {
		key, err := cid.Parse(item.CID)
		if err != nil {
			return nil, fmt.Errorf("invalid Merkle-DAG evidence CID %d: %w", i, err)
		}
		if item.Codec != key.Type() {
			return nil, fmt.Errorf("Merkle-DAG evidence block %s codec %d does not match CID codec %d", key, item.Codec, key.Type())
		}
		block, err := blocks.NewBlockWithCid(item.Data, key)
		if err != nil {
			return nil, fmt.Errorf("Merkle-DAG evidence bytes do not match CID %s: %w", key, err)
		}
		if _, exists := dag.blocks[key.KeyString()]; exists {
			return nil, fmt.Errorf("duplicate Merkle-DAG evidence block %s", key)
		}
		dag.blocks[key.KeyString()] = block
	}
	return dag, nil
}

func (d *evidenceDAG) Get(_ context.Context, key cid.Cid) (ipld.Node, error) {
	block, err := d.loadBlock(key)
	if err != nil {
		return nil, err
	}
	switch key.Type() {
	case cid.Raw:
		return merkledag.DecodeRawBlock(block)
	case cid.DagProtobuf:
		return merkledag.DecodeProtobufBlock(block)
	default:
		return nil, fmt.Errorf("unsupported Merkle-DAG evidence codec %d", key.Type())
	}
}

func (d *evidenceDAG) load(_ context.Context, key cid.Cid) ([]byte, error) {
	block, err := d.loadBlock(key)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), block.RawData()...), nil
}

func (d *evidenceDAG) loadBlock(key cid.Cid) (blocks.Block, error) {
	block, ok := d.blocks[key.KeyString()]
	if !ok {
		return nil, fmt.Errorf("Merkle-DAG evidence is missing block %s", key)
	}
	return block, nil
}

func (d *evidenceDAG) GetMany(ctx context.Context, keys []cid.Cid) <-chan *ipld.NodeOption {
	results := make(chan *ipld.NodeOption)
	go func() {
		defer close(results)
		for _, key := range keys {
			node, err := d.Get(ctx, key)
			select {
			case results <- &ipld.NodeOption{Node: node, Err: err}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return results
}

func (d *evidenceDAG) Add(context.Context, ipld.Node) error {
	return errors.New("evidence DAG is read-only")
}
func (d *evidenceDAG) AddMany(context.Context, []ipld.Node) error {
	return errors.New("evidence DAG is read-only")
}
func (d *evidenceDAG) Remove(context.Context, cid.Cid) error {
	return errors.New("evidence DAG is read-only")
}
func (d *evidenceDAG) RemoveMany(context.Context, []cid.Cid) error {
	return errors.New("evidence DAG is read-only")
}

func (d *evidenceDAG) requireAllReachable(rawRoot string) error {
	root, err := cid.Parse(rawRoot)
	if err != nil {
		return err
	}
	queue := []cid.Cid{root}
	reachable := make(map[string]bool, len(d.blocks))
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		keyString := key.KeyString()
		if reachable[keyString] {
			continue
		}
		block, ok := d.blocks[keyString]
		if !ok {
			continue
		}
		reachable[keyString] = true
		links, err := evidenceBlockLinks(block)
		if err != nil {
			return err
		}
		for _, link := range links {
			if _, present := d.blocks[link.KeyString()]; present && !reachable[link.KeyString()] {
				queue = append(queue, link)
			}
		}
	}
	for key := range d.blocks {
		if reachable[key] {
			continue
		}
		parsed, err := cid.Cast([]byte(key))
		if err != nil {
			return fmt.Errorf("Merkle-DAG evidence contains an unreachable block")
		}
		return fmt.Errorf("Merkle-DAG evidence contains unreachable block %s", parsed)
	}
	return nil
}

func evidenceBlockLinks(block blocks.Block) ([]cid.Cid, error) {
	switch block.Cid().Type() {
	case cid.Raw:
		return nil, nil
	case cid.DagProtobuf:
		node, err := merkledag.DecodeProtobufBlock(block)
		if err != nil {
			return nil, err
		}
		links := node.Links()
		out := make([]cid.Cid, 0, len(links))
		for _, link := range links {
			out = append(out, link.Cid)
		}
		return out, nil
	case cid.DagCBOR, cid.DagJSON:
		builder := basicnode.Prototype.Any.NewBuilder()
		var decode func(datamodel.NodeAssembler, io.Reader) error
		if block.Cid().Type() == cid.DagCBOR {
			decode = dagcbor.Decode
		} else {
			decode = dagjson.Decode
		}
		if err := decode(builder, bytes.NewReader(block.RawData())); err != nil {
			return nil, fmt.Errorf("decode linked IPLD evidence: %w", err)
		}
		var out []cid.Cid
		if err := appendIPLDLinks(builder.Build(), &out); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported Merkle-DAG evidence codec %d", block.Cid().Type())
	}
}

func appendIPLDLinks(node datamodel.Node, out *[]cid.Cid) error {
	switch node.Kind() {
	case datamodel.Kind_Link:
		link, err := node.AsLink()
		if err != nil {
			return err
		}
		value, ok := link.(cidlink.Link)
		if !ok {
			return fmt.Errorf("DAG-CBOR evidence link is not a CID")
		}
		*out = append(*out, value.Cid)
	case datamodel.Kind_Map:
		iterator := node.MapIterator()
		for !iterator.Done() {
			_, value, err := iterator.Next()
			if err != nil {
				return err
			}
			if err := appendIPLDLinks(value, out); err != nil {
				return err
			}
		}
	case datamodel.Kind_List:
		iterator := node.ListIterator()
		for !iterator.Done() {
			_, value, err := iterator.Next()
			if err != nil {
				return err
			}
			if err := appendIPLDLinks(value, out); err != nil {
				return err
			}
		}
	}
	return nil
}

func merkleDAGNodeKind(key cid.Cid, node ipld.Node) string {
	if isLinkIPLDCodec(key.Type()) {
		return "ipld"
	}
	if _, ok := node.(*merkledag.RawNode); ok {
		return "file"
	}
	proto, ok := node.(*merkledag.ProtoNode)
	if !ok {
		return "ipld"
	}
	value, err := unixfs.FSNodeFromBytes(proto.Data())
	if err != nil {
		return "ipld"
	}
	switch value.Type() {
	case unixfs.TFile, unixfs.TRaw:
		return "file"
	case unixfs.TDirectory:
		return "directory"
	case unixfs.THAMTShard:
		return "hamt_directory"
	case unixfs.TSymlink:
		return "symlink"
	case unixfs.TMetadata:
		return "metadata"
	default:
		return "unixfs"
	}
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneSegments(segments []string) []string {
	cloned := make([]string, len(segments))
	copy(cloned, segments)
	return cloned
}

var _ ipld.DAGService = (*evidenceDAG)(nil)
