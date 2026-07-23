package merkledag

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	merkledag "github.com/ipfs/boxo/ipld/merkledag"
	unixfsio "github.com/ipfs/boxo/ipld/unixfs/io"
	blocks "github.com/ipfs/go-block-format"
	cid "github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
)

// BlockGetter is the only network/storage capability needed by a Direct CAS
// verified read. Returned bytes are always revalidated locally against the
// caller-requested CID, even when the concrete transport already validates
// them.
type BlockGetter interface {
	Get(context.Context, cid.Cid) ([]byte, error)
}

// VerifiedReadMetrics contains request-scoped counters collected at the local
// verification boundary. Gateway assertions are never inputs to these values.
type VerifiedReadMetrics struct {
	NetworkRequests          uint64 `json:"network_requests"`
	CriticalSequentialRounds uint64 `json:"critical_sequential_rounds"`
	BlockLoadCalls           uint64 `json:"block_load_calls"`
	BlocksVerified           uint64 `json:"blocks_verified"`
	CASGetRequests           uint64 `json:"cas_get_requests"`
	CASBytes                 uint64 `json:"cas_bytes"`
	CARBytes                 uint64 `json:"car_bytes"`
	CARBlocks                uint64 `json:"car_blocks"`
	NetworkDurationNS        uint64 `json:"network_duration_ns"`
	CIDVerifyDurationNS      uint64 `json:"cid_verify_duration_ns"`
	// PayloadBindingDurationNS is an inclusive subset of CIDVerifyDurationNS:
	// it covers the selected target block plus blocks first verified while the
	// local UnixFS reader binds the returned payload/range.
	PayloadBindingDurationNS uint64 `json:"payload_binding_duration_ns"`
	CARDecodeDurationNS      uint64 `json:"car_decode_duration_ns"`
	PathReplayDurationNS     uint64 `json:"path_replay_duration_ns"`
	PayloadReadDurationNS    uint64 `json:"payload_read_duration_ns"`
}

// VerifiedReadResult is derived entirely by local CID/link replay from the
// caller-selected root. Target, Kind, size metadata, and Data are therefore
// suitable for use by an evaluator without trusting a Gateway response claim.
type VerifiedReadResult struct {
	Root      cid.Cid             `json:"root"`
	Target    cid.Cid             `json:"target"`
	Kind      string              `json:"kind"`
	TotalSize uint64              `json:"total_size"`
	Offset    uint64              `json:"offset"`
	Length    uint64              `json:"length"`
	Data      []byte              `json:"data"`
	Metrics   VerifiedReadMetrics `json:"metrics"`
}

// ReadMerkleDAGDirectCASVerified resolves and reads a UnixFS payload through
// on-demand CAS GETs. Every fetched block is hash-bound to its requested CID
// and decoded locally; no target, kind, or payload assertion is accepted from
// the block source.
func ReadMerkleDAGDirectCASVerified(
	ctx context.Context,
	getter BlockGetter,
	root cid.Cid,
	segments []string,
	offset, length *uint64,
) (*VerifiedReadResult, error) {
	if getter == nil {
		return nil, fmt.Errorf("Direct CAS block getter is nil")
	}
	if segments == nil {
		return nil, fmt.Errorf("Merkle-DAG segments field is required")
	}
	request := MerkleDAGReadRequest{
		Profile:  MerkleDAGReadProfile,
		Root:     root.String(),
		Segments: cloneSegments(segments),
		Offset:   cloneUint64(offset),
		Length:   cloneUint64(length),
	}
	if err := validateMerkleDAGReadRequest(request); err != nil {
		return nil, err
	}
	dag := newDirectCASDAG(getter)
	result, err := readLocallyVerified(ctx, dag, request)
	if err != nil {
		return nil, err
	}
	localMetrics := result.Metrics
	result.Metrics = dag.metrics()
	result.Metrics.PathReplayDurationNS = localMetrics.PathReplayDurationNS
	result.Metrics.PayloadReadDurationNS = localMetrics.PayloadReadDurationNS
	return result, nil
}

func readLocallyVerified(ctx context.Context, dag replayBlockLoader, request MerkleDAGReadRequest) (*VerifiedReadResult, error) {
	if err := validateMerkleDAGReadRequest(request); err != nil {
		return nil, err
	}
	root, err := cid.Parse(request.Root)
	if err != nil {
		return nil, fmt.Errorf("parse caller-selected Merkle-DAG root: %w", err)
	}
	if !isSupportedMerkleDAGCodec(root.Type()) {
		return nil, fmt.Errorf("unsupported Merkle-DAG codec %d", root.Type())
	}
	replayStarted := time.Now()
	resolved, err := replayMerkleDAGResolve(ctx, dag, request.Root, request.Segments)
	if err != nil {
		return nil, fmt.Errorf("replay Merkle-DAG read path: %w", err)
	}
	replayDuration := time.Since(replayStarted)
	if resolved.node == nil {
		return nil, fmt.Errorf("replayed target %s is not a readable UnixFS node", resolved.key)
	}
	if tracker, ok := dag.(interface {
		beginPayloadBinding(cid.Cid)
		endPayloadBinding()
	}); ok {
		tracker.beginPayloadBinding(resolved.key)
		defer tracker.endPayloadBinding()
	}
	payloadStarted := time.Now()
	reader, err := unixfsio.NewDagReader(ctx, resolved.node, dag)
	if err != nil {
		return nil, fmt.Errorf("open replayed UnixFS file: %w", err)
	}
	defer reader.Close()

	total := reader.Size()
	readOffset := uint64(0)
	if request.Offset != nil {
		readOffset = *request.Offset
	}
	if readOffset > total {
		return nil, fmt.Errorf("Merkle-DAG read offset %d exceeds replayed size %d", readOffset, total)
	}
	readLength := total - readOffset
	if request.Length != nil && *request.Length < readLength {
		readLength = *request.Length
	}
	if readLength > maxMerkleDAGReadBytes {
		return nil, fmt.Errorf("Merkle-DAG requested range exceeds %d-byte profile limit", maxMerkleDAGReadBytes)
	}
	if readOffset > uint64(^uint64(0)>>1) {
		return nil, fmt.Errorf("Merkle-DAG read offset exceeds local seek range")
	}
	if _, err := reader.Seek(int64(readOffset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek replayed UnixFS file: %w", err)
	}
	data := make([]byte, int(readLength))
	if readLength > 0 {
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, fmt.Errorf("read replayed UnixFS range: %w", err)
		}
	}
	return &VerifiedReadResult{
		Root: root, Target: resolved.key, Kind: merkleDAGNodeKind(resolved.key, resolved.node),
		TotalSize: total, Offset: readOffset, Length: readLength, Data: data,
		Metrics: VerifiedReadMetrics{
			PathReplayDurationNS:  durationNanoseconds(replayDuration),
			PayloadReadDurationNS: durationNanoseconds(time.Since(payloadStarted)),
		},
	}, nil
}

type directCASDAG struct {
	getter BlockGetter

	mu               sync.Mutex
	blocks           map[string]blocks.Block
	blockLoadCalls   uint64
	casGetRequests   uint64
	casBytes         uint64
	networkNS        uint64
	cidVerifyNS      uint64
	payloadBindingNS uint64
	verifyNSByCID    map[string]uint64
	payloadCounted   map[string]struct{}
	inPayloadBinding bool
	totalBytes       int
}

func newDirectCASDAG(getter BlockGetter) *directCASDAG {
	return &directCASDAG{
		getter: getter, blocks: make(map[string]blocks.Block), verifyNSByCID: make(map[string]uint64),
		payloadCounted: make(map[string]struct{}),
	}
}

func (d *directCASDAG) getBlock(ctx context.Context, key cid.Cid) (blocks.Block, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.blockLoadCalls++
	if block, ok := d.blocks[key.KeyString()]; ok {
		return block, nil
	}
	if !key.Defined() {
		return nil, fmt.Errorf("Direct CAS requested an undefined CID")
	}
	if !isSupportedMerkleDAGCodec(key.Type()) {
		return nil, fmt.Errorf("unsupported Merkle-DAG codec %d", key.Type())
	}
	d.casGetRequests++
	networkStarted := time.Now()
	data, err := d.getter.Get(ctx, key)
	d.networkNS += durationNanoseconds(time.Since(networkStarted))
	if err != nil {
		return nil, fmt.Errorf("Direct CAS GET %s: %w", key, err)
	}
	if len(data) > maxMerkleDAGEvidenceRaw-d.totalBytes {
		return nil, fmt.Errorf("Direct CAS read exceeds %d-byte profile limit", maxMerkleDAGEvidenceRaw)
	}
	verifyStarted := time.Now()
	block, err := newVerifiedBlock(data, key)
	verifyNS := durationNanoseconds(time.Since(verifyStarted))
	d.cidVerifyNS += verifyNS
	if err != nil {
		return nil, fmt.Errorf("Direct CAS bytes do not match CID %s: %w", key, err)
	}
	d.verifyNSByCID[key.KeyString()] = verifyNS
	if d.inPayloadBinding {
		d.countPayloadBinding(key)
	}
	d.totalBytes += len(data)
	d.casBytes += uint64(len(data))
	d.blocks[key.KeyString()] = block
	return block, nil
}

func (d *directCASDAG) beginPayloadBinding(target cid.Cid) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inPayloadBinding = true
	// Path replay necessarily verifies the selected target before opening the
	// UnixFS reader. Attribute that one already-observed hash to payload binding
	// without hashing it again.
	d.countPayloadBinding(target)
}

func (d *directCASDAG) endPayloadBinding() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inPayloadBinding = false
}

func (d *directCASDAG) countPayloadBinding(key cid.Cid) {
	if _, counted := d.payloadCounted[key.KeyString()]; counted {
		return
	}
	verifyNS, verified := d.verifyNSByCID[key.KeyString()]
	if !verified {
		return
	}
	d.payloadCounted[key.KeyString()] = struct{}{}
	d.payloadBindingNS += verifyNS
}

func (d *directCASDAG) Get(ctx context.Context, key cid.Cid) (ipld.Node, error) {
	block, err := d.getBlock(ctx, key)
	if err != nil {
		return nil, err
	}
	return decodeMerkleDAGNode(block)
}

func (d *directCASDAG) load(ctx context.Context, key cid.Cid) ([]byte, error) {
	block, err := d.getBlock(ctx, key)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), block.RawData()...), nil
}

func (d *directCASDAG) GetMany(ctx context.Context, keys []cid.Cid) <-chan *ipld.NodeOption {
	results := make(chan *ipld.NodeOption, len(keys))
	defer close(results)
	for _, key := range keys {
		if ctx.Err() != nil {
			break
		}
		node, err := d.Get(ctx, key)
		results <- &ipld.NodeOption{Node: node, Err: err}
	}
	return results
}

func (d *directCASDAG) Add(context.Context, ipld.Node) error {
	return errors.New("Direct CAS replay DAG is read-only")
}

func (d *directCASDAG) AddMany(context.Context, []ipld.Node) error {
	return errors.New("Direct CAS replay DAG is read-only")
}

func (d *directCASDAG) Remove(context.Context, cid.Cid) error {
	return errors.New("Direct CAS replay DAG is read-only")
}

func (d *directCASDAG) RemoveMany(context.Context, []cid.Cid) error {
	return errors.New("Direct CAS replay DAG is read-only")
}

func (d *directCASDAG) metrics() VerifiedReadMetrics {
	d.mu.Lock()
	defer d.mu.Unlock()
	return VerifiedReadMetrics{
		NetworkRequests:          d.casGetRequests,
		CriticalSequentialRounds: d.casGetRequests,
		BlockLoadCalls:           d.blockLoadCalls,
		BlocksVerified:           uint64(len(d.blocks)),
		CASGetRequests:           d.casGetRequests,
		CASBytes:                 d.casBytes,
		NetworkDurationNS:        d.networkNS,
		CIDVerifyDurationNS:      d.cidVerifyNS,
		PayloadBindingDurationNS: d.payloadBindingNS,
	}
}

func durationNanoseconds(duration time.Duration) uint64 {
	if duration <= 0 {
		return 0
	}
	return uint64(duration)
}

func decodeMerkleDAGNode(block blocks.Block) (ipld.Node, error) {
	switch block.Cid().Type() {
	case cid.Raw:
		return merkledag.DecodeRawBlock(block)
	case cid.DagProtobuf:
		return merkledag.DecodeProtobufBlock(block)
	default:
		return nil, fmt.Errorf("unsupported Merkle-DAG node codec %d", block.Cid().Type())
	}
}

func isSupportedMerkleDAGCodec(codec uint64) bool {
	switch codec {
	case cid.Raw, cid.DagProtobuf, cid.DagCBOR, cid.DagJSON:
		return true
	default:
		return false
	}
}

// NewBlockWithCid hashes only in dependency debug builds, so untrusted
// network/evidence bytes must be checked explicitly before constructing the
// block wrapper.
func newVerifiedBlock(data []byte, key cid.Cid) (blocks.Block, error) {
	got, err := key.Prefix().Sum(data)
	if err != nil {
		return nil, err
	}
	if !got.Equals(key) {
		return nil, fmt.Errorf("content does not match CID %s", key)
	}
	return blocks.NewBlockWithCid(data, key)
}

var _ replayBlockLoader = (*directCASDAG)(nil)
