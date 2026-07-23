package merkledag

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

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

type replayedMerkleDAGNode struct {
	key  cid.Cid
	node ipld.Node
}

// replayBlockLoader is the narrow read boundary required by local Merkle-DAG
// replay. Implementations may be backed by an in-memory evidence bundle or by
// on-demand CAS GETs, but they must return bytes bound to the requested CID.
// The DAG methods are needed only by the UnixFS resolver/reader.
type replayBlockLoader interface {
	ipld.DAGService
	load(context.Context, cid.Cid) ([]byte, error)
}

func replayMerkleDAGResolve(ctx context.Context, dag replayBlockLoader, rawRoot string, segments []string) (replayedMerkleDAGNode, error) {
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
	mu               sync.Mutex
	blocks           map[string]blocks.Block
	used             map[string]bool
	loadCalls        uint64
	cidVerifyNS      uint64
	verifyNSByCID    map[string]uint64
	payloadBindingNS uint64
	payloadCounted   map[string]struct{}
	inPayloadBinding bool
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
	dag := &evidenceDAG{
		blocks:         make(map[string]blocks.Block, len(evidence)),
		used:           make(map[string]bool, len(evidence)),
		verifyNSByCID:  make(map[string]uint64, len(evidence)),
		payloadCounted: make(map[string]struct{}),
	}
	for i, item := range evidence {
		key, err := cid.Parse(item.CID)
		if err != nil {
			return nil, fmt.Errorf("invalid Merkle-DAG evidence CID %d: %w", i, err)
		}
		if item.Codec != key.Type() {
			return nil, fmt.Errorf("Merkle-DAG evidence block %s codec %d does not match CID codec %d", key, item.Codec, key.Type())
		}
		verifyStarted := time.Now()
		block, err := newVerifiedBlock(item.Data, key)
		verifyNS := durationNanoseconds(time.Since(verifyStarted))
		if err != nil {
			return nil, fmt.Errorf("Merkle-DAG evidence bytes do not match CID %s: %w", key, err)
		}
		if _, exists := dag.blocks[key.KeyString()]; exists {
			return nil, fmt.Errorf("duplicate Merkle-DAG evidence block %s", key)
		}
		dag.blocks[key.KeyString()] = block
		dag.verifyNSByCID[key.KeyString()] = verifyNS
		dag.cidVerifyNS += verifyNS
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
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadCalls++
	block, ok := d.blocks[key.KeyString()]
	if !ok {
		return nil, fmt.Errorf("Merkle-DAG evidence is missing block %s", key)
	}
	d.used[key.KeyString()] = true
	if d.inPayloadBinding {
		d.countPayloadBindingLocked(key)
	}
	return block, nil
}

func (d *evidenceDAG) beginPayloadBinding(target cid.Cid) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inPayloadBinding = true
	// Selective CAR validation hashes every supplied block before path replay.
	// Attribute the already-verified target hash, then hashes for blocks first
	// consumed by the UnixFS reader, without hashing any bytes a second time.
	d.countPayloadBindingLocked(target)
}

func (d *evidenceDAG) endPayloadBinding() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inPayloadBinding = false
}

func (d *evidenceDAG) countPayloadBindingLocked(key cid.Cid) {
	encoded := key.KeyString()
	if _, counted := d.payloadCounted[encoded]; counted {
		return
	}
	verifyNS, verified := d.verifyNSByCID[encoded]
	if !verified {
		return
	}
	d.payloadCounted[encoded] = struct{}{}
	d.payloadBindingNS += verifyNS
}

func (d *evidenceDAG) GetMany(ctx context.Context, keys []cid.Cid) <-chan *ipld.NodeOption {
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

// requireAllUsed rejects blocks that were not needed to replay the selected
// path and payload. Reachability from the root is insufficient: a gateway
// could otherwise attach unrelated siblings from a large DAG and turn a
// selective read into an unbounded disclosure or accounting ambiguity.
func (d *evidenceDAG) requireAllUsed() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key := range d.blocks {
		if d.used[key] {
			continue
		}
		parsed, err := cid.Cast([]byte(key))
		if err != nil {
			return fmt.Errorf("Merkle-DAG evidence contains an unused block")
		}
		return fmt.Errorf("Merkle-DAG evidence contains unused block %s", parsed)
	}
	return nil
}

func (d *evidenceDAG) blockLoadCount() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loadCalls
}

func (d *evidenceDAG) verificationDurations() (cidVerifyNS, payloadBindingNS uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cidVerifyNS, d.payloadBindingNS
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
