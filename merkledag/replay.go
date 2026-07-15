package merkledag

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

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
