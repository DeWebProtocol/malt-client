// Package ipld provides client-owned Merkle-DAG parsing and link traversal.
// It is a compatibility/application facility and deliberately does not expose
// Merkle-DAG evidence as a MALT ProofList.
package ipld

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	merkledag "github.com/ipfs/boxo/ipld/merkledag"
	cid "github.com/ipfs/go-cid"
	prime "github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/codec/dagjson"
	"github.com/ipld/go-ipld-prime/datamodel"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	mh "github.com/multiformats/go-multihash"
)

type Codec uint64

const (
	CodecRaw     Codec = cid.Raw
	CodecDagPB   Codec = cid.DagProtobuf
	CodecDagCBOR Codec = cid.DagCBOR
	CodecDagJSON Codec = cid.DagJSON

	// CodecLegacyJSON is the ordinary JSON multicodec used by the v0.0.5
	// helper. It is accepted for compatibility but has no DAG-JSON guarantees.
	CodecLegacyJSON Codec = 0x0200
)

type Link struct {
	Name string
	CID  cid.Cid
	Size uint64
}

type Node struct {
	Codec  Codec
	Links  []Link
	Data   []byte
	Fields map[string]any
	Value  any
}

type Reader interface {
	Get(context.Context, cid.Cid) ([]byte, error)
}

type Decoder func(cid.Cid, []byte) (*Node, error)

// Registry maps multicodecs to bounded decoders. It is safe for concurrent
// reads and registrations.
type Registry struct {
	mu       sync.RWMutex
	decoders map[uint64]Decoder
}

func NewRegistry() *Registry {
	registry := &Registry{decoders: make(map[uint64]Decoder)}
	registry.Register(uint64(CodecRaw), decodeRaw)
	registry.Register(uint64(CodecDagPB), decodeDagPB)
	registry.Register(uint64(CodecDagCBOR), decodeDagCBOR)
	registry.Register(uint64(CodecDagJSON), decodeDagJSON)
	registry.Register(uint64(CodecLegacyJSON), decodeLegacyJSON)
	return registry
}

func (r *Registry) Register(codec uint64, decoder Decoder) {
	if r == nil || decoder == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decoders[codec] = decoder
}

func (r *Registry) Decode(key cid.Cid, data []byte) (*Node, error) {
	if r == nil {
		return nil, fmt.Errorf("IPLD codec registry is nil")
	}
	computed, err := key.Prefix().Sum(data)
	if err != nil || !computed.Equals(key) {
		return nil, fmt.Errorf("IPLD block bytes do not match CID %s", key)
	}
	r.mu.RLock()
	decoder := r.decoders[key.Type()]
	r.mu.RUnlock()
	if decoder == nil {
		return nil, fmt.Errorf("unsupported IPLD codec 0x%x", key.Type())
	}
	return decoder(key, data)
}

type Parser struct {
	blocks   Reader
	registry *Registry
}

func NewParser(blocks Reader) *Parser { return &Parser{blocks: blocks, registry: NewRegistry()} }

func NewParserWithRegistry(blocks Reader, registry *Registry) *Parser {
	if registry == nil {
		registry = NewRegistry()
	}
	return &Parser{blocks: blocks, registry: registry}
}

func (p *Parser) ParseBlock(key cid.Cid, data []byte) (*Node, error) {
	if p == nil || p.registry == nil {
		return nil, fmt.Errorf("IPLD parser is nil")
	}
	return p.registry.Decode(key, data)
}

func (p *Parser) ResolveLink(node *Node, name string) (cid.Cid, bool) {
	if node == nil {
		return cid.Undef, false
	}
	for _, link := range node.Links {
		if link.Name == name {
			return link.CID, true
		}
	}
	return cid.Undef, false
}

func (p *Parser) GetAllLinks(node *Node) []Link {
	if node == nil {
		return nil
	}
	return append([]Link(nil), node.Links...)
}

func (p *Parser) FollowLink(ctx context.Context, source cid.Cid, linkName string) (*Node, error) {
	if p == nil || p.blocks == nil {
		return nil, fmt.Errorf("IPLD block reader is nil")
	}
	data, err := p.blocks.Get(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("fetch IPLD source block: %w", err)
	}
	node, err := p.ParseBlock(source, data)
	if err != nil {
		return nil, err
	}
	target, ok := p.ResolveLink(node, linkName)
	if !ok {
		return nil, fmt.Errorf("IPLD link %q not found", linkName)
	}
	targetData, err := p.blocks.Get(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("fetch linked IPLD block: %w", err)
	}
	return p.ParseBlock(target, targetData)
}

func decodeRaw(_ cid.Cid, data []byte) (*Node, error) {
	return &Node{Codec: CodecRaw, Data: append([]byte(nil), data...)}, nil
}

func decodeDagPB(_ cid.Cid, data []byte) (*Node, error) {
	node, err := merkledag.DecodeProtobuf(data)
	if err != nil {
		return nil, fmt.Errorf("decode DAG-PB: %w", err)
	}
	links := make([]Link, 0, len(node.Links()))
	for _, link := range node.Links() {
		links = append(links, Link{Name: link.Name, CID: link.Cid, Size: link.Size})
	}
	return &Node{Codec: CodecDagPB, Links: links, Data: append([]byte(nil), node.Data()...)}, nil
}

func decodeDagCBOR(_ cid.Cid, data []byte) (*Node, error) {
	return decodePrime(CodecDagCBOR, data, dagcbor.Decode)
}

func decodeDagJSON(_ cid.Cid, data []byte) (*Node, error) {
	return decodePrime(CodecDagJSON, data, dagjson.Decode)
}

func decodePrime(codec Codec, data []byte, decoder prime.Decoder) (*Node, error) {
	builder := basicnode.Prototype.Any.NewBuilder()
	if err := decoder(builder, bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("decode IPLD codec 0x%x: %w", uint64(codec), err)
	}
	value := builder.Build()
	converted, links, err := convertNode(value, "")
	if err != nil {
		return nil, err
	}
	fields, _ := converted.(map[string]any)
	return &Node{Codec: codec, Fields: fields, Value: converted, Links: links}, nil
}

func decodeLegacyJSON(_ cid.Cid, data []byte) (*Node, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode legacy JSON IPLD block: %w", err)
	}
	links := make([]Link, 0)
	collectJSONLinks(value, "", &links)
	fields, _ := value.(map[string]any)
	return &Node{Codec: CodecLegacyJSON, Fields: fields, Value: value, Links: links}, nil
}

func convertNode(node datamodel.Node, currentPath string) (any, []Link, error) {
	switch node.Kind() {
	case datamodel.Kind_Null:
		return nil, nil, nil
	case datamodel.Kind_Bool:
		value, err := node.AsBool()
		return value, nil, err
	case datamodel.Kind_Int:
		value, err := node.AsInt()
		return value, nil, err
	case datamodel.Kind_Float:
		value, err := node.AsFloat()
		return value, nil, err
	case datamodel.Kind_String:
		value, err := node.AsString()
		return value, nil, err
	case datamodel.Kind_Bytes:
		value, err := node.AsBytes()
		return append([]byte(nil), value...), nil, err
	case datamodel.Kind_Link:
		value, err := node.AsLink()
		if err != nil {
			return nil, nil, err
		}
		link, ok := value.(cidlink.Link)
		if !ok {
			return nil, nil, fmt.Errorf("unsupported non-CID IPLD link %T", value)
		}
		return link.Cid, []Link{{Name: currentPath, CID: link.Cid}}, nil
	case datamodel.Kind_Map:
		result := make(map[string]any, node.Length())
		links := make([]Link, 0)
		iterator := node.MapIterator()
		for !iterator.Done() {
			keyNode, valueNode, err := iterator.Next()
			if err != nil {
				return nil, nil, err
			}
			key, err := keyNode.AsString()
			if err != nil {
				return nil, nil, err
			}
			childPath := joinLinkPath(currentPath, key)
			value, childLinks, err := convertNode(valueNode, childPath)
			if err != nil {
				return nil, nil, err
			}
			result[key] = value
			links = append(links, childLinks...)
		}
		return result, links, nil
	case datamodel.Kind_List:
		result := make([]any, 0, node.Length())
		links := make([]Link, 0)
		iterator := node.ListIterator()
		for !iterator.Done() {
			index, child, err := iterator.Next()
			if err != nil {
				return nil, nil, err
			}
			value, childLinks, err := convertNode(child, joinLinkPath(currentPath, strconv.FormatInt(index, 10)))
			if err != nil {
				return nil, nil, err
			}
			result = append(result, value)
			links = append(links, childLinks...)
		}
		return result, links, nil
	default:
		return nil, nil, fmt.Errorf("unsupported IPLD node kind %s", node.Kind())
	}
}

func joinLinkPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "/" + child
}

func collectJSONLinks(value any, currentPath string, links *[]Link) {
	switch typed := value.(type) {
	case map[string]any:
		if raw, ok := typed["/"].(string); ok && len(typed) == 1 {
			if key, err := cid.Parse(raw); err == nil {
				*links = append(*links, Link{Name: currentPath, CID: key})
			}
			return
		}
		for key, child := range typed {
			collectJSONLinks(child, joinLinkPath(currentPath, key), links)
		}
	case []any:
		for index, child := range typed {
			collectJSONLinks(child, joinLinkPath(currentPath, strconv.Itoa(index)), links)
		}
	}
}

func CreateDAGJSON(fields map[string]any) ([]byte, cid.Cid, error) {
	converted := convertCIDValues(fields)
	data, err := json.Marshal(converted)
	if err != nil {
		return nil, cid.Undef, fmt.Errorf("marshal DAG-JSON: %w", err)
	}
	return blockForCodec(data, uint64(CodecDagJSON))
}

func CreateLegacyJSON(fields map[string]any) ([]byte, cid.Cid, error) {
	converted := convertCIDValues(fields)
	data, err := json.Marshal(converted)
	if err != nil {
		return nil, cid.Undef, fmt.Errorf("marshal legacy JSON: %w", err)
	}
	return blockForCodec(data, uint64(CodecLegacyJSON))
}

func convertCIDValues(value any) any {
	switch typed := value.(type) {
	case cid.Cid:
		return map[string]any{"/": typed.String()}
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			result[key] = convertCIDValues(child)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = convertCIDValues(child)
		}
		return result
	default:
		return value
	}
}

func CreateRawBlock(data []byte) ([]byte, cid.Cid, error) {
	return blockForCodec(append([]byte(nil), data...), uint64(CodecRaw))
}

func blockForCodec(data []byte, codec uint64) ([]byte, cid.Cid, error) {
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return nil, cid.Undef, err
	}
	return data, cid.NewCidV1(codec, hash), nil
}

func EncodeVarint(value uint64) []byte {
	var buffer [binary.MaxVarintLen64]byte
	size := binary.PutUvarint(buffer[:], value)
	return append([]byte(nil), buffer[:size]...)
}

func DecodeVarint(data []byte) (uint64, int, error) {
	value, size := binary.Uvarint(data)
	if size <= 0 {
		return 0, 0, fmt.Errorf("invalid unsigned varint")
	}
	return value, size, nil
}

func ParseLinkPath(raw string) []string {
	parts := strings.Split(raw, "/")
	result := parts[:0]
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
