package rq3baseline

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	merkledag "github.com/ipfs/boxo/ipld/merkledag"
	unixfs "github.com/ipfs/boxo/ipld/unixfs"
	blocks "github.com/ipfs/go-block-format"
	cid "github.com/ipfs/go-cid"
)

const (
	categoryPayloadChunk    = "payload_chunk"
	categoryStructural      = "cas_structural_metadata"
	categoryMixed           = "mixed_payload_and_structural_metadata"
	statusNewlyPersisted    = "newly_persisted"
	statusAlreadyPresent    = "already_present"
	statusDuplicateInCommit = "duplicate_in_commit"
)

type storedBlock struct {
	codec uint64
	data  []byte
}

type accountingStore struct {
	mu sync.Mutex

	blocks map[string]storedBlock

	phaseAttempts map[string]struct{}
	events        []CASWriteEvent
	putNanos      int64
	getNanos      int64
	readObjects   int
	readBytes     int64
}

func newAccountingStore() *accountingStore {
	return &accountingStore{blocks: make(map[string]storedBlock)}
}

func (s *accountingStore) beginPhase() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phaseAttempts = make(map[string]struct{})
	s.events = make([]CASWriteEvent, 0)
	s.putNanos = 0
	s.getNanos = 0
	s.readObjects = 0
	s.readBytes = 0
}

func (s *accountingStore) Get(ctx context.Context, key cid.Cid) ([]byte, error) {
	started := time.Now()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	block, ok := s.blocks[key.String()]
	if ok {
		s.readObjects++
		s.readBytes += int64(len(block.data))
	}
	s.getNanos += time.Since(started).Nanoseconds()
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", clientcas.ErrNotFound, key)
	}
	if block.codec != key.Type() {
		return nil, fmt.Errorf("stored block codec %d does not match CID codec %d", block.codec, key.Type())
	}
	return cloneBytes(block.data), nil
}

func (s *accountingStore) PutWithCodec(ctx context.Context, data []byte, codec uint64) (cid.Cid, error) {
	started := time.Now()
	if err := ctx.Err(); err != nil {
		return cid.Undef, err
	}
	if codec != cid.Raw && codec != cid.DagProtobuf {
		return cid.Undef, fmt.Errorf("unsupported evaluator CAS codec %d", codec)
	}
	key, err := clientcas.CIDForBlock(clientcas.Block{Data: data, Codec: codec})
	if err != nil {
		return cid.Undef, err
	}
	category, payloadBytes, structuralBytes, err := classifyBlock(key, data, codec)
	if err != nil {
		return cid.Undef, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { s.putNanos += time.Since(started).Nanoseconds() }()
	if s.phaseAttempts == nil {
		return cid.Undef, fmt.Errorf("CAS accounting phase is not active")
	}
	keyString := key.String()
	status := statusNewlyPersisted
	if existing, exists := s.blocks[keyString]; exists {
		if existing.codec != codec || !bytes.Equal(existing.data, data) {
			return cid.Undef, fmt.Errorf("CID collision for %s", key)
		}
		if _, attempted := s.phaseAttempts[keyString]; attempted {
			status = statusDuplicateInCommit
		} else {
			status = statusAlreadyPresent
		}
	} else {
		s.blocks[keyString] = storedBlock{codec: codec, data: cloneBytes(data)}
	}
	s.phaseAttempts[keyString] = struct{}{}
	s.events = append(s.events, CASWriteEvent{
		Sequence:                len(s.events),
		CID:                     keyString,
		Codec:                   codec,
		Category:                category,
		Bytes:                   int64(len(data)),
		PayloadBytes:            payloadBytes,
		StructuralMetadataBytes: structuralBytes,
		Status:                  status,
	})
	return key, nil
}

func (s *accountingStore) finishPhase() (CASAccounting, int64, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	accounting := CASAccounting{
		Events: append([]CASWriteEvent(nil), s.events...),
		Reads:  CASReadAccounting{Objects: s.readObjects, Bytes: s.readBytes},
	}
	for _, event := range accounting.Events {
		accumulateCategory(&accounting.Total, event, event.Bytes)
		if event.PayloadBytes > 0 || event.Category == categoryPayloadChunk {
			accumulateCategory(&accounting.PayloadChunks, event, event.PayloadBytes)
		}
		if event.StructuralMetadataBytes > 0 {
			accumulateCategory(&accounting.StructuralMetadata, event, event.StructuralMetadataBytes)
		}
	}
	return accounting, s.putNanos, s.getNanos
}

func accumulateCategory(summary *CategoryAccounting, event CASWriteEvent, bytes int64) {
	summary.AttemptedObjects++
	summary.AttemptedBytes += bytes
	switch event.Status {
	case statusNewlyPersisted:
		summary.NewlyPersistedObjects++
		summary.NewlyPersistedBytes += bytes
	case statusAlreadyPresent:
		summary.AlreadyPresentObjects++
		summary.AlreadyPresentBytes += bytes
	case statusDuplicateInCommit:
		summary.DuplicateObjects++
		summary.DuplicateBytes += bytes
	}
}

func classifyBlock(key cid.Cid, data []byte, codec uint64) (string, int64, int64, error) {
	if codec == cid.Raw {
		return categoryPayloadChunk, int64(len(data)), 0, nil
	}
	block, err := blocks.NewBlockWithCid(data, key)
	if err != nil {
		return "", 0, 0, fmt.Errorf("decode dag-pb accounting block %s: %w", key, err)
	}
	node, err := merkledag.DecodeProtobufBlock(block)
	if err != nil {
		return "", 0, 0, fmt.Errorf("decode dag-pb accounting node %s: %w", key, err)
	}
	protoNode, ok := node.(*merkledag.ProtoNode)
	if !ok {
		return "", 0, 0, fmt.Errorf("decoded dag-pb accounting node %s has type %T", key, node)
	}
	unixFSData, err := unixfs.FromBytes(protoNode.Data())
	if err != nil {
		return "", 0, 0, fmt.Errorf("decode UnixFS accounting data %s: %w", key, err)
	}
	payloadBytes := int64(0)
	switch unixFSData.GetType() {
	case unixfs.TFile, unixfs.TRaw:
		payloadBytes = int64(len(unixFSData.GetData()))
	case unixfs.TDirectory, unixfs.THAMTShard:
		// HAMT uses Data for its bitfield. It is authentication structure,
		// not application payload, so the entire block remains metadata.
	default:
		return "", 0, 0, &UnsupportedError{Gap: "symlink_and_special_file_mutation", Message: fmt.Sprintf("UnixFS accounting node %s has unsupported type %d", key, unixFSData.GetType())}
	}
	structuralBytes := int64(len(data)) - payloadBytes
	if structuralBytes < 0 {
		return "", 0, 0, fmt.Errorf("UnixFS payload accounting exceeds dag-pb block %s", key)
	}
	if payloadBytes > 0 {
		return categoryMixed, payloadBytes, structuralBytes, nil
	}
	return categoryStructural, 0, structuralBytes, nil
}
