// Package memory provides an in-memory CAS for client tests.
package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/dewebprotocol/malt-client/internal/cas"
	cid "github.com/ipfs/go-cid"
)

// Store is a concurrency-safe in-memory content-addressed store.
type Store struct {
	mu     sync.RWMutex
	blocks map[string][]byte
}

// New creates an empty store.
func New() *Store { return &Store{blocks: make(map[string][]byte)} }

func (s *Store) Get(_ context.Context, c cid.Cid) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.blocks[c.String()]
	if !ok {
		return nil, fmt.Errorf("CAS block %s not found", c)
	}
	return append([]byte(nil), data...), nil
}

func (s *Store) Has(_ context.Context, c cid.Cid) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.blocks[c.String()]
	return ok, nil
}

func (s *Store) Put(ctx context.Context, data []byte) (cid.Cid, error) {
	return s.PutWithCodec(ctx, data, cid.Raw)
}

func (s *Store) PutWithCodec(_ context.Context, data []byte, codec uint64) (cid.Cid, error) {
	c, err := cas.CIDForBlock(cas.Block{Data: data, Codec: codec})
	if err != nil {
		return cid.Undef, err
	}
	s.mu.Lock()
	s.blocks[c.String()] = append([]byte(nil), data...)
	s.mu.Unlock()
	return c, nil
}

var _ cas.Client = (*Store)(nil)
