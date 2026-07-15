// Package truststore persists the roots accepted by the local MALT client.
// Candidate roots returned by an untrusted gateway are recorded separately and
// never become accepted without an explicit local action.
package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	cid "github.com/ipfs/go-cid"
)

var (
	ErrNotFound          = errors.New("trusted-root alias not found")
	ErrCandidateNotFound = errors.New("candidate root not found")
	ErrStaleCandidate    = errors.New("candidate is based on a stale accepted root")
)

type Candidate struct {
	Root       string    `json:"root"`
	BaseRoot   string    `json:"base_root,omitempty"`
	Source     string    `json:"source,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type Record struct {
	Alias        string      `json:"alias"`
	Profile      string      `json:"profile,omitempty"`
	Gateway      string      `json:"gateway,omitempty"`
	AcceptedRoot string      `json:"accepted_root"`
	PreviousRoot string      `json:"previous_root,omitempty"`
	Source       string      `json:"source,omitempty"`
	AcceptedAt   time.Time   `json:"accepted_at"`
	Candidates   []Candidate `json:"candidates,omitempty"`
}

type state struct {
	Version int               `json:"version"`
	Roots   map[string]Record `json:"roots"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	state state
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("trust-store path is empty")
	}
	s := &Store{path: path, state: state{Version: 1, Roots: map[string]Record{}}}
	if err := s.withLockedState(func() error { return nil }); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) List() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadWithFileLock(); err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(s.state.Roots))
	for _, record := range s.state.Roots {
		out = append(out, cloneRecord(record))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out, nil
}

func (s *Store) Get(alias string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadWithFileLock(); err != nil {
		return Record{}, err
	}
	record, ok := s.state.Roots[normalizeAlias(alias)]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *Store) Trust(alias, root, profile, gateway, source string) (Record, error) {
	alias = normalizeAlias(alias)
	if alias == "" {
		return Record{}, fmt.Errorf("trusted-root alias is empty")
	}
	if _, err := cid.Parse(root); err != nil {
		return Record{}, fmt.Errorf("invalid trusted root: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockAndReload()
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = unlock() }()
	record := s.state.Roots[alias]
	previous := record.AcceptedRoot
	record.Alias = alias
	record.Profile = profile
	record.Gateway = gateway
	record.PreviousRoot = previous
	record.AcceptedRoot = root
	record.Source = source
	record.AcceptedAt = time.Now().UTC()
	record.Candidates = removeCandidate(record.Candidates, root)
	s.state.Roots[alias] = record
	if err := s.writeLocked(); err != nil {
		return Record{}, err
	}
	return cloneRecord(record), nil
}

func (s *Store) AddCandidate(alias, root, baseRoot, source string) (Record, error) {
	alias = normalizeAlias(alias)
	if _, err := cid.Parse(root); err != nil {
		return Record{}, fmt.Errorf("invalid candidate root: %w", err)
	}
	if _, err := cid.Parse(baseRoot); err != nil {
		return Record{}, fmt.Errorf("invalid candidate base root: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockAndReload()
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = unlock() }()
	record, ok := s.state.Roots[alias]
	if !ok {
		return Record{}, ErrNotFound
	}
	if baseRoot != record.AcceptedRoot {
		return Record{}, fmt.Errorf("%w: candidate base %s, accepted root %s", ErrStaleCandidate, baseRoot, record.AcceptedRoot)
	}
	if root == record.AcceptedRoot {
		return cloneRecord(record), nil
	}
	record.Candidates = removeCandidate(record.Candidates, root)
	record.Candidates = append(record.Candidates, Candidate{
		Root: root, BaseRoot: baseRoot, Source: source, ObservedAt: time.Now().UTC(),
	})
	s.state.Roots[alias] = record
	if err := s.writeLocked(); err != nil {
		return Record{}, err
	}
	return cloneRecord(record), nil
}

func (s *Store) AcceptCandidate(alias, root, source string) (Record, error) {
	alias = normalizeAlias(alias)
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockAndReload()
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = unlock() }()
	record, ok := s.state.Roots[alias]
	if !ok {
		return Record{}, ErrNotFound
	}
	var candidate Candidate
	found := false
	for _, value := range record.Candidates {
		if value.Root == root {
			candidate = value
			found = true
			break
		}
	}
	if !found {
		return Record{}, ErrCandidateNotFound
	}
	if candidate.BaseRoot == "" || candidate.BaseRoot != record.AcceptedRoot {
		return Record{}, fmt.Errorf("%w: candidate base %q, accepted root %s", ErrStaleCandidate, candidate.BaseRoot, record.AcceptedRoot)
	}
	record.PreviousRoot = record.AcceptedRoot
	record.AcceptedRoot = root
	record.Source = source
	record.AcceptedAt = time.Now().UTC()
	record.Candidates = removeCandidate(record.Candidates, root)
	s.state.Roots[alias] = record
	if err := s.writeLocked(); err != nil {
		return Record{}, err
	}
	return cloneRecord(record), nil
}

func (s *Store) reloadWithFileLock() error {
	unlock, err := s.lockAndReload()
	if err != nil {
		return err
	}
	return unlock()
}

func (s *Store) withLockedState(operation func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockAndReload()
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()
	return operation()
}

func (s *Store) lockAndReload() (func() error, error) {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return nil, fmt.Errorf("create trust-store directory: %w", err)
	}
	unlock, err := acquireTrustStoreLock(s.path + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock trust store: %w", err)
	}
	if err := s.reloadLocked(); err != nil {
		_ = unlock()
		return nil, err
	}
	return unlock, nil
}

func (s *Store) reloadLocked() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.state = state{Version: 1, Roots: map[string]Record{}}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read trust store: %w", err)
	}
	var next state
	if err := json.Unmarshal(data, &next); err != nil {
		return fmt.Errorf("decode trust store: %w", err)
	}
	if next.Version != 1 {
		return fmt.Errorf("unsupported trust-store version %d", next.Version)
	}
	if next.Roots == nil {
		next.Roots = map[string]Record{}
	}
	s.state = next
	return nil
}

func (s *Store) writeLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create trust-store directory: %w", err)
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".roots-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace trust store: %w", err)
	}
	return nil
}

func normalizeAlias(alias string) string { return strings.TrimSpace(alias) }

func removeCandidate(values []Candidate, root string) []Candidate {
	out := make([]Candidate, 0, len(values))
	for _, value := range values {
		if value.Root != root {
			out = append(out, value)
		}
	}
	return out
}

func cloneRecord(record Record) Record {
	record.Candidates = append([]Candidate(nil), record.Candidates...)
	return record
}
