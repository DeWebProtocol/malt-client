// Package bucketsync owns durable client-side Bucket synchronization state.
// It records local candidates before observing a remote head and never promotes
// a Gateway head into the separate trusted-root store.
package bucketsync

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dewebprotocol/malt-client/transport"
	cid "github.com/ipfs/go-cid"
)

var (
	ErrNotInitialized = errors.New("Bucket workspace is not initialized; pull the Bucket head before producing local work")
	ErrNotStaged      = errors.New("Bucket candidate is not staged with its original base")
)

type Gateway interface {
	BucketHead(context.Context) (*transport.BucketRef, error)
	PushBucket(context.Context, transport.BucketPushRequest) (*transport.BucketPushResult, error)
}

type Head struct {
	CommitID string `json:"commit_id,omitempty"`
	Root     string `json:"root,omitempty"`
	Revision uint64 `json:"revision"`
}

type Conflict struct {
	Coordinate string `json:"coordinate"`
	Base       string `json:"base,omitempty"`
	Local      string `json:"local,omitempty"`
	Remote     string `json:"remote,omitempty"`
}

type Stash struct {
	ID            string     `json:"id"`
	PushID        string     `json:"push_id"`
	CandidateRoot string     `json:"candidate_root"`
	Base          Head       `json:"base"`
	ChangeSetCID  string     `json:"change_set_cid,omitempty"`
	Message       string     `json:"message,omitempty"`
	Status        string     `json:"status"`
	Branch        string     `json:"branch,omitempty"`
	Conflicts     []Conflict `json:"conflicts,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type Workspace struct {
	BucketID    string    `json:"bucket_id"`
	Initialized bool      `json:"initialized"`
	Base        Head      `json:"base"`
	Remote      Head      `json:"remote"`
	Stashes     []Stash   `json:"stashes,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type PushOutcome struct {
	Result    transport.BucketPushResult `json:"result"`
	Workspace Workspace                  `json:"workspace"`
}

type persistedState struct {
	Version    int                  `json:"version"`
	Workspaces map[string]Workspace `json:"workspaces"`
}

type Service struct {
	mu       sync.Mutex
	path     string
	gateway  Gateway
	bucketID string
	state    persistedState
}

func Open(path string, gateway Gateway, bucketID string) (*Service, error) {
	path = strings.TrimSpace(path)
	bucketID = strings.TrimSpace(bucketID)
	if path == "" || gateway == nil || bucketID == "" {
		return nil, fmt.Errorf("Bucket sync path, Gateway, and Bucket ID are required")
	}
	service := &Service{path: path, gateway: gateway, bucketID: bucketID}
	if err := service.withState(false, func() error { return nil }); err != nil {
		return nil, err
	}
	return service, nil
}

// Pull observes the latest Gateway head. When pending local stashes exist it
// updates Remote only; their recorded Base is never overwritten.
func (s *Service) Pull(ctx context.Context) (Workspace, error) {
	head, err := s.gateway.BucketHead(ctx)
	if err != nil {
		return Workspace{}, err
	}
	remote, err := headFromRef(*head)
	if err != nil {
		return Workspace{}, err
	}
	var result Workspace
	err = s.withState(true, func() error {
		workspace := s.workspace()
		workspace.Initialized = true
		workspace.Remote = remote
		if !hasPending(workspace.Stashes) {
			workspace.Base = remote
		}
		workspace.UpdatedAt = time.Now().UTC()
		s.state.Workspaces[s.bucketID] = workspace
		result = cloneWorkspace(workspace)
		return nil
	})
	return result, err
}

// CurrentBase captures the base metadata before a caller starts materializing
// a candidate. The requested root must be the currently recorded base.
func (s *Service) CurrentBase(baseRoot cid.Cid) (Head, error) {
	want := ""
	if baseRoot.Defined() {
		want = baseRoot.String()
	}
	var result Head
	err := s.withState(false, func() error {
		workspace := s.workspace()
		if !workspace.Initialized {
			return ErrNotInitialized
		}
		if workspace.Base.Root != want {
			return fmt.Errorf("candidate base root %q does not match staged workspace base %q", want, workspace.Base.Root)
		}
		result = workspace.Base
		return nil
	})
	return result, err
}

// Stage durably binds a materialized candidate to the base captured before
// its creation. Pull never rewrites this record.
func (s *Service) Stage(candidateRoot cid.Cid, base Head, changeSet cid.Cid, message string) (Stash, error) {
	if !candidateRoot.Defined() {
		return Stash{}, fmt.Errorf("candidate root is undefined")
	}
	if err := validateHead(base); err != nil {
		return Stash{}, fmt.Errorf("candidate base: %w", err)
	}
	var stash Stash
	if err := s.withState(true, func() error {
		workspace := s.workspace()
		if !workspace.Initialized {
			return ErrNotInitialized
		}
		for _, existing := range workspace.Stashes {
			if existing.Status == "pending" && existing.CandidateRoot == candidateRoot.String() {
				if existing.Base != base {
					return fmt.Errorf("candidate is already staged against a different base")
				}
				stash = existing
				return nil
			}
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		stash = Stash{
			ID: id, PushID: "push_" + id, CandidateRoot: candidateRoot.String(), Base: base,
			Message: strings.TrimSpace(message), Status: "pending", CreatedAt: now, UpdatedAt: now,
		}
		if changeSet.Defined() {
			stash.ChangeSetCID = changeSet.String()
		}
		workspace.Stashes = append(workspace.Stashes, stash)
		workspace.UpdatedAt = now
		s.state.Workspaces[s.bucketID] = workspace
		return nil
	}); err != nil {
		return Stash{}, err
	}
	return stash, nil
}

// Push submits a previously staged candidate. It never infers a base from the
// workspace at push time. A failed fetch or push leaves the stash pending for
// a later retry with the same push ID.
func (s *Service) Push(ctx context.Context, candidateRoot cid.Cid, changeSet cid.Cid, message string) (PushOutcome, error) {
	if !candidateRoot.Defined() {
		return PushOutcome{}, fmt.Errorf("candidate root is undefined")
	}
	var stash Stash
	if err := s.withState(true, func() error {
		workspace := s.workspace()
		if !workspace.Initialized {
			return ErrNotInitialized
		}
		found := false
		for i := range workspace.Stashes {
			if workspace.Stashes[i].Status != "pending" || workspace.Stashes[i].CandidateRoot != candidateRoot.String() {
				continue
			}
			found = true
			if changeSet.Defined() {
				workspace.Stashes[i].ChangeSetCID = changeSet.String()
			}
			if strings.TrimSpace(message) != "" {
				workspace.Stashes[i].Message = strings.TrimSpace(message)
			}
			workspace.Stashes[i].UpdatedAt = time.Now().UTC()
			stash = workspace.Stashes[i]
			break
		}
		if !found {
			return ErrNotStaged
		}
		workspace.UpdatedAt = time.Now().UTC()
		s.state.Workspaces[s.bucketID] = workspace
		return nil
	}); err != nil {
		return PushOutcome{}, err
	}

	// The candidate and original base are already durable. Fetching cannot
	// erase its base even when another client has advanced main.
	if _, err := s.Pull(ctx); err != nil {
		return PushOutcome{}, err
	}
	result, err := s.gateway.PushBucket(ctx, transport.BucketPushRequest{
		PushID: stash.PushID, BaseCommit: stash.Base.CommitID, BaseRoot: stash.Base.Root,
		CandidateRoot: stash.CandidateRoot, ExpectedHeadRevision: stash.Base.Revision,
		ChangeSetCID: stash.ChangeSetCID, Message: stash.Message,
	})
	if err != nil {
		return PushOutcome{}, err
	}
	var workspace Workspace
	if err := s.withState(true, func() error {
		current := s.workspace()
		for i := range current.Stashes {
			if current.Stashes[i].ID != stash.ID {
				continue
			}
			if result.Status == "branched" {
				current.Stashes[i].Status = "branched"
				if result.Branch != nil {
					current.Stashes[i].Branch = result.Branch.Name
				}
				current.Stashes[i].Conflicts = conflictsFromTransport(result.Conflicts)
				current.Stashes[i].UpdatedAt = time.Now().UTC()
			} else {
				current.Stashes = append(current.Stashes[:i], current.Stashes[i+1:]...)
			}
			break
		}
		head, err := headFromRef(result.Head)
		if err != nil {
			return err
		}
		current.Base = head
		current.Remote = head
		current.UpdatedAt = time.Now().UTC()
		s.state.Workspaces[s.bucketID] = current
		workspace = cloneWorkspace(current)
		return nil
	}); err != nil {
		return PushOutcome{}, err
	}
	return PushOutcome{Result: *result, Workspace: workspace}, nil
}

func (s *Service) Status() (Workspace, error) {
	var result Workspace
	err := s.withState(false, func() error {
		result = cloneWorkspace(s.workspace())
		return nil
	})
	return result, err
}

func (s *Service) workspace() Workspace {
	value := s.state.Workspaces[s.bucketID]
	value.BucketID = s.bucketID
	return value
}

func (s *Service) withState(write bool, operation func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	unlock, err := acquireLock(s.path + ".lock")
	if err != nil {
		return fmt.Errorf("lock Bucket workspace: %w", err)
	}
	defer func() { _ = unlock() }()
	if err := s.reload(); err != nil {
		return err
	}
	if err := operation(); err != nil {
		return err
	}
	if !write {
		return nil
	}
	return s.write()
}

func (s *Service) reload() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.state = persistedState{Version: 1, Workspaces: map[string]Workspace{}}
		return nil
	}
	if err != nil {
		return err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode Bucket workspace: %w", err)
	}
	if state.Version != 1 {
		return fmt.Errorf("unsupported Bucket workspace version %d", state.Version)
	}
	if state.Workspaces == nil {
		state.Workspaces = map[string]Workspace{}
	}
	for id, workspace := range state.Workspaces {
		if workspace.BucketID != id {
			return fmt.Errorf("Bucket workspace key does not match record")
		}
		if err := validateHead(workspace.Base); err != nil {
			return fmt.Errorf("Bucket %s base: %w", id, err)
		}
		if err := validateHead(workspace.Remote); err != nil {
			return fmt.Errorf("Bucket %s remote: %w", id, err)
		}
		for _, stash := range workspace.Stashes {
			if stash.ID == "" || stash.PushID == "" || (stash.Status != "pending" && stash.Status != "branched") {
				return fmt.Errorf("Bucket %s has an invalid stash", id)
			}
			if _, err := cid.Parse(stash.CandidateRoot); err != nil {
				return fmt.Errorf("Bucket %s stash root: %w", id, err)
			}
			if err := validateHead(stash.Base); err != nil {
				return fmt.Errorf("Bucket %s stash base: %w", id, err)
			}
		}
	}
	s.state = state
	return nil
}

func (s *Service) write() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".buckets-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
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
	return os.Rename(name, s.path)
}

func headFromRef(value transport.BucketRef) (Head, error) {
	head := Head{CommitID: value.CommitID, Root: value.Root, Revision: value.Revision}
	return head, validateHead(head)
}

func validateHead(value Head) error {
	if value.CommitID == "" {
		if value.Root != "" || value.Revision != 0 {
			return fmt.Errorf("empty head has root or revision")
		}
		return nil
	}
	if value.Root == "" || value.Revision == 0 {
		return fmt.Errorf("non-empty head lacks root or revision")
	}
	if _, err := cid.Parse(value.Root); err != nil {
		return err
	}
	return nil
}

func hasPending(values []Stash) bool {
	for _, value := range values {
		if value.Status == "pending" {
			return true
		}
	}
	return false
}

func conflictsFromTransport(values []transport.BucketConflict) []Conflict {
	result := make([]Conflict, len(values))
	for i, value := range values {
		result[i] = Conflict{Coordinate: value.Coordinate, Base: value.Base, Local: value.Local, Remote: value.Remote}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Coordinate < result[j].Coordinate })
	return result
}

func cloneWorkspace(value Workspace) Workspace {
	value.Stashes = append([]Stash(nil), value.Stashes...)
	for i := range value.Stashes {
		value.Stashes[i].Conflicts = append([]Conflict(nil), value.Stashes[i].Conflicts...)
	}
	return value
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
