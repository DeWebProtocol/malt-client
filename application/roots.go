// Package application composes trusted-root policy with UnixFS and Merkle-DAG
// capabilities into reusable native-client use cases. CLI and daemon adapters
// should remain thin presentation/control-plane layers over these services.
package application

import (
	"fmt"
	"strings"

	"github.com/dewebprotocol/malt-client/trust"
	cid "github.com/ipfs/go-cid"
)

// RootSelection is a caller-selected CID or a locally accepted alias. Alias is
// empty for explicit CIDs. Candidate roots are never considered during
// selection.
type RootSelection struct {
	Root  cid.Cid
	Alias string
}

// Roots owns reusable accepted/candidate-root policy use cases.
type Roots struct {
	policy trust.Policy
}

func NewRoots(policy trust.Policy) (*Roots, error) {
	if policy == nil {
		return nil, fmt.Errorf("trusted-root policy is nil")
	}
	return &Roots{policy: policy}, nil
}

// NewExplicitRootSelector returns a selector that accepts caller-supplied CIDs
// without consulting local trusted-root state. It deliberately cannot resolve
// aliases or mutate accepted/candidate-root records.
//
// This selector keeps explicit-CID operations available even when the optional
// alias store is missing, corrupt, or not writable.
func NewExplicitRootSelector() *Roots {
	return &Roots{}
}

// Select resolves an explicit CID or an accepted alias. It never falls back to
// a candidate root or an untrusted network value.
func (r *Roots) Select(raw string) (RootSelection, error) {
	if r == nil {
		return RootSelection{}, fmt.Errorf("trusted-root application is nil")
	}
	raw = strings.TrimSpace(raw)
	if root, err := cid.Parse(raw); err == nil {
		return RootSelection{Root: root}, nil
	}
	if r.policy == nil {
		return RootSelection{}, fmt.Errorf("%q is not an explicit CID", raw)
	}
	root, record, err := trust.AcceptedRoot(r.policy, raw)
	if err != nil {
		return RootSelection{}, fmt.Errorf("%q is neither a CID nor a trusted-root alias: %w", raw, err)
	}
	return RootSelection{Root: root, Alias: record.Alias}, nil
}

func (r *Roots) List() ([]trust.Record, error) {
	if r == nil || r.policy == nil {
		return nil, fmt.Errorf("trusted-root application is nil")
	}
	return r.policy.List()
}

func (r *Roots) Get(alias string) (trust.Record, error) {
	if r == nil || r.policy == nil {
		return trust.Record{}, fmt.Errorf("trusted-root application is nil")
	}
	return r.policy.Get(alias)
}

func (r *Roots) Trust(alias, root, profile, gateway, source string) (trust.Record, error) {
	if r == nil || r.policy == nil {
		return trust.Record{}, fmt.Errorf("trusted-root application is nil")
	}
	return r.policy.Trust(alias, root, profile, gateway, source)
}

// RecordCandidate records an untrusted mutation result without accepting it.
// The policy verifies that baseRoot is still the alias's accepted root.
func (r *Roots) RecordCandidate(alias string, candidateRoot, baseRoot cid.Cid, source string) (trust.Record, error) {
	if r == nil || r.policy == nil {
		return trust.Record{}, fmt.Errorf("trusted-root application is nil")
	}
	if strings.TrimSpace(alias) == "" {
		return trust.Record{}, fmt.Errorf("candidate alias is empty")
	}
	if !candidateRoot.Defined() || !baseRoot.Defined() {
		return trust.Record{}, fmt.Errorf("candidate and base roots must be defined")
	}
	return r.policy.AddCandidate(alias, candidateRoot.String(), baseRoot.String(), source)
}

// AcceptCandidate is the only application use case that promotes a recorded
// candidate. Callers must invoke it as an explicit local action.
func (r *Roots) AcceptCandidate(alias string, candidate cid.Cid, source string) (trust.Record, error) {
	if r == nil || r.policy == nil {
		return trust.Record{}, fmt.Errorf("trusted-root application is nil")
	}
	if !candidate.Defined() {
		return trust.Record{}, fmt.Errorf("candidate root is undefined")
	}
	return r.policy.AcceptCandidate(alias, candidate.String(), source)
}
