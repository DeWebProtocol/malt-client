package application_test

import (
	"context"
	"github.com/dewebprotocol/malt-client/application"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/protocol"
	sdk "github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	"testing"
)

type authenticationRemote struct {
	e                     *engine.Engine
	nodes                 *memory.Nodes
	tamper, receiptTamper bool
	calls                 int
}

func (r *authenticationRemote) Authenticate(ctx context.Context, q protocol.AuthenticationRequest) (*protocol.AuthenticationResult, error) {
	r.calls++
	result, err := sdk.Execute(ctx, r.e, q, r.nodes)
	if err == nil && r.tamper {
		result.Binding.Target = cid.MustParse("bafkqablimvwgy3y")
	}
	return &result, err
}
func (r *authenticationRemote) MaterializeAuthentication(ctx context.Context, c protocol.AuthenticationCandidate) (cid.Cid, error) {
	if r.receiptTamper {
		return cid.MustParse("bafkqaaa"), nil
	}
	if err := sdk.Materialize(ctx, r.e, c, r.nodes); err != nil {
		return cid.Undef, err
	}
	return cid.Decode(c.Root)
}
func TestAuthenticationSelectsCallerRootAndVerifiesBeforeReturning(t *testing.T) {
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		t.Fatal(err)
	}
	registry := engine.NewRegistry()
	if err = registry.Register(scheme); err != nil {
		t.Fatal(err)
	}
	e := engine.New(input.DefaultRegistry(), registry)
	remote := &authenticationRemote{e: e, nodes: memory.NewNodes()}
	app, err := application.NewAuthentication(application.NewExplicitRootSelector(), remote, e)
	if err != nil {
		t.Fatal(err)
	}
	value := input.LabelValue([]byte("a/b"))
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 1, Profile: maltcid.IPA256}, Entries: []engine.Entry{{Input: value, Target: cid.MustParse("bafkqaaa")}}}
	candidate, err := app.Store(t.Context(), state, cid.Undef)
	if err != nil {
		t.Fatal(err)
	}
	q := protocol.AuthenticationRequest{Operation: "binding", Input: &value}
	result, err := app.Read(t.Context(), candidate.Root, q)
	if err != nil || !result.Binding.Present {
		t.Fatal("typed read", err)
	}
	remote.tamper = true
	if _, err = app.Read(t.Context(), candidate.Root, q); err == nil {
		t.Fatal("returned forged target")
	}
	calls := remote.calls
	q.Root = "bafkqaaa"
	if _, err = app.Read(t.Context(), candidate.Root, q); err == nil || remote.calls != calls {
		t.Fatal("accepted different request Root")
	}
	if _, err = app.Read(t.Context(), "unaccepted-alias", q); err == nil || remote.calls != calls {
		t.Fatal("selected an unaccepted alias")
	}
	remote.receiptTamper = true
	if _, err = app.Store(t.Context(), state, cid.Undef); err == nil {
		t.Fatal("accepted altered receipt Root")
	}
}
