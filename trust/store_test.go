package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	cid "github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
)

const testRoot = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
const candidateRoot = "bafkreib6u4dvknbd5g7pp7z2ex2jvdkbo3hytm5v6hlx3q3iibgfk5j5wi"
const secondCandidateRoot = "bafkqaaa"

func TestCandidateRequiresExplicitAcceptance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust("docs", testRoot, "unixfs", "http://gateway", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddCandidate("docs", candidateRoot, testRoot, "upload"); err != nil {
		t.Fatal(err)
	}
	record, err := store.Get("docs")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != testRoot || len(record.Candidates) != 1 {
		t.Fatalf("candidate changed accepted root: %#v", record)
	}
	if _, err := store.AcceptCandidate("docs", candidateRoot, "manual"); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err = reopened.Get("docs")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != candidateRoot || record.PreviousRoot != testRoot {
		t.Fatalf("accepted record = %#v", record)
	}
	if _, err := reopened.AcceptCandidate("docs", testRoot, "rollback"); !errors.Is(err, ErrCandidateNotFound) {
		t.Fatalf("unexpected rollback acceptance error: %v", err)
	}
}

func TestCIDRepresentationsAreCanonicalizedAcrossTrustWorkflow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	alternateRoot := alternateCIDString(t, testRoot)
	alternateCandidate := alternateCIDString(t, candidateRoot)

	record, err := store.Trust("docs", alternateRoot, "unixfs", "", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != testRoot {
		t.Fatalf("trusted root = %q, want canonical %q", record.AcceptedRoot, testRoot)
	}
	record, err = store.AddCandidate("docs", alternateCandidate, alternateRoot, "upload")
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Candidates) != 1 || record.Candidates[0].Root != candidateRoot || record.Candidates[0].BaseRoot != testRoot {
		t.Fatalf("canonical candidate record = %#v", record)
	}
	record, err = store.AcceptCandidate("docs", alternateCandidate, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != candidateRoot || record.PreviousRoot != testRoot {
		t.Fatalf("accepted canonical record = %#v", record)
	}
}

func TestTrustEquivalentRootPreservesDistinctPreviousRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust("docs", testRoot, "unixfs", "first.example", "initial"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust("docs", candidateRoot, "unixfs", "second.example", "advance"); err != nil {
		t.Fatal(err)
	}
	record, err := store.Trust("docs", alternateCIDString(t, candidateRoot), "updated", "third.example", "refresh")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != candidateRoot || record.PreviousRoot != testRoot {
		t.Fatalf("equivalent re-trust changed root history: %#v", record)
	}
	if record.Profile != "updated" || record.Gateway != "third.example" || record.Source != "refresh" {
		t.Fatalf("equivalent re-trust did not refresh metadata: %#v", record)
	}
}

func TestOpenCanonicalizesPersistedCIDRepresentationsAndDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.json")
	persisted := state{Version: 1, Roots: map[string]Record{
		"docs": {
			Alias:        "docs",
			AcceptedRoot: alternateCIDString(t, testRoot),
			PreviousRoot: alternateCIDString(t, secondCandidateRoot),
			Candidates: []Candidate{
				{Root: alternateCIDString(t, candidateRoot), BaseRoot: alternateCIDString(t, testRoot), Source: "first"},
				{Root: candidateRoot, BaseRoot: testRoot, Source: "last"},
			},
		},
	}}
	writeTestState(t, path, persisted)

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get("docs")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != testRoot || record.PreviousRoot != secondCandidateRoot {
		t.Fatalf("canonical persisted record = %#v", record)
	}
	if len(record.Candidates) != 1 || record.Candidates[0].Root != candidateRoot || record.Candidates[0].BaseRoot != testRoot || record.Candidates[0].Source != "last" {
		t.Fatalf("canonical persisted candidates = %#v", record.Candidates)
	}
	if _, err := store.AcceptCandidate("docs", alternateCIDString(t, candidateRoot), "manual"); err != nil {
		t.Fatalf("accept canonicalized persisted candidate: %v", err)
	}
}

func TestOpenDropsPersistedCandidateEquivalentToAcceptedRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.json")
	persisted := state{Version: 1, Roots: map[string]Record{
		"docs": {
			Alias:        "docs",
			AcceptedRoot: alternateCIDString(t, testRoot),
			PreviousRoot: alternateCIDString(t, secondCandidateRoot),
			Candidates: []Candidate{
				{Root: testRoot, BaseRoot: alternateCIDString(t, testRoot), Source: "legacy-self"},
				{Root: alternateCIDString(t, candidateRoot), BaseRoot: testRoot, Source: "real-candidate"},
			},
		},
	}}
	writeTestState(t, path, persisted)

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get("docs")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != testRoot || record.PreviousRoot != secondCandidateRoot {
		t.Fatalf("canonical persisted record = %#v", record)
	}
	if len(record.Candidates) != 1 || record.Candidates[0].Root != candidateRoot || record.Candidates[0].Source != "real-candidate" {
		t.Fatalf("persisted candidates after self-candidate migration = %#v", record.Candidates)
	}
	if _, err := store.AcceptCandidate("docs", alternateCIDString(t, testRoot), "manual"); !errors.Is(err, ErrCandidateNotFound) {
		t.Fatalf("accept equivalent-to-current candidate error = %v, want ErrCandidateNotFound", err)
	}
	after, err := store.Get("docs")
	if err != nil {
		t.Fatal(err)
	}
	if after.AcceptedRoot != testRoot || after.PreviousRoot != secondCandidateRoot {
		t.Fatalf("rejected self-acceptance changed roots: %#v", after)
	}
}

func TestOpenDropsPreviousRootEquivalentToAcceptedRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.json")
	persisted := state{Version: 1, Roots: map[string]Record{
		"docs": {
			Alias:        "docs",
			AcceptedRoot: alternateCIDString(t, testRoot),
			PreviousRoot: testRoot,
		},
	}}
	writeTestState(t, path, persisted)

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get("docs")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != testRoot || record.PreviousRoot != "" {
		t.Fatalf("canonical reload retained a self previous root: %#v", record)
	}
}

func TestOpenRejectsMalformedPersistedCID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.json")
	writeTestState(t, path, state{Version: 1, Roots: map[string]Record{
		"docs": {Alias: "docs", AcceptedRoot: "not-a-cid"},
	}})
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted malformed persisted CID")
	}
}

func TestAddCandidateRejectsStaleBaseAfterAcceptedRootAdvances(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust("docs", testRoot, "unixfs", "", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust("docs", candidateRoot, "unixfs", "", "concurrent-update"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddCandidate("docs", secondCandidateRoot, testRoot, "stale-operation"); !errors.Is(err, ErrStaleCandidate) {
		t.Fatalf("AddCandidate stale error = %v, want ErrStaleCandidate", err)
	}
	record, err := store.Get("docs")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != candidateRoot || len(record.Candidates) != 0 {
		t.Fatalf("stale add changed record: %#v", record)
	}
}

func TestAcceptCandidateRejectsStaleSibling(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust("docs", testRoot, "unixfs", "", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddCandidate("docs", candidateRoot, testRoot, "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddCandidate("docs", secondCandidateRoot, testRoot, "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptCandidate("docs", secondCandidateRoot, "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptCandidate("docs", candidateRoot, "manual"); !errors.Is(err, ErrStaleCandidate) {
		t.Fatalf("AcceptCandidate stale error = %v, want ErrStaleCandidate", err)
	}
	record, err := store.Get("docs")
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != secondCandidateRoot || record.PreviousRoot != testRoot {
		t.Fatalf("stale acceptance changed record: %#v", record)
	}
}

func TestIndependentStoresReloadBeforeMutating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.json")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Trust("first", testRoot, "unixfs", "", "first-process"); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Trust("second", candidateRoot, "unixfs", "", "second-process"); err != nil {
		t.Fatal(err)
	}
	roots, err := first.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 2 || roots[0].Alias != "first" || roots[1].Alias != "second" {
		t.Fatalf("roots after interleaved writers = %#v", roots)
	}
}

func TestIndependentStoresSerializeConcurrentMutations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roots.json")
	stores := make([]*Store, 2)
	for i := range stores {
		store, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		stores[i] = store
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := stores[i%len(stores)].Trust(fmt.Sprintf("root-%02d", i), testRoot, "unixfs", "", "concurrent-test")
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	roots, err := stores[0].List()
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 20 {
		t.Fatalf("roots after concurrent writers = %d, want 20", len(roots))
	}
}

func alternateCIDString(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := cid.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := parsed.StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatal(err)
	}
	if alternate == parsed.String() {
		t.Fatalf("alternate CID representation did not change for %s", raw)
	}
	return alternate
}

func writeTestState(t *testing.T, path string, value state) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
