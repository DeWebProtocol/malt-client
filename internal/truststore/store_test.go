package truststore

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
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
