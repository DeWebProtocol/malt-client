package truststore

import (
	"errors"
	"path/filepath"
	"testing"
)

const testRoot = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
const candidateRoot = "bafkreib6u4dvknbd5g7pp7z2ex2jvdkbo3hytm5v6hlx3q3iibgfk5j5wi"

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
