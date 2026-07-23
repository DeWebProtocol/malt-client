package e0selftest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIssueBindsEvaluatorInvocationCasesAndFiles(t *testing.T) {
	profile := Profile{ProfileID: "profile", PositiveCases: []string{"accept"}, HostileCases: []string{"reject"}}
	contract, err := profile.Contract()
	if err != nil {
		t.Fatal(err)
	}
	if contract.ProfileSHA256 != "254f4b991b9ae62cc380181d4d0daba8d7019b312c620c42340e2bbea1451ad8" {
		t.Fatalf("profile digest = %s", contract.ProfileSHA256)
	}
	input := filepath.Join(t.TempDir(), "corpus.json")
	if err := os.WriteFile(input, []byte(`{"case":"fixed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	environment, err := BuildInvocationEnvironment(
		"capability", profile,
		InputFile{FileID: "worker", Path: executable},
		[]InputFile{{FileID: "corpus", Path: input}},
		[]string{"corpus"},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(InvocationEnvironment, environment)
	receipt, err := Issue("capability", profile, []CaseResult{{ID: "accept", Passed: true}, {ID: "reject", Passed: true}})
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	if receipt.CapabilityID != "capability" || receipt.Positive.Executed != 1 || receipt.Hostile.Executed != 1 || len(receipt.TestedInputs) != 1 || receipt.TestedInputs[0].FileID != "corpus" {
		t.Fatalf("receipt = %+v", receipt)
	}
}

func TestIssueRejectsRelabelMissingFailedAndDuplicateCases(t *testing.T) {
	profile := Profile{ProfileID: "profile", PositiveCases: []string{"accept"}, HostileCases: []string{"reject"}}
	input := filepath.Join(t.TempDir(), "corpus.json")
	if err := os.WriteFile(input, []byte(`{"case":"fixed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	environment, err := BuildInvocationEnvironment(
		"capability", profile,
		InputFile{FileID: "worker", Path: executable},
		[]InputFile{{FileID: "corpus", Path: input}},
		[]string{"corpus"},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(InvocationEnvironment, environment)
	for name, test := range map[string]struct {
		capability string
		results    []CaseResult
	}{
		"relabel":   {capability: "other", results: []CaseResult{{ID: "accept", Passed: true}, {ID: "reject", Passed: true}}},
		"missing":   {capability: "capability", results: []CaseResult{{ID: "accept", Passed: true}}},
		"failed":    {capability: "capability", results: []CaseResult{{ID: "accept", Passed: true}, {ID: "reject", Passed: false}}},
		"duplicate": {capability: "capability", results: []CaseResult{{ID: "accept", Passed: true}, {ID: "accept", Passed: true}, {ID: "reject", Passed: true}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Issue(test.capability, profile, test.results); err == nil {
				t.Fatal("invalid self-test issued a receipt")
			}
		})
	}
}

func TestIssueRejectsMutatedInputAndMalformedInvocation(t *testing.T) {
	profile := Profile{ProfileID: "profile", PositiveCases: []string{"accept"}, HostileCases: []string{"reject"}}
	input := filepath.Join(t.TempDir(), "corpus.json")
	if err := os.WriteFile(input, []byte(`{"case":"fixed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	environment, err := BuildInvocationEnvironment(
		"capability", profile,
		InputFile{FileID: "worker", Path: executable},
		[]InputFile{{FileID: "corpus", Path: input}},
		[]string{"corpus"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte(`{"case":"mutated"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(InvocationEnvironment, environment)
	if _, err := Issue("capability", profile, []CaseResult{{ID: "accept", Passed: true}, {ID: "reject", Passed: true}}); err == nil || !strings.Contains(err.Error(), "does not match E0 pin") {
		t.Fatalf("mutated input error = %v", err)
	}
	t.Setenv(InvocationEnvironment, `{"schema_version":"one","schema_version":"two"}`)
	if _, err := Issue("capability", profile, []CaseResult{{ID: "accept", Passed: true}, {ID: "reject", Passed: true}}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate invocation error = %v", err)
	}
}
