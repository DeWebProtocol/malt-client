package machine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedDescriptorMatchesActualMachine(t *testing.T) {
	identity, err := Probe()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := NewDescriptor("host-under-test", ClassGeneral, "test-suite:registered-platform-evidence", identity)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "machine.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	evidence, err := LoadPinned(path, hex.EncodeToString(digest[:]), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Descriptor.ID != descriptor.ID || evidence.Probe != identity {
		t.Fatalf("machine evidence = %#v", evidence)
	}

	hostile := *descriptor
	hostile.Identity.CPUModel += " hostile"
	if err := Match(&hostile, identity); err == nil {
		t.Fatal("mismatched CPU model was accepted")
	}
}

func TestDescriptorDecodeIsStrict(t *testing.T) {
	if _, err := Decode([]byte(`{"schema_version":"malt-evaluation-machine-descriptor/v1","schema_version":"malt-evaluation-machine-descriptor/v1"}`)); err == nil {
		t.Fatal("duplicate descriptor field was accepted")
	}
	identity, err := Probe()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := NewDescriptor("host", ClassGeneral, "test:evidence", identity)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(descriptor)
	raw = append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := Decode(raw); err == nil {
		t.Fatal("unknown descriptor field was accepted")
	}
}
