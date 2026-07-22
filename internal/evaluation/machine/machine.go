// Package machine pins and verifies the physical machine identity used by the
// paper evaluator. A low-power classification is accepted only after the
// descriptor's actual OS, architecture, CPU, board, cores, and memory match a
// local probe.
package machine

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	SchemaVersion = "malt-evaluation-machine-descriptor/v1"
	ClassGeneral  = "general-purpose"
	ClassLowPower = "low-power-arm"

	MaxDescriptorBytes = 64 << 10
)

//go:embed machine-descriptor.schema.json
var SchemaJSON []byte

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type Identity struct {
	OS                 string `json:"os"`
	Architecture       string `json:"architecture"`
	CPUModel           string `json:"cpu_model"`
	CPUModelSource     string `json:"cpu_model_source"`
	BoardModel         string `json:"board_model"`
	BoardModelSource   string `json:"board_model_source"`
	LogicalCores       uint32 `json:"logical_cores"`
	LogicalCoresSource string `json:"logical_cores_source"`
	MemoryBytes        uint64 `json:"memory_bytes"`
	MemorySource       string `json:"memory_source"`
}

type Descriptor struct {
	SchemaVersion                string   `json:"schema_version"`
	ID                           string   `json:"id"`
	Identity                     Identity `json:"identity"`
	Classification               string   `json:"classification"`
	ClassificationEvidenceSource string   `json:"classification_evidence_source"`
}

type Evidence struct {
	Descriptor *Descriptor
	SHA256     string
	Bytes      uint64
	Probe      Identity
}

func Decode(data []byte) (*Descriptor, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("decode machine descriptor: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var descriptor Descriptor
	if err := decoder.Decode(&descriptor); err != nil {
		return nil, fmt.Errorf("decode machine descriptor: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("machine descriptor must contain exactly one JSON object")
	}
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	return &descriptor, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delimiter == '[' {
			for decoder.More() {
				if err := value(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		}
		if delimiter != '{' {
			return fmt.Errorf("unexpected JSON delimiter")
		}
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			keys[key] = struct{}{}
			if err := value(); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON contains trailing data")
	}
	return nil
}

func (d Descriptor) Validate() error {
	if d.SchemaVersion != SchemaVersion || !idPattern.MatchString(d.ID) {
		return fmt.Errorf("machine descriptor schema or ID is invalid")
	}
	identity := d.Identity
	for name, value := range map[string]string{
		"os": identity.OS, "architecture": identity.Architecture,
		"cpu_model": identity.CPUModel, "cpu_model_source": identity.CPUModelSource,
		"board_model": identity.BoardModel, "board_model_source": identity.BoardModelSource,
		"logical_cores_source": identity.LogicalCoresSource, "memory_source": identity.MemorySource,
	} {
		if value != normalize(value) || len(value) == 0 || len(value) > 512 {
			return fmt.Errorf("machine descriptor %s is empty, non-canonical, or too long", name)
		}
	}
	if identity.LogicalCores == 0 || identity.LogicalCores > 4096 || identity.MemoryBytes < 64<<20 {
		return fmt.Errorf("machine descriptor cores or memory is outside evaluator bounds")
	}
	if d.Classification != ClassGeneral && d.Classification != ClassLowPower || normalize(d.ClassificationEvidenceSource) != d.ClassificationEvidenceSource || len(d.ClassificationEvidenceSource) == 0 || len(d.ClassificationEvidenceSource) > 1024 {
		return fmt.Errorf("machine descriptor classification evidence is invalid")
	}
	if d.Classification == ClassLowPower && identity.Architecture != "arm" && identity.Architecture != "arm64" {
		return fmt.Errorf("low-power-arm classification requires an ARM architecture")
	}
	return nil
}

func (d Descriptor) LowPowerARM() bool { return d.Classification == ClassLowPower }

func Match(descriptor *Descriptor, actual Identity) error {
	if descriptor == nil {
		return fmt.Errorf("machine descriptor is nil")
	}
	if err := descriptor.Validate(); err != nil {
		return err
	}
	expected := descriptor.Identity
	if actual != expected {
		return fmt.Errorf("actual machine identity does not match descriptor %q: actual=%+v expected=%+v", descriptor.ID, actual, expected)
	}
	return nil
}

// LoadPinned rejects symlinks and file replacement, verifies the registered
// bytes/digest, strictly decodes the descriptor, probes the host, and matches
// the complete physical identity before returning evidence.
func LoadPinned(path, expectedSHA256 string, expectedBytes int64) (*Evidence, error) {
	if path == "" || !canonicalSHA256(expectedSHA256) || expectedBytes <= 0 || expectedBytes > MaxDescriptorBytes {
		return nil, fmt.Errorf("machine descriptor artifact pin is incomplete")
	}
	lstat, err := os.Lstat(path)
	if err != nil || lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() || lstat.Size() != expectedBytes {
		return nil, fmt.Errorf("machine descriptor is not the pinned regular file: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(lstat, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("machine descriptor changed before it was opened")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxDescriptorBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	post, err := os.Lstat(path)
	if err != nil || !os.SameFile(lstat, post) || post.Mode()&os.ModeSymlink != 0 || int64(len(data)) != expectedBytes {
		return nil, fmt.Errorf("machine descriptor changed while it was read")
	}
	digest := sha256.Sum256(data)
	encodedDigest := hex.EncodeToString(digest[:])
	if encodedDigest != expectedSHA256 {
		return nil, fmt.Errorf("machine descriptor SHA-256 does not match its pin")
	}
	descriptor, err := Decode(data)
	if err != nil {
		return nil, err
	}
	actual, err := Probe()
	if err != nil {
		return nil, err
	}
	if err := Match(descriptor, actual); err != nil {
		return nil, err
	}
	return &Evidence{Descriptor: descriptor, SHA256: encodedDigest, Bytes: uint64(len(data)), Probe: actual}, nil
}

func NewDescriptor(id, classification, evidenceSource string, identity Identity) (*Descriptor, error) {
	descriptor := &Descriptor{
		SchemaVersion: SchemaVersion, ID: id, Identity: identity,
		Classification: classification, ClassificationEvidenceSource: normalize(evidenceSource),
	}
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	return descriptor, nil
}

func normalize(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(strings.Trim(value, "\x00"))), " ")
}

func canonicalSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
