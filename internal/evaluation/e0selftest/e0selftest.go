// Package e0selftest implements the cross-repository side of the evaluator's
// formal-E0 invocation/receipt contract. Evaluation commands use it only when
// the reserved invocation environment is present; normal product paths never
// depend on this package.
package e0selftest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const (
	InvocationEnvironment = "MALT_EVAL_E0_SELF_TEST_INVOCATION"
	InvocationSchema      = "malt-eval-e0-self-test-invocation/v1"
	ReceiptSchema         = "malt-eval-e0-self-test-receipt/v1"
	maximumInvocationSize = 1 << 20
)

var (
	idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Profile struct {
	ProfileID     string   `json:"profile_id"`
	PositiveCases []string `json:"positive_cases"`
	HostileCases  []string `json:"hostile_cases"`
}

type Contract struct {
	ProfileID     string `json:"profile_id"`
	ProfileSHA256 string `json:"profile_sha256"`
	PositiveCases uint32 `json:"positive_cases"`
	HostileCases  uint32 `json:"hostile_cases"`
}

type CaseResult struct {
	ID     string
	Passed bool
}

type Counts struct {
	Expected uint32 `json:"expected"`
	Executed uint32 `json:"executed"`
	Passed   uint32 `json:"passed"`
}

type TestedFilePin struct {
	FileID string `json:"file_id"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type Receipt struct {
	SchemaVersion    string          `json:"schema_version"`
	CapabilityID     string          `json:"capability_id"`
	ProfileID        string          `json:"profile_id"`
	ProfileSHA256    string          `json:"profile_sha256"`
	CorpusSHA256     string          `json:"corpus_sha256"`
	Positive         Counts          `json:"positive"`
	Hostile          Counts          `json:"hostile"`
	TestedExecutable TestedFilePin   `json:"tested_executable"`
	TestedInputs     []TestedFilePin `json:"tested_inputs"`
}

type invocation struct {
	SchemaVersion string           `json:"schema_version"`
	CapabilityID  string           `json:"capability_id"`
	Contract      Contract         `json:"contract"`
	CorpusSHA256  string           `json:"corpus_sha256"`
	Executable    invocationFile   `json:"executable"`
	Inputs        []invocationFile `json:"inputs"`
}

type invocationFile struct {
	FileID string `json:"file_id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type InputFile struct {
	FileID string
	Path   string
}

// InputPaths returns the exact canonical input paths in the evaluator-authored
// invocation. Self-test commands use it to prove that their typed file flags
// consume the complete argument set, rather than relying on Issue to bind
// inputs they never opened or interpreted.
func InputPaths() ([]string, error) {
	invocation, err := readInvocation()
	if err != nil {
		return nil, err
	}
	paths := make([]string, len(invocation.Inputs))
	for index, input := range invocation.Inputs {
		paths[index] = input.Path
	}
	slices.Sort(paths)
	return paths, nil
}

// Issue verifies the evaluator-authored invocation, the compiled capability
// and profile, every executed case, the running binary, and every file input.
// It returns no receipt if any positive or hostile case is missing or fails.
func Issue(expectedCapabilityID string, profile Profile, results []CaseResult) (Receipt, error) {
	if !idPattern.MatchString(expectedCapabilityID) {
		return Receipt{}, fmt.Errorf("invalid compiled self-test capability ID %q", expectedCapabilityID)
	}
	profileContract, err := profile.Contract()
	if err != nil {
		return Receipt{}, err
	}
	invocation, err := readInvocation()
	if err != nil {
		return Receipt{}, err
	}
	if invocation.CapabilityID != expectedCapabilityID {
		return Receipt{}, fmt.Errorf("compiled self-test capability %q does not match E0 invocation %q", expectedCapabilityID, invocation.CapabilityID)
	}
	if invocation.Contract != profileContract {
		return Receipt{}, fmt.Errorf("compiled self-test profile %+v does not match E0 contract %+v", profileContract, invocation.Contract)
	}
	positive, hostile, err := countCases(profile, results)
	if err != nil {
		return Receipt{}, err
	}
	executable, err := describeExecutable(invocation.Executable)
	if err != nil {
		return Receipt{}, err
	}
	inputs := make([]TestedFilePin, len(invocation.Inputs))
	for index, input := range invocation.Inputs {
		pin, err := describeInvocationFile(input)
		if err != nil {
			return Receipt{}, fmt.Errorf("self-test input %q: %w", input.FileID, err)
		}
		inputs[index] = pin
	}
	slices.SortFunc(inputs, func(left, right TestedFilePin) int { return strings.Compare(left.FileID, right.FileID) })
	receipt := Receipt{
		SchemaVersion: ReceiptSchema, CapabilityID: expectedCapabilityID,
		ProfileID: profileContract.ProfileID, ProfileSHA256: profileContract.ProfileSHA256,
		CorpusSHA256: invocation.CorpusSHA256, Positive: positive, Hostile: hostile,
		TestedExecutable: executable, TestedInputs: inputs,
	}
	if err := receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func (p Profile) Contract() (Contract, error) {
	if !idPattern.MatchString(p.ProfileID) {
		return Contract{}, fmt.Errorf("invalid self-test profile ID %q", p.ProfileID)
	}
	if err := validateCaseIDs("positive", p.PositiveCases); err != nil {
		return Contract{}, err
	}
	if err := validateCaseIDs("hostile", p.HostileCases); err != nil {
		return Contract{}, err
	}
	seen := make(map[string]struct{}, len(p.PositiveCases)+len(p.HostileCases))
	for _, id := range append(append([]string(nil), p.PositiveCases...), p.HostileCases...) {
		if _, duplicate := seen[id]; duplicate {
			return Contract{}, fmt.Errorf("self-test case %q appears in both profiles or repeats", id)
		}
		seen[id] = struct{}{}
	}
	digest, err := canonicalDigest(p)
	if err != nil {
		return Contract{}, err
	}
	return Contract{ProfileID: p.ProfileID, ProfileSHA256: digest, PositiveCases: uint32(len(p.PositiveCases)), HostileCases: uint32(len(p.HostileCases))}, nil
}

func (r Receipt) Validate() error {
	if r.SchemaVersion != ReceiptSchema || !idPattern.MatchString(r.CapabilityID) || !idPattern.MatchString(r.ProfileID) || !hex64.MatchString(r.ProfileSHA256) || !hex64.MatchString(r.CorpusSHA256) {
		return errors.New("invalid E0 self-test receipt identity")
	}
	if err := validateCounts("positive", r.Positive); err != nil {
		return err
	}
	if err := validateCounts("hostile", r.Hostile); err != nil {
		return err
	}
	if err := r.TestedExecutable.validate(); err != nil {
		return fmt.Errorf("invalid tested executable: %w", err)
	}
	if len(r.TestedInputs) == 0 {
		return errors.New("self-test receipt must bind at least one input")
	}
	for index, input := range r.TestedInputs {
		if err := input.validate(); err != nil {
			return fmt.Errorf("invalid tested input: %w", err)
		}
		if input.FileID == r.TestedExecutable.FileID {
			return errors.New("self-test receipt repeats executable as an input")
		}
		if index > 0 && r.TestedInputs[index-1].FileID >= input.FileID {
			return errors.New("self-test receipt inputs must be canonical sorted unique file IDs")
		}
	}
	return nil
}

// BuildInvocationEnvironment is a test/interop helper. It derives all digests
// from live files and returns the exact reserved environment value used by the
// evaluator; callers cannot provide claimed file hashes.
func BuildInvocationEnvironment(capabilityID string, profile Profile, executable InputFile, inputs []InputFile, corpusFileIDs []string) (string, error) {
	contract, err := profile.Contract()
	if err != nil {
		return "", err
	}
	executablePin, err := describeInputFile(executable)
	if err != nil {
		return "", err
	}
	inputPins := make([]invocationFile, len(inputs))
	byID := make(map[string]invocationFile, len(inputs))
	for index, input := range inputs {
		pin, err := describeInputFile(input)
		if err != nil {
			return "", err
		}
		if _, duplicate := byID[pin.FileID]; duplicate {
			return "", fmt.Errorf("repeated self-test input file %q", pin.FileID)
		}
		byID[pin.FileID] = pin
		inputPins[index] = pin
	}
	slices.SortFunc(inputPins, func(left, right invocationFile) int { return strings.Compare(left.FileID, right.FileID) })
	corpusPins := make([]TestedFilePin, len(corpusFileIDs))
	seenCorpus := make(map[string]struct{}, len(corpusFileIDs))
	for index, id := range corpusFileIDs {
		pin, exists := byID[id]
		if !exists {
			return "", fmt.Errorf("corpus file %q is not a self-test input", id)
		}
		if _, duplicate := seenCorpus[id]; duplicate {
			return "", fmt.Errorf("repeated self-test corpus file %q", id)
		}
		seenCorpus[id] = struct{}{}
		corpusPins[index] = TestedFilePin{FileID: pin.FileID, SHA256: pin.SHA256, Bytes: pin.Bytes}
	}
	if len(corpusPins) == 0 {
		return "", errors.New("self-test corpus set is empty")
	}
	slices.SortFunc(corpusPins, func(left, right TestedFilePin) int { return strings.Compare(left.FileID, right.FileID) })
	corpusDigest, err := canonicalDigest(corpusPins)
	if err != nil {
		return "", err
	}
	invocation := invocation{
		SchemaVersion: InvocationSchema, CapabilityID: capabilityID, Contract: contract, CorpusSHA256: corpusDigest,
		Executable: executablePin, Inputs: inputPins,
	}
	if err := invocation.validate(); err != nil {
		return "", err
	}
	encoded, err := marshalCanonical(invocation)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func readInvocation() (invocation, error) {
	raw := os.Getenv(InvocationEnvironment)
	if raw == "" {
		return invocation{}, fmt.Errorf("%s is required for a formal E0 self-test", InvocationEnvironment)
	}
	if len(raw) > maximumInvocationSize {
		return invocation{}, errors.New("E0 self-test invocation exceeds the bounded profile")
	}
	var value invocation
	if err := decodeStrict([]byte(raw), &value); err != nil {
		return invocation{}, fmt.Errorf("decode E0 self-test invocation: %w", err)
	}
	if err := value.validate(); err != nil {
		return invocation{}, err
	}
	return value, nil
}

func (i invocation) validate() error {
	if i.SchemaVersion != InvocationSchema || !idPattern.MatchString(i.CapabilityID) || !hex64.MatchString(i.CorpusSHA256) {
		return errors.New("invalid E0 self-test invocation identity")
	}
	if err := i.Contract.validate(); err != nil {
		return err
	}
	if err := i.Executable.validate(); err != nil {
		return fmt.Errorf("invalid E0 self-test executable: %w", err)
	}
	if len(i.Inputs) == 0 {
		return errors.New("E0 external self-test invocation requires input pins")
	}
	for index, input := range i.Inputs {
		if err := input.validate(); err != nil {
			return fmt.Errorf("invalid E0 self-test input: %w", err)
		}
		if input.FileID == i.Executable.FileID {
			return errors.New("E0 self-test invocation repeats executable as an input")
		}
		if index > 0 && i.Inputs[index-1].FileID >= input.FileID {
			return errors.New("E0 self-test inputs must be canonical sorted unique file IDs")
		}
	}
	return nil
}

func (c Contract) validate() error {
	if !idPattern.MatchString(c.ProfileID) || !hex64.MatchString(c.ProfileSHA256) || c.PositiveCases == 0 || c.HostileCases == 0 {
		return errors.New("self-test contract requires a canonical profile, digest, and nonzero positive/hostile counts")
	}
	return nil
}

func (f invocationFile) validate() error {
	if !idPattern.MatchString(f.FileID) || !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path || !hex64.MatchString(f.SHA256) || f.Bytes < 0 {
		return fmt.Errorf("invalid invocation file %q", f.FileID)
	}
	return nil
}

func (f TestedFilePin) validate() error {
	if !idPattern.MatchString(f.FileID) || !hex64.MatchString(f.SHA256) || f.Bytes < 0 {
		return fmt.Errorf("invalid tested file %q", f.FileID)
	}
	return nil
}

func validateCounts(label string, counts Counts) error {
	if counts.Expected == 0 || counts.Executed != counts.Expected || counts.Passed != counts.Expected {
		return fmt.Errorf("self-test %s counts must be nonzero and satisfy expected=executed=passed", label)
	}
	return nil
}

func validateCaseIDs(label string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("self-test %s profile must contain at least one case", label)
	}
	seen := make(map[string]struct{}, len(values))
	for _, id := range values {
		if !idPattern.MatchString(id) {
			return fmt.Errorf("invalid self-test %s case ID %q", label, id)
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("repeated self-test %s case ID %q", label, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func countCases(profile Profile, results []CaseResult) (Counts, Counts, error) {
	positiveIDs := make(map[string]struct{}, len(profile.PositiveCases))
	hostileIDs := make(map[string]struct{}, len(profile.HostileCases))
	for _, id := range profile.PositiveCases {
		positiveIDs[id] = struct{}{}
	}
	for _, id := range profile.HostileCases {
		hostileIDs[id] = struct{}{}
	}
	positive := Counts{Expected: uint32(len(profile.PositiveCases))}
	hostile := Counts{Expected: uint32(len(profile.HostileCases))}
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		if _, duplicate := seen[result.ID]; duplicate {
			return Counts{}, Counts{}, fmt.Errorf("self-test case %q executed more than once", result.ID)
		}
		seen[result.ID] = struct{}{}
		switch {
		case contains(positiveIDs, result.ID):
			positive.Executed++
			if result.Passed {
				positive.Passed++
			}
		case contains(hostileIDs, result.ID):
			hostile.Executed++
			if result.Passed {
				hostile.Passed++
			}
		default:
			return Counts{}, Counts{}, fmt.Errorf("self-test executed unknown case %q", result.ID)
		}
	}
	if positive.Executed != positive.Expected || hostile.Executed != hostile.Expected {
		return Counts{}, Counts{}, fmt.Errorf("self-test executed positive=%d/%d hostile=%d/%d", positive.Executed, positive.Expected, hostile.Executed, hostile.Expected)
	}
	if positive.Passed != positive.Expected || hostile.Passed != hostile.Expected {
		return Counts{}, Counts{}, fmt.Errorf("self-test passed positive=%d/%d hostile=%d/%d", positive.Passed, positive.Expected, hostile.Passed, hostile.Expected)
	}
	return positive, hostile, nil
}

func contains(values map[string]struct{}, id string) bool {
	_, ok := values[id]
	return ok
}

func describeExecutable(expected invocationFile) (TestedFilePin, error) {
	path, err := os.Executable()
	if err != nil {
		return TestedFilePin{}, fmt.Errorf("locate self-test executable: %w", err)
	}
	actualInfo, err := os.Stat(path)
	if err != nil {
		return TestedFilePin{}, fmt.Errorf("inspect running self-test executable: %w", err)
	}
	expectedInfo, err := os.Stat(expected.Path)
	if err != nil {
		return TestedFilePin{}, fmt.Errorf("inspect E0 executable pin: %w", err)
	}
	if !os.SameFile(actualInfo, expectedInfo) {
		return TestedFilePin{}, errors.New("running self-test executable is not the E0-pinned file")
	}
	return describeInvocationFile(expected)
}

func describeInputFile(file InputFile) (invocationFile, error) {
	if !idPattern.MatchString(file.FileID) || !filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path {
		return invocationFile{}, fmt.Errorf("invalid self-test input file %q", file.FileID)
	}
	digest, size, err := describeRegularFile(file.Path)
	if err != nil {
		return invocationFile{}, err
	}
	return invocationFile{FileID: file.FileID, Path: file.Path, SHA256: digest, Bytes: size}, nil
}

func describeInvocationFile(expected invocationFile) (TestedFilePin, error) {
	digest, size, err := describeRegularFile(expected.Path)
	if err != nil {
		return TestedFilePin{}, err
	}
	if digest != expected.SHA256 || size != expected.Bytes {
		return TestedFilePin{}, fmt.Errorf("live descriptor %s/%d does not match E0 pin %s/%d", digest, size, expected.SHA256, expected.Bytes)
	}
	return TestedFilePin{FileID: expected.FileID, SHA256: digest, Bytes: size}, nil
}

func describeRegularFile(path string) (string, int64, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", 0, errors.New("self-test file path must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", 0, errors.New("self-test file must be a regular non-symlink")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", 0, err
	}
	if resolved != path {
		return "", 0, errors.New("self-test file or one of its parents is symlinked")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return "", 0, errors.New("self-test file changed while opening")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	if written != opened.Size() {
		return "", 0, errors.New("self-test file size changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

func canonicalDigest(value any) (string, error) {
	encoded, err := marshalCanonical(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func marshalCanonical(value any) ([]byte, error) {
	var initial bytes.Buffer
	encoder := json.NewEncoder(&initial)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSuffix(initial.Bytes(), []byte{'\n'})))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	encoder = json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func decodeStrict(data []byte, target any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("top-level JSON value must be an object")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanValue(decoder, "$"); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func scanValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key at %s is not a string", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := scanValue(decoder, path+"."+key); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object closing delimiter")
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := scanValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array closing delimiter")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}
