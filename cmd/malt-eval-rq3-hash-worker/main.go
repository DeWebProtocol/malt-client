// Command malt-eval-rq3-hash-worker exposes the malt-client UnixFS/HAMT
// baseline primitive as strict, bounded JSONL over stdin/stdout.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"unicode/utf8"

	"github.com/dewebprotocol/malt-client/merkledag/rq3baseline"
)

const (
	maxJSONLRecordBytes = rq3baseline.MaximumJSONLRecordBytes
	maxWorkerRequests   = 4_096
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("malt-eval-rq3-hash-worker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selfTestCorpus := flags.String("self-test-corpus", "", "formal E0 hash-adapter corpus")
	var boundWorkloads, gitExecutables repeatedPathFlag
	flags.Var(&boundWorkloads, "bound-workload", "production RQ3 workload artifact bound by formal E0 (repeatable)")
	flags.Var(&gitExecutables, "git-executable", "production Git executable bound by formal E0 (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("malt-eval-rq3-hash-worker accepts no positional arguments")
	}
	if *selfTestCorpus != "" {
		return runHashAdapterSelfTest(ctx, *selfTestCorpus, boundWorkloads, gitExecutables, output)
	}
	if len(arguments) != 0 {
		return fmt.Errorf("normal hash-worker mode accepts no command-line arguments")
	}
	return runWorker(ctx, input, output)
}

func runWorker(ctx context.Context, input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), maxJSONLRecordBytes)
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	requests := 0
	for scanner.Scan() {
		requests++
		if requests > maxWorkerRequests {
			return fmt.Errorf("RQ3 hash worker exceeds %d-request process limit", maxWorkerRequests)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		response := handleLine(ctx, scanner.Bytes())
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("encode worker response: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read JSONL request (maximum record %d bytes): %w", maxJSONLRecordBytes, err)
	}
	return nil
}

func handleLine(ctx context.Context, line []byte) rq3baseline.WorkerResponse {
	request, err := decodeRequest(line)
	if err != nil {
		return errorResponse("", "invalid_request", err, "")
	}
	if err := validateEnvelope(request); err != nil {
		return errorResponse(request.RequestID, "invalid_request", err, "")
	}
	switch request.Operation {
	case rq3baseline.OperationCapabilities:
		capability := rq3baseline.Capability()
		return rq3baseline.WorkerResponse{
			SchemaVersion: rq3baseline.WorkerResponseSchema,
			RequestID:     request.RequestID,
			OK:            true,
			Capability:    &capability,
		}
	case rq3baseline.OperationRun:
		result, err := rq3baseline.Run(ctx, *request.Run)
		if err != nil {
			var unsupported *rq3baseline.UnsupportedError
			if errors.As(err, &unsupported) {
				return errorResponse(request.RequestID, "unsupported_capability", err, unsupported.Gap)
			}
			return errorResponse(request.RequestID, "invalid_or_failed_run", err, "")
		}
		return rq3baseline.WorkerResponse{
			SchemaVersion: rq3baseline.WorkerResponseSchema,
			RequestID:     request.RequestID,
			OK:            true,
			Result:        result,
		}
	default:
		panic("validated operation is not handled")
	}
}

func decodeRequest(line []byte) (rq3baseline.WorkerRequest, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return rq3baseline.WorkerRequest{}, fmt.Errorf("JSONL record is empty")
	}
	if err := rejectDuplicateKeys(line); err != nil {
		return rq3baseline.WorkerRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var request rq3baseline.WorkerRequest
	if err := decoder.Decode(&request); err != nil {
		return rq3baseline.WorkerRequest{}, fmt.Errorf("decode strict worker request: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return rq3baseline.WorkerRequest{}, fmt.Errorf("worker request contains a trailing JSON value")
		}
		return rq3baseline.WorkerRequest{}, fmt.Errorf("decode worker request trailer: %w", err)
	}
	return request, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	// Only inspect the first value here. The strict typed decoder below owns
	// unknown-field and trailing-value diagnostics; this pass exists solely to
	// close encoding/json's otherwise last-key-wins duplicate-key behavior.
	return scanJSONValue(decoder, "$")
}

func scanJSONValue(decoder *json.Decoder, location string) error {
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
				return fmt.Errorf("%s has a non-string object key", location)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q at %s", key, location)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, location+"."+key); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", location, index)); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, location)
	}
}

func validateEnvelope(request rq3baseline.WorkerRequest) error {
	if request.SchemaVersion != rq3baseline.WorkerRequestSchema {
		return fmt.Errorf("schema_version must be %q", rq3baseline.WorkerRequestSchema)
	}
	if strings.TrimSpace(request.RequestID) != request.RequestID || request.RequestID == "" || len(request.RequestID) > 256 || !utf8.ValidString(request.RequestID) {
		return fmt.Errorf("request_id must be a non-empty bounded canonical string")
	}
	for _, r := range request.RequestID {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("request_id contains a control character")
		}
	}
	switch request.Operation {
	case rq3baseline.OperationCapabilities:
		if request.Run != nil {
			return fmt.Errorf("capabilities request must not include run")
		}
	case rq3baseline.OperationRun:
		if request.Run == nil {
			return fmt.Errorf("run request must include run")
		}
	default:
		return fmt.Errorf("unsupported operation %q", request.Operation)
	}
	return nil
}

func errorResponse(requestID, code string, err error, gap string) rq3baseline.WorkerResponse {
	return rq3baseline.WorkerResponse{
		SchemaVersion: rq3baseline.WorkerResponseSchema,
		RequestID:     requestID,
		OK:            false,
		Error: &rq3baseline.WorkerError{
			Code:          code,
			Message:       err.Error(),
			CapabilityGap: gap,
		},
	}
}
