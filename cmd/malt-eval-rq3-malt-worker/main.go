// Command malt-eval-rq3-malt-worker executes the paper RQ3 MALT-KZG hybrid
// write path against one disposable, token-bound Gateway.
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
	"time"
	"unicode/utf8"
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
	if hasMALTSelfTestFlag(arguments) {
		config, err := parseMALTSelfTestFlags(arguments)
		if err != nil {
			return err
		}
		return runMALTAdapterSelfTest(ctx, config, output)
	}
	config, err := parseFlags(arguments)
	if err != nil {
		return err
	}
	worker, err := newCampaignWorker(config)
	if err != nil {
		return err
	}
	return runWorker(ctx, input, output, worker)
}

func parseFlags(arguments []string) (workerConfig, error) {
	flags := flag.NewFlagSet("malt-eval-rq3-malt-worker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	baseURL := flags.String("gateway-base-url", "", "disposable Gateway base URL")
	token := flags.String("gateway-instance-token", "", "disposable Gateway instance token")
	bootstrapAuthorizationToken := flags.String("gateway-bootstrap-authorization-token", "", "secret disposable Gateway bootstrap capability")
	timeout := flags.Duration("request-timeout", 0, "per-request Gateway timeout")
	initialRoot := flags.String("initial-root", "", "externally supplied initial root (unsupported for fair snapshot accounting)")
	if err := flags.Parse(arguments); err != nil {
		return workerConfig{}, err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*baseURL) != *baseURL || *baseURL == "" ||
		!canonicalSHA256(*token) || !canonicalSHA256(*bootstrapAuthorizationToken) || *bootstrapAuthorizationToken == *token ||
		*timeout <= 0 || *timeout > 24*time.Hour || strings.TrimSpace(*initialRoot) != *initialRoot {
		return workerConfig{}, fmt.Errorf("required flags are -gateway-base-url, canonical and distinct -gateway-instance-token/-gateway-bootstrap-authorization-token, and positive -request-timeout")
	}
	return workerConfig{
		gatewayBaseURL: *baseURL, instanceToken: *token, bootstrapAuthorizationToken: *bootstrapAuthorizationToken,
		requestTimeout: *timeout, initialRoot: *initialRoot,
	}, nil
}

func runWorker(ctx context.Context, input io.Reader, output io.Writer, worker *campaignWorker) error {
	if worker == nil {
		return fmt.Errorf("RQ3 MALT worker is nil")
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), maxWorkerLineBytes)
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	requests := 0
	capabilityPassed := false
	for scanner.Scan() {
		requests++
		if requests > maxWorkerRequests {
			return fmt.Errorf("RQ3 MALT worker accepts exactly two request records")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		request, err := decodeWorkerRequest(scanner.Bytes())
		var response workerResponse
		if err != nil {
			response = failedResponse("", "invalid_request", err)
		} else if err := validateRequestEnvelope(request, requests, capabilityPassed); err != nil {
			response = failedResponse(request.RequestID, "invalid_request", err)
		} else if request.Operation == "capabilities" {
			capability := supportedCapability()
			if err := worker.validateHealth(ctx); err != nil {
				capability.Supported = false
				capability.MissingCategories = []string{"exact-gateway-boundary"}
				capability.MissingMetrics = []string{"gateway-health-preflight"}
				response = failedResponse(request.RequestID, "capability_unavailable", err)
				response.Capability = &capability
			} else {
				capabilityPassed = true
				response = workerResponse{
					SchemaVersion: workerResponseSchema, RequestID: request.RequestID, OK: true, Capability: &capability,
				}
			}
		} else {
			result, err := worker.run(ctx, *request.Run)
			if err != nil {
				response = failedResponse(request.RequestID, "invalid_or_failed_run", err)
			} else {
				response = workerResponse{
					SchemaVersion: workerResponseSchema, RequestID: request.RequestID, OK: true, Result: result,
				}
			}
		}
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("encode worker response: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read bounded worker JSONL: %w", err)
	}
	if requests != maxWorkerRequests {
		return fmt.Errorf("RQ3 MALT worker received %d request records, want exactly two", requests)
	}
	return nil
}

func decodeWorkerRequest(line []byte) (workerRequest, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return workerRequest{}, fmt.Errorf("JSONL record is empty")
	}
	if err := rejectDuplicateKeys(line); err != nil {
		return workerRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var request workerRequest
	if err := decoder.Decode(&request); err != nil {
		return workerRequest{}, fmt.Errorf("decode strict worker request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return workerRequest{}, fmt.Errorf("worker request contains trailing JSON")
		}
		return workerRequest{}, fmt.Errorf("decode worker request trailer: %w", err)
	}
	return request, nil
}

func validateRequestEnvelope(request workerRequest, sequence int, capabilityPassed bool) error {
	if request.SchemaVersion != workerRequestSchema {
		return fmt.Errorf("schema_version must be %q", workerRequestSchema)
	}
	if request.RequestID == "" || len(request.RequestID) > 256 || strings.TrimSpace(request.RequestID) != request.RequestID || !utf8.ValidString(request.RequestID) {
		return fmt.Errorf("request_id must be a bounded canonical string")
	}
	for _, character := range request.RequestID {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("request_id contains a control character")
		}
	}
	switch request.Operation {
	case "capabilities":
		if sequence != 1 || request.Run != nil {
			return fmt.Errorf("capabilities must be the first request and omit run")
		}
	case "run":
		if sequence != 2 || !capabilityPassed || request.Run == nil {
			return fmt.Errorf("run must follow a successful capability preflight and include run")
		}
	default:
		return fmt.Errorf("unsupported operation %q", request.Operation)
	}
	return nil
}

func failedResponse(requestID, code string, err error) workerResponse {
	return workerResponse{
		SchemaVersion: workerResponseSchema, RequestID: requestID, OK: false,
		Error: &workerError{Code: code, Message: err.Error()},
	}
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, "$"); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing token %v", token)
		}
		return err
	}
	return nil
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
		index := 0
		for decoder.More() {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", location, index)); err != nil {
				return err
			}
			index++
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}
