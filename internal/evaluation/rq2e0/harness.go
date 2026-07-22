package rq2e0

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const maximumWorkerLine = 1 << 20

// Harness runs the production worker function over its real JSONL process
// boundary while allowing a formal self-test to advance the accepted root one
// response at a time.
type Harness struct {
	input   *io.PipeWriter
	lines   <-chan harnessLine
	done    <-chan error
	timeout time.Duration
	once    sync.Once
}

type harnessLine struct {
	data []byte
	err  error
}

// StartHarness starts one production worker callback. The callback must use
// input/output exactly as its normal stdin/stdout path does.
func StartHarness(timeout time.Duration, run func(io.Reader, io.Writer) error) (*Harness, error) {
	if timeout <= 0 || timeout > 10*time.Minute || run == nil {
		return nil, errors.New("invalid RQ2 E0 worker harness")
	}
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := run(inputReader, outputWriter)
		_ = outputWriter.CloseWithError(err)
		_ = inputReader.CloseWithError(err)
		done <- err
	}()
	lines := make(chan harnessLine, 1)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(outputReader)
		scanner.Buffer(make([]byte, 64<<10), maximumWorkerLine)
		for scanner.Scan() {
			lines <- harnessLine{data: append([]byte(nil), scanner.Bytes()...)}
		}
		if err := scanner.Err(); err != nil {
			lines <- harnessLine{err: err}
		}
		_ = outputReader.Close()
	}()
	return &Harness{input: inputWriter, lines: lines, done: done, timeout: timeout}, nil
}

// Exchange sends one strict JSON object and decodes one strict JSON response.
func (h *Harness) Exchange(request, response any) error {
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if _, err := h.input.Write(append(encoded, '\n')); err != nil {
		return err
	}
	select {
	case line, ok := <-h.lines:
		if !ok {
			return errors.New("RQ2 E0 worker closed stdout before its response")
		}
		if line.err != nil {
			return line.err
		}
		decoder := json.NewDecoder(bytes.NewReader(line.data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(response); err != nil {
			return err
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return errors.New("RQ2 E0 worker response contains trailing JSON")
		}
		return nil
	case <-time.After(h.timeout):
		return errors.New("RQ2 E0 worker response timeout")
	}
}

// WriteRaw writes one raw JSONL request for malformed-input hostile cases.
func (h *Harness) WriteRaw(value []byte) error {
	if len(value) == 0 || bytes.IndexByte(value, '\n') >= 0 {
		return errors.New("invalid raw RQ2 E0 request")
	}
	_, err := h.input.Write(append(append([]byte(nil), value...), '\n'))
	return err
}

// WaitError closes stdin and requires the worker to fail. It is used only for
// hostile cases that are rejected before a valid response can be emitted.
func (h *Harness) WaitError() error {
	_ = h.input.Close()
	select {
	case err := <-h.done:
		h.once.Do(func() {})
		if err == nil {
			return errors.New("RQ2 E0 hostile worker unexpectedly succeeded")
		}
		return nil
	case <-time.After(h.timeout):
		h.Abort()
		return errors.New("RQ2 E0 hostile worker did not terminate")
	}
}

// Close completes a successful worker after its session-end response and
// rejects any trailing output.
func (h *Harness) Close() error {
	if h == nil || h.input == nil {
		return errors.New("RQ2 E0 worker harness is closed")
	}
	_ = h.input.Close()
	select {
	case err := <-h.done:
		h.input = nil
		h.once.Do(func() {})
		if err != nil {
			return err
		}
		for line := range h.lines {
			if line.err != nil {
				return line.err
			}
			return fmt.Errorf("RQ2 E0 worker emitted trailing output %q", line.data)
		}
		return nil
	case <-time.After(h.timeout):
		h.Abort()
		return errors.New("RQ2 E0 worker did not exit")
	}
}

// Abort stops an incomplete/hostile harness without claiming a successful
// production session.
func (h *Harness) Abort() {
	if h == nil {
		return
	}
	h.once.Do(func() {
		if h.input != nil {
			_ = h.input.CloseWithError(errors.New("formal E0 hostile abort"))
		}
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
		}
		h.input = nil
	})
}
