package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6455 requires SHA-1 for the handshake accept value.
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	maxCDPMessageBytes = 16 << 20
	websocketGUID      = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

type websocketConn struct {
	connection net.Conn
	reader     *bufio.Reader
	writeMu    sync.Mutex
}

func dialWebsocket(ctx context.Context, rawURL string) (*websocketConn, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "ws" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid local DevTools websocket URL")
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", parsed.Host)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = connection.Close()
		}
	}()
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	request := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + parsed.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Origin: http://127.0.0.1\r\n\r\n"
	if _, err := io.WriteString(connection, request); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, err
	}
	acceptDigest := sha1.Sum([]byte(key + websocketGUID)) // #nosec G401 -- required by RFC 6455.
	wantAccept := base64.StdEncoding.EncodeToString(acceptDigest[:])
	if response.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") || response.Header.Get("Sec-WebSocket-Accept") != wantAccept {
		_ = response.Body.Close()
		return nil, fmt.Errorf("DevTools websocket handshake failed with %s", response.Status)
	}
	failed = false
	return &websocketConn{connection: connection, reader: reader}, nil
}

func (w *websocketConn) Close() error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	_ = w.writeFrame(0x8, nil)
	return w.connection.Close()
}

func (w *websocketConn) writeText(ctx context.Context, data []byte) error {
	if len(data) > maxCDPMessageBytes {
		return fmt.Errorf("DevTools command exceeds %d bytes", maxCDPMessageBytes)
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	cancellationDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = w.connection.SetWriteDeadline(time.Now())
		close(cancellationDone)
	})
	defer func() {
		if !stopCancellation() {
			<-cancellationDone
		}
		_ = w.connection.SetWriteDeadline(time.Time{})
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := w.connection.SetWriteDeadline(deadline); err != nil {
			return err
		}
	}
	if err := w.writeFrame(0x1, data); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

func (w *websocketConn) writeFrame(opcode byte, data []byte) error {
	header := []byte{0x80 | opcode}
	switch {
	case len(data) < 126:
		header = append(header, 0x80|byte(len(data)))
	case uint64(len(data)) <= uint64(^uint16(0)):
		header = append(header, 0x80|126, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(len(data)))
	default:
		header = append(header, 0x80|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[len(header)-8:], uint64(len(data)))
	}
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	header = append(header, mask...)
	masked := make([]byte, len(data))
	for index := range data {
		masked[index] = data[index] ^ mask[index%len(mask)]
	}
	if _, err := w.connection.Write(header); err != nil {
		return err
	}
	_, err := w.connection.Write(masked)
	return err
}

func (w *websocketConn) readText(ctx context.Context) ([]byte, error) {
	cancellationDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = w.connection.SetReadDeadline(time.Now())
		close(cancellationDone)
	})
	defer func() {
		if !stopCancellation() {
			<-cancellationDone
		}
		_ = w.connection.SetReadDeadline(time.Time{})
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := w.connection.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
	}
	var assembled []byte
	continuation := false
	for {
		first, err := w.reader.ReadByte()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		second, err := w.reader.ReadByte()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		final := first&0x80 != 0
		opcode := first & 0x0f
		if first&0x70 != 0 || second&0x80 != 0 {
			return nil, fmt.Errorf("invalid DevTools websocket frame")
		}
		length := uint64(second & 0x7f)
		switch length {
		case 126:
			var raw [2]byte
			if _, err := io.ReadFull(w.reader, raw[:]); err != nil {
				return nil, err
			}
			length = uint64(binary.BigEndian.Uint16(raw[:]))
		case 127:
			var raw [8]byte
			if _, err := io.ReadFull(w.reader, raw[:]); err != nil {
				return nil, err
			}
			length = binary.BigEndian.Uint64(raw[:])
		}
		if length > maxCDPMessageBytes || uint64(len(assembled))+length > maxCDPMessageBytes {
			return nil, fmt.Errorf("DevTools websocket message exceeds %d bytes", maxCDPMessageBytes)
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(w.reader, payload); err != nil {
			return nil, err
		}
		switch opcode {
		case 0x8:
			return nil, io.EOF
		case 0x9:
			w.writeMu.Lock()
			err := w.writeFrame(0xA, payload)
			w.writeMu.Unlock()
			if err != nil {
				return nil, err
			}
			continue
		case 0xA:
			continue
		case 0x1:
			if continuation {
				return nil, fmt.Errorf("unexpected DevTools text frame")
			}
			assembled = append(assembled, payload...)
			continuation = !final
		case 0x0:
			if !continuation {
				return nil, fmt.Errorf("unexpected DevTools continuation frame")
			}
			assembled = append(assembled, payload...)
			continuation = !final
		default:
			return nil, fmt.Errorf("unsupported DevTools websocket opcode %d", opcode)
		}
		if final {
			return assembled, nil
		}
	}
}

type cdpClient struct {
	websocket *websocketConn
	nextID    uint64
}

type cdpResponse struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func newCDPClient(ctx context.Context, websocketURL string) (*cdpClient, error) {
	connection, err := dialWebsocket(ctx, websocketURL)
	if err != nil {
		return nil, err
	}
	return &cdpClient{websocket: connection}, nil
}

func (c *cdpClient) Close() error { return c.websocket.Close() }

// forceClose skips the websocket close handshake and write mutex. It is used
// only after the owning Chromium process has received a non-graceful kill, so
// a stuck writer cannot delay fail-closed session termination.
func (c *cdpClient) forceClose() error { return c.websocket.connection.Close() }

func (c *cdpClient) call(ctx context.Context, method string, params any, result any) error {
	c.nextID++
	id := c.nextID
	command, err := json.Marshal(struct {
		ID     uint64 `json:"id"`
		Method string `json:"method"`
		Params any    `json:"params,omitempty"`
	}{ID: id, Method: method, Params: params})
	if err != nil {
		return err
	}
	if err := c.websocket.writeText(ctx, command); err != nil {
		return err
	}
	for {
		message, err := c.websocket.readText(ctx)
		if err != nil {
			return err
		}
		var response cdpResponse
		if err := json.Unmarshal(message, &response); err != nil {
			return err
		}
		if response.ID != id {
			continue
		}
		if response.Error != nil {
			return fmt.Errorf("DevTools %s failed (%d): %s", method, response.Error.Code, response.Error.Message)
		}
		if result == nil {
			return nil
		}
		if len(response.Result) == 0 {
			return errors.New("DevTools response omitted result")
		}
		return json.Unmarshal(response.Result, result)
	}
}

type runtimeEvaluateResult struct {
	Result struct {
		Type        string          `json:"type"`
		Value       json.RawMessage `json:"value"`
		Description string          `json:"description"`
	} `json:"result"`
	ExceptionDetails json.RawMessage `json:"exceptionDetails"`
}

func (c *cdpClient) evaluateString(ctx context.Context, expression string, await bool) (string, error) {
	var result runtimeEvaluateResult
	err := c.call(ctx, "Runtime.evaluate", map[string]any{
		"expression": expression, "awaitPromise": await, "returnByValue": true,
	}, &result)
	if err != nil {
		return "", err
	}
	if len(result.ExceptionDetails) != 0 {
		return "", fmt.Errorf("browser JavaScript exception: %s", string(result.ExceptionDetails))
	}
	if result.Result.Type != "string" {
		return "", fmt.Errorf("browser expression returned %q, want string", result.Result.Type)
	}
	var value string
	if err := json.Unmarshal(result.Result.Value, &value); err != nil {
		return "", err
	}
	return value, nil
}

func (c *cdpClient) taskDuration(ctx context.Context) (float64, error) {
	var response struct {
		Metrics []struct {
			Name  string  `json:"name"`
			Value float64 `json:"value"`
		} `json:"metrics"`
	}
	if err := c.call(ctx, "Performance.getMetrics", map[string]any{}, &response); err != nil {
		return 0, err
	}
	for _, metric := range response.Metrics {
		if metric.Name == "TaskDuration" {
			return metric.Value, nil
		}
	}
	return 0, fmt.Errorf("Chromium omitted Performance.TaskDuration")
}
