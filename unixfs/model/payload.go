package unixfs

import (
	"errors"
	"fmt"
	"io"
)

// PayloadChunks splits payload bytes according to the UnixFS chunking policy.
func PayloadChunks(data []byte, chunkSize int) ([][]byte, error) {
	if chunkSize <= 0 {
		return nil, fmt.Errorf("chunk size must be positive")
	}
	chunks := make([][]byte, 0, (len(data)+chunkSize-1)/chunkSize)
	for start := 0; start < len(data); start += chunkSize {
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, append([]byte(nil), data[start:end]...))
	}
	return chunks, nil
}

// StreamPayloadChunks reads payload chunks from r according to the UnixFS
// layout chunk size and calls emit with an owned byte slice for each chunk.
func StreamPayloadChunks(r io.Reader, chunkSize int, emit func([]byte) error) error {
	if chunkSize <= 0 {
		return fmt.Errorf("chunk size must be positive")
	}
	if emit == nil {
		return fmt.Errorf("emit is nil")
	}
	buf := make([]byte, chunkSize)
	for {
		n, readErr := io.ReadFull(r, buf)
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return readErr
		}
		if n > 0 {
			if err := emit(append([]byte(nil), buf[:n]...)); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
			return nil
		}
	}
}
