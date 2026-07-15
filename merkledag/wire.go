package merkledag

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type merkleDAGResolveWire struct {
	Profile string                 `json:"profile"`
	Target  string                 `json:"target"`
	Kind    string                 `json:"kind"`
	Blocks  boundedMerkleDAGBlocks `json:"blocks"`
}

type merkleDAGReadWire struct {
	Profile   string                   `json:"profile"`
	Target    string                   `json:"target"`
	Kind      string                   `json:"kind"`
	TotalSize uint64                   `json:"total_size"`
	Offset    uint64                   `json:"offset"`
	Length    uint64                   `json:"length"`
	Data      boundedMerkleDAGReadData `json:"data"`
	Blocks    boundedMerkleDAGBlocks   `json:"blocks"`
}

type boundedMerkleDAGBlocks []MerkleDAGBlock

type boundedMerkleDAGReadData []byte

func (c *Client) doMerkleDAG(ctx context.Context, route string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode gateway Merkle-DAG JSON request: %w", err)
	}
	var data []byte
	switch route {
	case "/v1/compat/merkledag/resolve":
		data, err = c.transport.PostMerkleDAGResolve(ctx, body)
	case "/v1/compat/merkledag/read":
		data, err = c.transport.PostMerkleDAGRead(ctx, body)
	default:
		return fmt.Errorf("unsupported Merkle-DAG profile route %q", route)
	}
	if err != nil {
		return err
	}
	switch out := response.(type) {
	case *MerkleDAGResolveResponse:
		var wire merkleDAGResolveWire
		if err := decodeStrictMerkleDAGJSON(data, &wire); err != nil {
			return err
		}
		*out = MerkleDAGResolveResponse{Profile: wire.Profile, Target: wire.Target, Kind: wire.Kind, Blocks: []MerkleDAGBlock(wire.Blocks)}
	case *MerkleDAGReadResponse:
		var wire merkleDAGReadWire
		if err := decodeStrictMerkleDAGJSON(data, &wire); err != nil {
			return err
		}
		*out = MerkleDAGReadResponse{
			Profile: wire.Profile, Target: wire.Target, Kind: wire.Kind,
			TotalSize: wire.TotalSize, Offset: wire.Offset, Length: wire.Length,
			Data: []byte(wire.Data), Blocks: []MerkleDAGBlock(wire.Blocks),
		}
	default:
		return fmt.Errorf("unsupported Merkle-DAG response type %T", response)
	}
	return nil
}

func decodeStrictMerkleDAGJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode gateway Merkle-DAG JSON response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode gateway Merkle-DAG JSON response: expected one JSON object")
	}
	return nil
}

func (blocks *boundedMerkleDAGBlocks) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return fmt.Errorf("Merkle-DAG blocks must be an array")
	}
	result := make([]MerkleDAGBlock, 0, min(maxMerkleDAGEvidence, 64))
	totalBytes := 0
	for decoder.More() {
		if len(result) >= maxMerkleDAGEvidence {
			return fmt.Errorf("Merkle-DAG evidence exceeds %d-block profile limit", maxMerkleDAGEvidence)
		}
		var item struct {
			CID   string          `json:"cid"`
			Codec uint64          `json:"codec"`
			Data  json.RawMessage `json:"data"`
		}
		if err := decoder.Decode(&item); err != nil {
			return err
		}
		if len(item.Data) == 0 {
			return fmt.Errorf("Merkle-DAG evidence block data is required")
		}
		decoded, err := decodeBoundedBase64JSON(item.Data, maxMerkleDAGEvidenceRaw-totalBytes, "Merkle-DAG evidence")
		if err != nil {
			return err
		}
		totalBytes += len(decoded)
		result = append(result, MerkleDAGBlock{CID: item.CID, Codec: item.Codec, Data: decoded})
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("Merkle-DAG blocks contain trailing JSON")
	}
	*blocks = result
	return nil
}

func (data *boundedMerkleDAGReadData) UnmarshalJSON(raw []byte) error {
	decoded, err := decodeBoundedBase64JSON(raw, maxMerkleDAGReadBytes, "Merkle-DAG read data")
	if err != nil {
		return err
	}
	*data = decoded
	return nil
}

func decodeBoundedBase64JSON(raw []byte, limit int, description string) ([]byte, error) {
	if limit < 0 || bytes.Equal(raw, []byte("null")) {
		return nil, fmt.Errorf("%s exceeds its profile limit", description)
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf("%s must be a base64 JSON string: %w", description, err)
	}
	decodedLength := base64.StdEncoding.DecodedLen(len(encoded))
	if strings.HasSuffix(encoded, "==") {
		decodedLength -= 2
	} else if strings.HasSuffix(encoded, "=") {
		decodedLength--
	}
	if decodedLength > limit {
		return nil, fmt.Errorf("%s exceeds %d-byte profile limit", description, limit)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", description, err)
	}
	if len(decoded) > limit {
		return nil, fmt.Errorf("%s exceeds %d-byte profile limit", description, limit)
	}
	return decoded, nil
}

// ReadMerkleDAGVerified executes and locally replays a compatibility read.
