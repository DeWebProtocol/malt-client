// Package daemon exposes the trusted client's local control plane. It listens
// on a user-owned Unix socket and never exposes a remote verification service.
package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dewebprotocol/malt-client/internal/truststore"
)

type Server struct {
	store *truststore.Store
	mux   *http.ServeMux
}

func New(store *truststore.Store) (*Server, error) {
	if store == nil {
		return nil, fmt.Errorf("trust store is nil")
	}
	s := &Server{store: store, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) Listen(socketPath string) (net.Listener, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, fmt.Errorf("daemon socket path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, err
	}
	if err := removeStaleSocket(socketPath); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "role": "trusted-client"})
	})
	s.mux.HandleFunc("GET /v1/roots", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"roots": s.store.List()})
	})
	s.mux.HandleFunc("GET /v1/roots/{alias}", func(w http.ResponseWriter, r *http.Request) {
		record, err := s.store.Get(r.PathValue("alias"))
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, record)
	})
	s.mux.HandleFunc("PUT /v1/roots/{alias}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Root    string `json:"root"`
			Profile string `json:"profile"`
			Gateway string `json:"gateway"`
			Source  string `json:"source"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		record, err := s.store.Trust(r.PathValue("alias"), body.Root, body.Profile, body.Gateway, body.Source)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, record)
	})
	s.mux.HandleFunc("POST /v1/roots/{alias}/candidates", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Root     string `json:"root"`
			BaseRoot string `json:"base_root"`
			Source   string `json:"source"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		record, err := s.store.AddCandidate(r.PathValue("alias"), body.Root, body.BaseRoot, body.Source)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, record)
	})
	s.mux.HandleFunc("POST /v1/roots/{alias}/candidates/{root}/accept", func(w http.ResponseWriter, r *http.Request) {
		record, err := s.store.AcceptCandidate(r.PathValue("alias"), r.PathValue("root"), "explicit-local-acceptance")
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, record)
	})
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %s", path)
	}
	return os.Remove(path)
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if len(data) > 1<<20 {
		return fmt.Errorf("request body exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode request: expected one JSON object")
	}
	return nil
}

func writeStoreError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, truststore.ErrNotFound) || errors.Is(err, truststore.ErrCandidateNotFound) {
		status = http.StatusNotFound
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
