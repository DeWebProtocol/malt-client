// Package daemon exposes the trusted client's local control plane. It listens
// on a user-owned Unix socket or Windows named pipe and never exposes a remote
// verification service.
package daemon

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/dewebprotocol/malt-client/application"
	truststore "github.com/dewebprotocol/malt-client/trust"
	cid "github.com/ipfs/go-cid"
)

const lifecycleInstanceHeader = "X-Malt-Client-Instance"

type Server struct {
	roots    *application.Roots
	mux      *http.ServeMux
	instance string
}

func New(store *truststore.Store) (*Server, error) {
	return NewWithInstance(store, "")
}

// NewWithInstance constructs a daemon server whose health response is bound to
// a process-launch token. The CLI uses this identity to avoid signaling a
// recycled PID from stale metadata.
func NewWithInstance(store *truststore.Store, instance string) (*Server, error) {
	if store == nil {
		return nil, fmt.Errorf("trust store is nil")
	}
	roots, err := application.NewRoots(store)
	if err != nil {
		return nil, err
	}
	s := &Server{roots: roots, mux: http.NewServeMux(), instance: instance}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "role": "trusted-client"})
	})
	s.mux.HandleFunc("GET /_lifecycle/identity", func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get(lifecycleInstanceHeader)
		if s.instance == "" || len(provided) != len(s.instance) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.instance)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "daemon lifecycle identity mismatch"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /v1/roots", func(w http.ResponseWriter, _ *http.Request) {
		roots, err := s.roots.List()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"roots": roots})
	})
	s.mux.HandleFunc("GET /v1/roots/{alias}", func(w http.ResponseWriter, r *http.Request) {
		record, err := s.roots.Get(r.PathValue("alias"))
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
		record, err := s.roots.Trust(r.PathValue("alias"), body.Root, body.Profile, body.Gateway, body.Source)
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
		candidate, err := cid.Parse(body.Root)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid candidate root: %v", err)})
			return
		}
		base, err := cid.Parse(body.BaseRoot)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid candidate base root: %v", err)})
			return
		}
		record, err := s.roots.RecordCandidate(r.PathValue("alias"), candidate, base, body.Source)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, record)
	})
	s.mux.HandleFunc("POST /v1/roots/{alias}/candidates/{root}/accept", func(w http.ResponseWriter, r *http.Request) {
		candidate, err := cid.Parse(r.PathValue("root"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid candidate root: %v", err)})
			return
		}
		record, err := s.roots.AcceptCandidate(r.PathValue("alias"), candidate, "explicit-local-acceptance")
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, record)
	})
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
	} else if errors.Is(err, truststore.ErrStaleCandidate) {
		status = http.StatusConflict
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
