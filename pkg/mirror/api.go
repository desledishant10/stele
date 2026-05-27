package mirror

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// NewMux builds the read-only HTTP API for a Mirror.
func NewMux(m *Mirror) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v0/size", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"size": m.Size()})
	})
	mux.HandleFunc("/api/v0/entries/", func(w http.ResponseWriter, r *http.Request) {
		idxStr := strings.TrimPrefix(r.URL.Path, "/api/v0/entries/")
		idx, err := strconv.ParseUint(idxStr, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		entry, err := m.GetEntry(idx)
		if err != nil {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entry": entry})
	})
	mux.HandleFunc("/api/v0/entries", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		from, err := strconv.ParseUint(q.Get("from"), 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid from: %w", err))
			return
		}
		to, err := strconv.ParseUint(q.Get("to"), 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid to: %w", err))
			return
		}
		if to <= from || to-from > 10_000 {
			writeErr(w, http.StatusBadRequest, errors.New("invalid range"))
			return
		}
		var entries []any
		for i := from; i < to && i < m.Size(); i++ {
			e, err := m.GetEntry(i)
			if err != nil {
				break
			}
			entries = append(entries, e)
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "from": from, "to": to})
	})
	mux.HandleFunc("/api/v0/mirror-status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, m.Status())
	})
	// /healthz, /readyz, /metrics are mounted by callers via obs.Mount.
	return mux
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
