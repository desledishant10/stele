// Package mirror is the public, read-only replica of a stele log.
//
// What it gives you: a copy of every entry the operator has ever
// produced, served from infrastructure the operator does not control.
// An auditor who does not trust the operator can query a mirror they
// DO trust and cross-check responses against the operator's own.
//
// What it defends against: selective-disclosure attacks where a
// compromised operator quietly hides specific entries from specific
// auditors. The mirror sees everything the operator publishes via the
// public read APIs; the moment the operator hides an entry from
// somebody but not the mirror, the discrepancy is detectable.
//
// What it does NOT defend against: an operator that refuses to publish
// an entry at all. That's a liveness problem, not an integrity one.
// (For that, producers should keep their own outgoing log of submitted
// envelope hashes and periodically check they're all in the public
// log.)
//
// Operationally: the mirror is a thin client around the operator's
// HTTP API. It pulls in chunks, re-verifies every envelope signature
// and every hash chain link, and stores in its own BadgerDB. It serves
// the same /api/v0/entries/{idx} and /api/v0/size endpoints the
// operator does, plus /api/v0/mirror-status.
package mirror

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/desledishant10/stele/pkg/api"
	"github.com/desledishant10/stele/pkg/logentry"
	"github.com/desledishant10/stele/pkg/storage"
)

// Config holds mirror options.
type Config struct {
	// Upstream is the operator's base URL (e.g. https://stele.example.com:8443).
	Upstream string

	// HTTP, if set, overrides the default HTTP client (useful for TLS
	// configurations and tests).
	HTTP *http.Client

	// PollEvery is how often to check for new entries upstream.
	// Default 30 seconds.
	PollEvery time.Duration

	// ChunkSize caps how many entries we ask for in one HTTP call.
	// Default 256.
	ChunkSize uint64
}

// Mirror is the running mirror instance.
type Mirror struct {
	cfg   Config
	store *storage.Store

	mu       sync.Mutex
	prev     *logentry.Entry // last verified entry, for chain checks
	lastSize atomic.Uint64

	// stats
	totalEntries atomic.Uint64
	lastSync     atomic.Int64 // unix nano
	syncErrors   atomic.Uint64
}

// New opens a Mirror backed by the supplied Store.
func New(cfg Config, store *storage.Store) (*Mirror, error) {
	if cfg.Upstream == "" {
		return nil, errors.New("mirror: Upstream required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.PollEvery == 0 {
		cfg.PollEvery = 30 * time.Second
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = 256
	}
	m := &Mirror{cfg: cfg, store: store}
	// Recover prev from storage (last entry) if any.
	size, err := store.Size()
	if err != nil {
		return nil, err
	}
	m.lastSize.Store(size)
	m.totalEntries.Store(size)
	if size > 0 {
		prev, err := store.GetEntry(size - 1)
		if err != nil {
			return nil, fmt.Errorf("mirror: read tail entry: %w", err)
		}
		m.prev = prev
	}
	return m, nil
}

// Start launches the polling loop. Cancel ctx to stop.
func (m *Mirror) Start(ctx context.Context) {
	go m.loop(ctx)
}

func (m *Mirror) loop(ctx context.Context) {
	// Drain once immediately, then poll on the ticker.
	if err := m.syncOnce(ctx); err != nil {
		m.syncErrors.Add(1)
	}
	t := time.NewTicker(m.cfg.PollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.syncOnce(ctx); err != nil {
				m.syncErrors.Add(1)
			}
		}
	}
}

// syncOnce pulls everything new from the upstream, verifying each entry.
func (m *Mirror) syncOnce(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	upstreamSize, err := m.fetchUpstreamSize(ctx)
	if err != nil {
		return err
	}
	have := m.lastSize.Load()
	if upstreamSize <= have {
		m.lastSync.Store(time.Now().UnixNano())
		return nil
	}
	for from := have; from < upstreamSize; from += m.cfg.ChunkSize {
		to := from + m.cfg.ChunkSize
		if to > upstreamSize {
			to = upstreamSize
		}
		entries, err := m.fetchEntries(ctx, from, to)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := m.acceptEntry(e); err != nil {
				return fmt.Errorf("mirror: entry %d rejected: %w", e.Index, err)
			}
		}
	}
	m.lastSync.Store(time.Now().UnixNano())
	return nil
}

// acceptEntry validates an entry against the running chain and persists.
func (m *Mirror) acceptEntry(e *logentry.Entry) error {
	if err := e.Verify(); err != nil {
		return err
	}
	if err := e.VerifyChain(m.prev); err != nil {
		return err
	}
	if err := m.store.AppendEntry(e); err != nil {
		return err
	}
	m.prev = e
	m.lastSize.Add(1)
	m.totalEntries.Add(1)
	return nil
}

// Size returns the number of entries the mirror has verified locally.
func (m *Mirror) Size() uint64 { return m.lastSize.Load() }

// Status returns mirror health metrics for the /mirror-status endpoint.
func (m *Mirror) Status() Status {
	return Status{
		Upstream:     m.cfg.Upstream,
		MirroredSize: m.lastSize.Load(),
		TotalEntries: m.totalEntries.Load(),
		LastSyncNs:   m.lastSync.Load(),
		SyncErrors:   m.syncErrors.Load(),
	}
}

// GetEntry serves an entry by index from the local store.
func (m *Mirror) GetEntry(idx uint64) (*logentry.Entry, error) {
	return m.store.GetEntry(idx)
}

// Status is the JSON shape served by /api/v0/mirror-status.
type Status struct {
	Upstream     string `json:"upstream"`
	MirroredSize uint64 `json:"mirrored_size"`
	TotalEntries uint64 `json:"total_entries"`
	LastSyncNs   int64  `json:"last_sync_ns"`
	SyncErrors   uint64 `json:"sync_errors"`
}

// ----- upstream HTTP helpers -----

func (m *Mirror) fetchUpstreamSize(ctx context.Context) (uint64, error) {
	var resp api.SizeResponse
	if err := m.httpGet(ctx, "/api/v0/size", &resp); err != nil {
		return 0, err
	}
	return resp.Size, nil
}

func (m *Mirror) fetchEntries(ctx context.Context, from, to uint64) ([]*logentry.Entry, error) {
	var resp api.EntriesResponse
	if err := m.httpGet(ctx, fmt.Sprintf("/api/v0/entries?from=%d&to=%d", from, to), &resp); err != nil {
		return nil, err
	}
	return resp.Entries, nil
}

func (m *Mirror) httpGet(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.Upstream+path, nil)
	if err != nil {
		return err
	}
	resp, err := m.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

// hashOf is a small helper used by tests when comparing entries across
// mirror and operator.
func hashOf(e *logentry.Entry) string { return hex.EncodeToString(e.EntryHash) }
