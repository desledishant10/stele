package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/obs"
)

// GossipConfig controls the gossip loop.
type GossipConfig struct {
	// Interval between gossip rounds. Default 30 seconds.
	Interval time.Duration

	// HTTP holds the client used to talk to peers. nil = use default.
	HTTP *http.Client

	// EventSink, if set, receives a callback for every detected fork
	// (so the witness operator can wire in PagerDuty / Slack alerts).
	EventSink func(*ForkEvidence)
}

// StartGossip launches the gossip loop. Cancel ctx to stop.
func (s *Server) StartGossip(ctx context.Context, cfg GossipConfig) {
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	go s.gossipLoop(ctx, cfg)
}

func (s *Server) gossipLoop(ctx context.Context, cfg GossipConfig) {
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.gossipRound(ctx, cfg)
		}
	}
}

// gossipRound polls each peer for every watched operator and checks for
// forks. Forks fire the EventSink callback exactly once per
// (origin, size, peer).
func (s *Server) gossipRound(ctx context.Context, cfg GossipConfig) {
	peers := s.ListPeers()
	operators := s.ListOperators()
	if len(peers) == 0 || len(operators) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, p := range peers {
		for _, op := range operators {
			wg.Add(1)
			go func(p *Peer, op *WatchedOperator) {
				defer wg.Done()
				s.gossipOne(ctx, cfg, p, op)
			}(p, op)
		}
	}
	wg.Wait()
}

// gossipOne pulls one peer's SIGNED seen statement, verifies the
// signature, persists it as evidence, and compares against our own
// view. Disagreement is recorded as a fork; a peer that previously
// signed something different also gets caught the moment we persist
// the new statement (via recordAttestationLocked's contradiction
// check).
func (s *Server) gossipOne(ctx context.Context, cfg GossipConfig, peer *Peer, op *WatchedOperator) {
	stmt, err := fetchSignedSeen(ctx, cfg.HTTP, peer.URL, op.Origin)
	if err != nil {
		// Peer unreachable is not a fork — log and move on.
		obs.Warn("gossip fetch failed", "peer", peer.ID, "origin", op.Origin, "err", err)
		return
	}
	if err := stmt.Verify(); err != nil {
		obs.Warn("gossip peer returned invalid signed seen", "peer", peer.ID, "err", err)
		return
	}
	// The signed statement's PublicKey must match the peer we trust.
	// Otherwise an attacker who hijacked the peer URL could return a
	// statement signed by their own key and have us record evidence
	// for a peer they don't control.
	if !bytesEqualLocal(stmt.PublicKey, peer.PublicKey) {
		obs.Warn("gossip peer signed with unexpected key", "peer", peer.ID)
		return
	}
	if stmt.WitnessID != peer.ID {
		obs.Warn("gossip peer claimed wrong witness_id", "peer", peer.ID, "claimed", stmt.WitnessID)
		return
	}

	// Persist the peer's signed statement. If it contradicts an older
	// one we already kept, the contradiction is now mathematically
	// provable (we have both signed statements).
	s.mu.Lock()
	if err := s.recordAttestationLocked(peer.ID, stmt); err != nil {
		obs.Error("gossip persist attestation failed", "peer", peer.ID, "err", err)
	}
	s.mu.Unlock()

	// Cross-check against our own view (existing fork detection).
	fetcher := func(size uint64) (*checkpoint.Checkpoint, error) {
		return fetchCheckpoint(ctx, cfg.HTTP, peer.URL, op.Origin, size)
	}
	if err := s.CompareWithPeer(op.Origin, stmt.Seen, peer, fetcher); err != nil {
		obs.Warn("gossip compare-with-peer failed", "peer", peer.ID, "origin", op.Origin, "err", err)
		if cfg.EventSink != nil {
			s.mu.Lock()
			ev := s.forks[op.Origin]
			s.mu.Unlock()
			if ev != nil {
				cfg.EventSink(ev)
			}
		}
		return
	}
	// No fork. If we have overlapping views, issue a signed cross-
	// attestation publicly stating "I, witness A, confirm peer B's
	// view at this point in time." Auditors aggregate these into a
	// web of trust.
	if att := s.issueCrossAttestation(peer, stmt); att != nil {
		s.mu.Lock()
		_ = s.recordCrossAttestationLocked(att)
		s.mu.Unlock()
	}
}

// fetchSignedSeen does GET /witness/v0/seen-signed?origin=X.
func fetchSignedSeen(ctx context.Context, c *http.Client, peerURL, origin string) (*SignedSeen, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		peerURL+"/witness/v0/seen-signed?origin="+origin, nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var sr SignedSeenResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, err
	}
	if sr.Statement == nil {
		return nil, fmt.Errorf("empty statement")
	}
	return sr.Statement, nil
}

func bytesEqualLocal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fetchCheckpoint does GET /witness/v0/checkpoint?origin=X&size=N.
func fetchCheckpoint(ctx context.Context, c *http.Client, peerURL, origin string, size uint64) (*checkpoint.Checkpoint, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/witness/v0/checkpoint?origin=%s&size=%d", peerURL, origin, size), nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var cr CheckpointResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, err
	}
	return cr.Checkpoint, nil
}
