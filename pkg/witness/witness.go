// Package witness implements the cosignature protocol that turns stele's
// single-operator trust model into a multi-party one.
//
// A witness is a tiny daemon, ideally run by an independent party (your
// customer, your auditor, an open-source watcher), that:
//
//  1. Accepts checkpoints from one or more operators it has been told
//     about, identified by (origin, root public key).
//
//  2. Verifies the operator's signature against the operator's rotation
//     chain.
//
//  3. Records the checkpoint in append-only storage so it can never claim
//     not to have seen something it counter-signed.
//
//  4. CHECKS for contradictions: if the operator has previously signed a
//     different root at the same tree size, that is a fork and the witness
//     refuses to cosign and emits an alert.
//
//  5. If all checks pass, returns a WitnessSig over the operator-signed
//     canonical bytes plus the operator signature.
//
// Verifiers then require >= N witness signatures from a known cohort.
// To rewrite history under that model, an attacker must compromise the
// operator's key AND >= N witnesses simultaneously, all of which are run
// by independent parties on independent infrastructure.
package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/threshold"
)

// WatchedOperator is one stele operator that this witness is willing to
// countersign for.
type WatchedOperator struct {
	Origin        string `json:"origin"`
	RootPublicKey []byte `json:"root_public_key"` // genesis pubkey trust anchor
	Description   string `json:"description,omitempty"`
}

// Peer is another witness this server gossips with. The public key is
// used to authenticate peer responses so a man-in-the-middle can't
// fabricate fork evidence.
type Peer struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	PublicKey   []byte `json:"public_key"`
	Description string `json:"description,omitempty"`
	AddedAt     int64  `json:"added_at"`
}

// ForkEvidence is the smoking gun the witness keeps when it detects
// that an operator has signed two different roots at the same tree
// size. The two checkpoints together are mathematical proof of
// operator misbehaviour.
type ForkEvidence struct {
	Origin    string                 `json:"origin"`
	Size      uint64                 `json:"size"`
	DetectedAt int64                 `json:"detected_at"`
	OurCheckpoint   *checkpoint.Checkpoint `json:"our_checkpoint"`
	TheirCheckpoint *checkpoint.Checkpoint `json:"their_checkpoint"`
	TheirPeerID     string                 `json:"their_peer_id,omitempty"`
}

// Server holds witness state for one or more watched operators.
//
// When qPriv != nil, the witness is in hybrid post-quantum mode: every
// countersignature it produces is BOTH an Ed25519 sig AND a Dilithium3
// sig over the same canonical bytes.
type Server struct {
	mu          sync.Mutex
	dir         string
	id          string                       // human label, e.g. "auditor-alice"
	priv        ed25519.PrivateKey
	pub         ed25519.PublicKey
	keyID       string
	qPriv       *mode3.PrivateKey            // Dilithium3 priv (nil = classical-only)
	qPub        []byte                       // Dilithium3 pub bytes
	operators   map[string]*WatchedOperator  // keyed by origin
	seen        map[string]map[uint64]string // origin -> tree_size -> hex(root)
	checkpoints map[string]map[uint64]*checkpoint.Checkpoint
	peers       map[string]*Peer            // keyed by peer ID
	forks       map[string]*ForkEvidence    // keyed by origin
	attest      *PeerAttestationStore       // signed statements gathered from peers
	crossAtts   []*CrossAttestation         // signed confirmations of peers (issued + received)
}

// NewServer creates or opens a CLASSICAL-mode witness. See
// NewHybridServer to opt into Ed25519 + Dilithium3 countersignatures.
func NewServer(id, dir string) (*Server, error) {
	return newServer(id, dir, false)
}

// NewHybridServer creates or opens a HYBRID witness. On first run it
// generates BOTH an Ed25519 keypair and a Dilithium3 keypair.
func NewHybridServer(id, dir string) (*Server, error) {
	return newServer(id, dir, true)
}

func newServer(id, dir string, hybrid bool) (*Server, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Server{
		id:          id,
		dir:         dir,
		operators:   make(map[string]*WatchedOperator),
		seen:        make(map[string]map[uint64]string),
		checkpoints: make(map[string]map[uint64]*checkpoint.Checkpoint),
		peers:       make(map[string]*Peer),
		forks:       make(map[string]*ForkEvidence),
	}
	if err := s.loadOrCreateKey(); err != nil {
		return nil, err
	}
	if err := s.loadOrCreateQuantumKey(hybrid); err != nil {
		return nil, err
	}
	if err := s.loadOperators(); err != nil {
		return nil, err
	}
	if err := s.loadSeen(); err != nil {
		return nil, err
	}
	if err := s.loadCheckpoints(); err != nil {
		return nil, err
	}
	if err := s.loadPeers(); err != nil {
		return nil, err
	}
	if err := s.loadForks(); err != nil {
		return nil, err
	}
	if err := s.loadAttestations(); err != nil {
		return nil, err
	}
	if err := s.loadCrossAtts(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) loadOrCreateKey() error {
	keyPath := filepath.Join(s.dir, "witness.key")
	if buf, err := os.ReadFile(keyPath); err == nil {
		raw, err := base64.StdEncoding.DecodeString(stripWS(string(buf)))
		if err != nil {
			return err
		}
		if len(raw) != ed25519.PrivateKeySize {
			return fmt.Errorf("witness key wrong length %d", len(raw))
		}
		s.priv = ed25519.PrivateKey(raw)
		s.pub = s.priv.Public().(ed25519.PublicKey)
		sum := sha256.Sum256(s.pub)
		s.keyID = hex.EncodeToString(sum[:8])
		return nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.priv = priv
	s.pub = pub
	sum := sha256.Sum256(pub)
	s.keyID = hex.EncodeToString(sum[:8])
	enc := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(keyPath, []byte(enc+"\n"), 0o600); err != nil {
		return err
	}
	pubPath := filepath.Join(s.dir, "witness.pub")
	pubEnc := base64.StdEncoding.EncodeToString(pub)
	return os.WriteFile(pubPath, []byte(pubEnc+"\n"), 0o644)
}

// loadOrCreateQuantumKey activates hybrid mode if requested. If a
// Dilithium key already exists on disk, it is loaded regardless of the
// `hybrid` parameter — once a witness is hybrid, it stays hybrid (so a
// peer/operator who has trusted our quantum pubkey doesn't suddenly
// see us downgrade).
func (s *Server) loadOrCreateQuantumKey(hybrid bool) error {
	qKeyPath := filepath.Join(s.dir, "witness-quantum.key")
	if buf, err := os.ReadFile(qKeyPath); err == nil {
		raw, err := base64.StdEncoding.DecodeString(stripWS(string(buf)))
		if err != nil {
			return err
		}
		priv := &mode3.PrivateKey{}
		if err := priv.UnmarshalBinary(raw); err != nil {
			return fmt.Errorf("witness quantum key parse: %w", err)
		}
		s.qPriv = priv
		s.qPub, _ = priv.Public().(*mode3.PublicKey).MarshalBinary()
		return nil
	}
	if !hybrid {
		return nil
	}
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.qPriv = priv
	s.qPub, _ = pub.MarshalBinary()
	body, err := priv.MarshalBinary()
	if err != nil {
		return err
	}
	if err := os.WriteFile(qKeyPath, []byte(base64.StdEncoding.EncodeToString(body)+"\n"), 0o600); err != nil {
		return err
	}
	qPubPath := filepath.Join(s.dir, "witness-quantum.pub")
	return os.WriteFile(qPubPath, []byte(base64.StdEncoding.EncodeToString(s.qPub)+"\n"), 0o644)
}

func (s *Server) opsPath() string          { return filepath.Join(s.dir, "operators.json") }
func (s *Server) seenPath() string         { return filepath.Join(s.dir, "seen.json") }
func (s *Server) checkpointsPath() string  { return filepath.Join(s.dir, "checkpoints.json") }
func (s *Server) peersPath() string        { return filepath.Join(s.dir, "peers.json") }
func (s *Server) forksPath() string        { return filepath.Join(s.dir, "forks.json") }
func (s *Server) attestationsPath() string { return filepath.Join(s.dir, "attestations.json") }
func (s *Server) crossAttsPath() string    { return filepath.Join(s.dir, "cross_attestations.json") }

func (s *Server) loadOperators() error {
	buf, err := os.ReadFile(s.opsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []*WatchedOperator
	if err := json.Unmarshal(buf, &list); err != nil {
		return err
	}
	for _, op := range list {
		s.operators[op.Origin] = op
	}
	return nil
}

func (s *Server) saveOperators() error {
	list := make([]*WatchedOperator, 0, len(s.operators))
	for _, op := range s.operators {
		list = append(list, op)
	}
	body, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.opsPath(), body)
}

func (s *Server) loadSeen() error {
	buf, err := os.ReadFile(s.seenPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(buf, &s.seen)
}

func (s *Server) saveSeen() error {
	body, err := json.MarshalIndent(s.seen, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.seenPath(), body)
}

func (s *Server) loadCheckpoints() error {
	buf, err := os.ReadFile(s.checkpointsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(buf, &s.checkpoints)
}

func (s *Server) saveCheckpoints() error {
	body, err := json.MarshalIndent(s.checkpoints, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.checkpointsPath(), body)
}

func (s *Server) loadPeers() error {
	buf, err := os.ReadFile(s.peersPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []*Peer
	if err := json.Unmarshal(buf, &list); err != nil {
		return err
	}
	for _, p := range list {
		s.peers[p.ID] = p
	}
	return nil
}

func (s *Server) savePeers() error {
	list := make([]*Peer, 0, len(s.peers))
	for _, p := range s.peers {
		list = append(list, p)
	}
	body, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.peersPath(), body)
}

func (s *Server) loadForks() error {
	buf, err := os.ReadFile(s.forksPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(buf, &s.forks)
}

func (s *Server) saveForks() error {
	body, err := json.MarshalIndent(s.forks, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.forksPath(), body)
}

func (s *Server) loadAttestations() error {
	buf, err := os.ReadFile(s.attestationsPath())
	if err != nil {
		if os.IsNotExist(err) {
			s.attest = &PeerAttestationStore{Latest: map[string]map[string]*PeerAttestation{}}
			return nil
		}
		return err
	}
	var store PeerAttestationStore
	if err := json.Unmarshal(buf, &store); err != nil {
		return err
	}
	if store.Latest == nil {
		store.Latest = map[string]map[string]*PeerAttestation{}
	}
	s.attest = &store
	return nil
}

// saveAttestationsLocked persists the store. Caller must hold s.mu.
func (s *Server) saveAttestationsLocked() error {
	if s.attest == nil {
		return nil
	}
	body, err := json.MarshalIndent(s.attest, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.attestationsPath(), body)
}

func (s *Server) loadCrossAtts() error {
	buf, err := os.ReadFile(s.crossAttsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(buf, &s.crossAtts)
}

// saveCrossAttsLocked persists the cross-attestation log. Caller holds s.mu.
func (s *Server) saveCrossAttsLocked() error {
	body, err := json.MarshalIndent(s.crossAtts, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.crossAttsPath(), body)
}

// AddOperator authorises the witness to countersign for an operator.
func (s *Server) AddOperator(op *WatchedOperator) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if op == nil || op.Origin == "" || len(op.RootPublicKey) != ed25519.PublicKeySize {
		return errors.New("witness: invalid operator descriptor")
	}
	s.operators[op.Origin] = op
	return s.saveOperators()
}

// ListOperators returns the operators this witness is watching.
func (s *Server) ListOperators() []*WatchedOperator {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*WatchedOperator, 0, len(s.operators))
	for _, op := range s.operators {
		out = append(out, op)
	}
	return out
}

// ID returns the human label for this witness.
func (s *Server) ID() string { return s.id }

// PublicKey returns the witness's public key.
func (s *Server) PublicKey() ed25519.PublicKey { return s.pub }

// KeyID returns the short identifier.
func (s *Server) KeyID() string { return s.keyID }

// Cosign is the heart of the protocol. Given a checkpoint that the
// operator has already signed (plus the operator's rotation chain), the
// witness:
//   - refuses if this operator is currently flagged as forked;
//   - verifies the operator's signature;
//   - checks for forks at the checkpoint's size;
//   - persists the full signed checkpoint as evidence;
//   - signs CanonicalForWitness with the witness key;
//   - returns a WitnessSig the caller can attach to the checkpoint.
func (s *Server) Cosign(c *checkpoint.Checkpoint, chain *fwdsec.Chain, group *threshold.Group) (*checkpoint.WitnessSig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, forked := s.forks[c.Origin]; forked {
		return nil, fmt.Errorf("witness: refusing to cosign — origin %q is flagged as FORKED (see /witness/v0/forks)", c.Origin)
	}

	op, ok := s.operators[c.Origin]
	if !ok {
		return nil, fmt.Errorf("witness: operator %q is not on the watch list", c.Origin)
	}
	root := ed25519.PublicKey(op.RootPublicKey)
	// When the operator is in threshold mode, the caller supplies the
	// active group so the witness can verify the t-of-N member sigs.
	// In single-sig mode, group is nil and we fall through to chain-
	// based verification.
	if err := checkpoint.Verify(c, chain, root, group); err != nil {
		return nil, fmt.Errorf("witness: operator signature did not verify: %w", err)
	}

	// Fork check: have we seen a different root at this size from this
	// operator before?
	rootHex := hex.EncodeToString(c.RootHash)
	if known, ok := s.seen[c.Origin]; ok {
		if existing, ok := known[c.Size]; ok && existing != rootHex {
			// Local fork — we've already cosigned a different root at
			// this size. Persist evidence and refuse.
			prevCheckpoint := s.checkpoints[c.Origin][c.Size]
			s.recordForkLocked(c.Origin, c.Size, prevCheckpoint, c, "")
			return nil, fmt.Errorf("witness: FORK detected for %s at size %d (existing root %s, new %s)",
				c.Origin, c.Size, existing, rootHex)
		}
	} else {
		s.seen[c.Origin] = make(map[uint64]string)
	}
	if _, ok := s.checkpoints[c.Origin]; !ok {
		s.checkpoints[c.Origin] = make(map[uint64]*checkpoint.Checkpoint)
	}
	s.seen[c.Origin][c.Size] = rootHex
	s.checkpoints[c.Origin][c.Size] = c
	if err := s.saveSeen(); err != nil {
		return nil, err
	}
	if err := s.saveCheckpoints(); err != nil {
		return nil, err
	}

	// Sign the operator-signed canonical bytes.
	msg := c.CanonicalForWitness()
	sig := ed25519.Sign(s.priv, msg)
	ws := &checkpoint.WitnessSig{
		WitnessID: s.id,
		PublicKey: append([]byte(nil), s.pub...),
		KeyID:     s.keyID,
		Signature: sig,
		SignedAt:  time.Now().UnixNano(),
	}
	if s.qPriv != nil {
		qsig := make([]byte, mode3.SignatureSize)
		mode3.SignTo(s.qPriv, msg, qsig)
		ws.QuantumPublicKey = append([]byte(nil), s.qPub...)
		ws.QuantumSignature = qsig
	}
	return ws, nil
}

// QuantumPublicKey returns the witness's Dilithium3 public key bytes
// (nil if classical-only).
func (s *Server) QuantumPublicKey() []byte { return s.qPub }

// IsHybrid reports whether this witness is signing in hybrid mode.
func (s *Server) IsHybrid() bool { return s.qPriv != nil }

// ----- peer + fork machinery -----

// SeenFor returns a copy of the size -> root_hex map this witness has
// recorded for the given operator. Peers query this during gossip.
func (s *Server) SeenFor(origin string) map[uint64]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	src, ok := s.seen[origin]
	if !ok {
		return map[uint64]string{}
	}
	out := make(map[uint64]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// CheckpointAt returns the signed checkpoint this witness recorded for
// (origin, size), or nil if it never saw one.
func (s *Server) CheckpointAt(origin string, size uint64) *checkpoint.Checkpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.checkpoints[origin]; ok {
		return m[size]
	}
	return nil
}

// AddPeer registers a sibling witness for gossip.
func (s *Server) AddPeer(p *Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p == nil || p.ID == "" || p.URL == "" {
		return errors.New("witness: peer requires id + url")
	}
	if len(p.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("witness: peer public key wrong length %d", len(p.PublicKey))
	}
	if p.AddedAt == 0 {
		p.AddedAt = time.Now().UnixNano()
	}
	s.peers[p.ID] = p
	return s.savePeers()
}

// ListPeers returns the configured peers.
func (s *Server) ListPeers() []*Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Peer, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p)
	}
	return out
}

// ListForks returns all currently-detected forks.
func (s *Server) ListForks() []*ForkEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*ForkEvidence, 0, len(s.forks))
	for _, f := range s.forks {
		out = append(out, f)
	}
	return out
}

// ClearFork removes a recorded fork for an origin. Called by an operator
// after a manual investigation has resolved the inconsistency. Audit
// trails should record this action out of band.
func (s *Server) ClearFork(origin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.forks, origin)
	_ = s.saveForks()
}

// recordForkLocked persists fork evidence. Caller must hold s.mu.
func (s *Server) recordForkLocked(origin string, size uint64, ours, theirs *checkpoint.Checkpoint, peerID string) {
	s.forks[origin] = &ForkEvidence{
		Origin:          origin,
		Size:            size,
		DetectedAt:      time.Now().UnixNano(),
		OurCheckpoint:   ours,
		TheirCheckpoint: theirs,
		TheirPeerID:     peerID,
	}
	_ = s.saveForks()
}

// CompareWithPeer takes another witness's seen map for `origin` (plus
// the peer's identity) and returns a non-nil error if we detect a fork.
// On detection, evidence is persisted and the origin is flagged forked.
func (s *Server) CompareWithPeer(origin string, peerSeen map[uint64]string, peer *Peer, fetchPeerCheckpoint func(size uint64) (*checkpoint.Checkpoint, error)) error {
	s.mu.Lock()
	mine := s.seen[origin]
	s.mu.Unlock()
	for size, theirRoot := range peerSeen {
		ourRoot, have := mine[size]
		if !have {
			continue
		}
		if ourRoot == theirRoot {
			continue
		}
		// Fetch the peer's actual checkpoint for evidence.
		var theirCP *checkpoint.Checkpoint
		if fetchPeerCheckpoint != nil {
			cp, err := fetchPeerCheckpoint(size)
			if err == nil {
				theirCP = cp
			}
		}
		s.mu.Lock()
		ourCP := s.checkpoints[origin][size]
		s.recordForkLocked(origin, size, ourCP, theirCP, peer.ID)
		s.mu.Unlock()
		return fmt.Errorf("FORK: %s at size %d, our root=%s, peer %s root=%s",
			origin, size, ourRoot, peer.ID, theirRoot)
	}
	return nil
}

// ----- helpers -----

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func stripWS(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
