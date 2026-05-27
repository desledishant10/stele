package witness

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// CrossAttestation is a signed statement A → B saying "I, witness A,
// pulled witness B's SignedSeen for origin O at time T, and B's view
// matched mine at every overlapping size."
//
// Why this matters. The base gossip layer lets each witness keep B's
// signed claims locally as evidence. Cross-attestations go further:
// they make A's CONFIRMATION of B's claims publicly auditable. A
// witness that never receives cross-attestations from peers is
// suspicious (isolated). A witness that publishes attestations
// contradicting its own seen map is provably dishonest.
//
// Auditors aggregate cross-attestations to build a "web of trust"
// graph: who confirms whom, how recently. A subset of witnesses that
// all cross-attest each other but is disjoint from the rest is the
// signature of a malicious cohort.
type CrossAttestation struct {
	// AttesterID is the witness emitting this statement (signs the
	// canonical bytes with its own witness key).
	AttesterID string `json:"attester_id"`
	AttesterKey []byte `json:"attester_key"`
	AttesterKeyID string `json:"attester_key_id"`

	// PeerID is the witness whose view is being confirmed.
	PeerID string `json:"peer_id"`
	PeerKey []byte `json:"peer_key"`

	// Origin is the operator whose log both parties watch.
	Origin string `json:"origin"`

	// OverlappingSizes is the set of (size, root) pairs at which A
	// and B agree. AT LEAST one is required — empty overlaps mean
	// nothing was confirmed and the attestation has no value.
	OverlappingSizes map[uint64]string `json:"overlapping_sizes"`

	// IssuedAt is A's wall-clock time when issuing.
	IssuedAt int64 `json:"issued_at"`

	// PeerStatementIssuedAt is the IssuedAt from B's SignedSeen
	// that A was confirming. Pins the attestation to a specific
	// point in B's signed history so a later contradiction by B is
	// independently provable: B's old SignedSeen + A's cross-
	// attestation referencing it together rule out the new claim.
	PeerStatementIssuedAt int64 `json:"peer_statement_issued_at"`

	// Signature over Canonical() using AttesterKey.
	Signature []byte `json:"signature"`
}

// Canonical returns the deterministic bytes A signs.
func (c *CrossAttestation) Canonical() []byte {
	sizes := make([]uint64, 0, len(c.OverlappingSizes))
	for s := range c.OverlappingSizes {
		sizes = append(sizes, s)
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })

	header := fmt.Sprintf(
		"stele-cross/v0\nattester: %s\npeer: %s\norigin: %s\nissued_at: %d\npeer_statement_issued_at: %d\nattester_key: %s\npeer_key: %s\noverlap_count: %d\n",
		c.AttesterID, c.PeerID, c.Origin, c.IssuedAt, c.PeerStatementIssuedAt,
		hex.EncodeToString(c.AttesterKey), hex.EncodeToString(c.PeerKey), len(sizes),
	)
	buf := []byte(header)
	for _, sz := range sizes {
		buf = append(buf, []byte(fmt.Sprintf("%d:%s\n", sz, c.OverlappingSizes[sz]))...)
	}
	return buf
}

// Verify checks the signature against AttesterKey.
func (c *CrossAttestation) Verify() error {
	if len(c.AttesterKey) != ed25519.PublicKeySize {
		return fmt.Errorf("cross-attestation: bad attester key length %d", len(c.AttesterKey))
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("cross-attestation: bad sig length %d", len(c.Signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(c.AttesterKey), c.Canonical(), c.Signature) {
		return errors.New("cross-attestation: signature invalid")
	}
	return nil
}

// issueCrossAttestation produces a CrossAttestation when this server
// pulled `peer`'s SignedSeen and there's at least one overlapping size
// where our local view agrees with theirs. Returns nil if no overlap.
func (s *Server) issueCrossAttestation(peer *Peer, stmt *SignedSeen) *CrossAttestation {
	s.mu.Lock()
	mine := s.seen[stmt.Origin]
	s.mu.Unlock()

	overlap := make(map[uint64]string)
	for size, theirRoot := range stmt.Seen {
		if ourRoot, ok := mine[size]; ok && ourRoot == theirRoot {
			overlap[size] = ourRoot
		}
	}
	if len(overlap) == 0 {
		return nil
	}
	att := &CrossAttestation{
		AttesterID:           s.id,
		AttesterKey:          append([]byte(nil), s.pub...),
		AttesterKeyID:        s.keyID,
		PeerID:               peer.ID,
		PeerKey:              append([]byte(nil), peer.PublicKey...),
		Origin:               stmt.Origin,
		OverlappingSizes:     overlap,
		IssuedAt:             time.Now().UnixNano(),
		PeerStatementIssuedAt: stmt.IssuedAt,
	}
	att.Signature = ed25519.Sign(s.priv, att.Canonical())
	return att
}

// recordCrossAttestationLocked appends to the on-disk store. Caller
// holds s.mu.
func (s *Server) recordCrossAttestationLocked(att *CrossAttestation) error {
	if s.crossAtts == nil {
		s.crossAtts = []*CrossAttestation{}
	}
	s.crossAtts = append(s.crossAtts, att)
	return s.saveCrossAttsLocked()
}

// CrossAttestationsAbout returns every cross-attestation this witness
// has issued or received about a specific peer (matches either
// AttesterID or PeerID). Pass empty to get all.
func (s *Server) CrossAttestationsAbout(peerID string) []*CrossAttestation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*CrossAttestation, 0, len(s.crossAtts))
	for _, a := range s.crossAtts {
		if peerID == "" || a.PeerID == peerID || a.AttesterID == peerID {
			out = append(out, a)
		}
	}
	return out
}
