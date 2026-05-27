package witness

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// SignedSeen is a witness's signed attestation of what it has cosigned for
// one origin. Peers fetch SignedSeen statements during gossip and keep them
// as evidence: if the issuing witness later contradicts an old statement,
// the contradiction is mathematically detectable.
//
// Without this, a malicious witness could lie about what it has seen and
// no peer would have proof — the gossip layer would degrade to "trust your
// peers' word." With SignedSeen, peers trust the cryptography instead.
type SignedSeen struct {
	WitnessID  string            `json:"witness_id"`
	PublicKey  []byte            `json:"public_key"`
	KeyID      string            `json:"key_id"`
	Origin     string            `json:"origin"`
	Seen       map[uint64]string `json:"seen"` // tree_size -> hex(root)
	IssuedAt   int64             `json:"issued_at"`
	Signature  []byte            `json:"signature"`
}

// Canonical returns the bytes the witness signs. Format is text and
// deterministic; size→root pairs are sorted by ascending size.
//
//	stele-seen/v0
//	witness_id: <id>
//	origin: <origin>
//	issued_at: <unix nanos>
//	pubkey: <hex>
//	entries: <count>
//	<size>:<hex root>
//	<size>:<hex root>
//	...
func (s *SignedSeen) Canonical() []byte {
	sizes := make([]uint64, 0, len(s.Seen))
	for size := range s.Seen {
		sizes = append(sizes, size)
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })

	header := fmt.Sprintf(
		"stele-seen/v0\nwitness_id: %s\norigin: %s\nissued_at: %d\npubkey: %s\nentries: %d\n",
		s.WitnessID, s.Origin, s.IssuedAt, hex.EncodeToString(s.PublicKey), len(sizes),
	)
	buf := []byte(header)
	for _, size := range sizes {
		buf = append(buf, []byte(fmt.Sprintf("%d:%s\n", size, s.Seen[size]))...)
	}
	return buf
}

// Verify checks the signature against the embedded PublicKey.
func (s *SignedSeen) Verify() error {
	if len(s.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("signed seen: bad public key length %d", len(s.PublicKey))
	}
	if len(s.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("signed seen: bad signature length %d", len(s.Signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(s.PublicKey), s.Canonical(), s.Signature) {
		return errors.New("signed seen: signature does not verify")
	}
	return nil
}

// IssueSignedSeen builds a SignedSeen for the given origin using the
// witness's current seen map.
func (s *Server) IssueSignedSeen(origin string) *SignedSeen {
	s.mu.Lock()
	src := s.seen[origin]
	seenCopy := make(map[uint64]string, len(src))
	for k, v := range src {
		seenCopy[k] = v
	}
	s.mu.Unlock()

	ss := &SignedSeen{
		WitnessID: s.id,
		PublicKey: append([]byte(nil), s.pub...),
		KeyID:     s.keyID,
		Origin:    origin,
		Seen:      seenCopy,
		IssuedAt:  time.Now().UnixNano(),
	}
	ss.Signature = ed25519.Sign(s.priv, ss.Canonical())
	return ss
}

// PeerAttestation pairs a SignedSeen we received from a peer with our
// metadata about when we received it and what peer it came from. We
// persist these to disk so an auditor can later replay every
// statement a peer made.
type PeerAttestation struct {
	PeerID     string      `json:"peer_id"`
	Origin     string      `json:"origin"`
	ReceivedAt int64       `json:"received_at"`
	Statement  *SignedSeen `json:"statement"`
}

// PeerAttestationStore is the on-disk persistence layer for the
// SignedSeen statements a witness has received from its peers.
//
// Conceptually a map keyed by (PeerID, Origin) that always overwrites
// with the latest statement — but the old statement is also retained
// in a history list under PeerHistory so an auditor can spot
// contradictions across time.
type PeerAttestationStore struct {
	Latest  map[string]map[string]*PeerAttestation `json:"latest"`  // peer_id -> origin -> latest
	History []*PeerAttestation                      `json:"history"` // append-only audit trail
}

// recordAttestationLocked stores a new attestation. Caller must hold
// s.mu. If the new statement contradicts the previous latest one (same
// size, different root), the contradiction is detected and recorded as
// a fork.
//
// `peerID` is the local trusted ID of the peer (so an attacker who
// returns a SignedSeen with someone else's WitnessID field is caught
// when this lookup fails).
func (s *Server) recordAttestationLocked(peerID string, ss *SignedSeen) error {
	if s.attest == nil {
		s.attest = &PeerAttestationStore{
			Latest: make(map[string]map[string]*PeerAttestation),
		}
	}
	if _, ok := s.attest.Latest[peerID]; !ok {
		s.attest.Latest[peerID] = make(map[string]*PeerAttestation)
	}
	att := &PeerAttestation{
		PeerID:     peerID,
		Origin:     ss.Origin,
		ReceivedAt: time.Now().UnixNano(),
		Statement:  ss,
	}

	// Check for contradiction with an older statement we kept from
	// this peer. If they previously claimed root R1 at size 5 and now
	// claim R2, that's evidence of dishonesty.
	if prev, ok := s.attest.Latest[peerID][ss.Origin]; ok && prev != nil && prev.Statement != nil {
		if contradicting := findContradiction(prev.Statement, ss); contradicting != "" {
			// The peer's own old + new statements are kept in the
			// history list and are themselves the cryptographic
			// evidence of dishonesty (both are signed by the peer's
			// witness key). The fork record flags the (origin,
			// peerID) pair for the operator to investigate.
			size := parseSizeOfContradiction(contradicting)
			s.recordForkLocked(ss.Origin, size, nil, nil, peerID)
		}
	}

	s.attest.Latest[peerID][ss.Origin] = att
	s.attest.History = append(s.attest.History, att)
	return s.saveAttestationsLocked()
}

// findContradiction returns a non-empty string explaining the first
// size at which `prev` and `next` disagree on a root, or "" if they
// agree on every overlapping size.
//
// Format: "size=42 prev=abc... next=def..." — used only for logs.
func findContradiction(prev, next *SignedSeen) string {
	for size, prevRoot := range prev.Seen {
		if nextRoot, ok := next.Seen[size]; ok && nextRoot != prevRoot {
			return fmt.Sprintf("size=%d prev=%s next=%s", size, prevRoot, nextRoot)
		}
	}
	return ""
}

// parseSizeOfContradiction extracts the size from a findContradiction
// string. Returns 0 on parse failure (the fork is still recorded; just
// with a less-informative size field).
func parseSizeOfContradiction(s string) uint64 {
	var size uint64
	_, _ = fmt.Sscanf(s, "size=%d", &size)
	return size
}

// PeerAttestations returns every SignedSeen this witness has received
// for `peerID` (or for all peers if empty), in chronological order.
// Auditors use this to walk a peer's history and look for
// contradictions across time.
func (s *Server) PeerAttestations(peerID string) []*PeerAttestation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attest == nil {
		return nil
	}
	out := make([]*PeerAttestation, 0, len(s.attest.History))
	for _, a := range s.attest.History {
		if peerID == "" || a.PeerID == peerID {
			out = append(out, a)
		}
	}
	return out
}
