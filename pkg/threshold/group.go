// Package threshold implements t-of-N multi-signature operator keys for
// stele. In threshold mode, no single signer can produce a valid
// checkpoint or rotation cert — at least `threshold` of `len(Members)`
// must each independently sign the same canonical bytes with their own
// Ed25519 private key.
//
// Why this is the right primitive for stele. The semantic property we
// want is "no single party can forge." Classic FROST achieves this with
// a 2-round MPC protocol that outputs a single Schnorr signature; we
// achieve the same property by simply collecting N independent
// signatures and requiring at least t to verify. The verification cost
// is t signature checks instead of one, and the signature is t*64
// bytes instead of 64 — both irrelevant at stele's scale and easier to
// reason about cryptographically.
//
// Practical defence: each Member runs as a separate stele-cosigner
// daemon on independent infrastructure (different hosts, different
// HSMs, ideally different humans + jurisdictions). To forge anything,
// an attacker must compromise at least `threshold` of these
// simultaneously — a much steeper requirement than a single key, HSM
// or no.
package threshold

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Member is one participant in a threshold group. ID is a stable label
// (e.g. "alice@security-team"), PublicKey is the member's Ed25519
// public key, and Endpoint is the URL of the member's running
// stele-cosigner daemon (used by the coordinator to fetch signatures).
//
// QuantumPublicKey, when non-empty, switches this member into hybrid
// mode: VerifyMulti requires the member's cosig to include a matching
// Dilithium3 signature.
type Member struct {
	ID               string `json:"id"`
	PublicKey        []byte `json:"public_key"`
	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	Endpoint         string `json:"endpoint,omitempty"`
	Description      string `json:"description,omitempty"`
}

// Group is a t-of-N signing group. The set of members and the threshold
// together define the security parameter: an attacker must compromise
// `Threshold` of the listed members to produce a valid signature.
type Group struct {
	// Version is bumped if the canonical encoding ever changes. Always
	// 1 for the current build.
	Version uint32 `json:"version"`

	// Origin is the stele log this group is authorised to sign for.
	// Included in the digest so a member key reuse across logs doesn't
	// silently leak signing authority.
	Origin string `json:"origin"`

	// Members lists every signer. Order is preserved in the canonical
	// encoding but does not affect threshold semantics.
	Members []*Member `json:"members"`

	// Threshold is the minimum number of valid signatures required.
	// Must satisfy 1 <= Threshold <= len(Members).
	Threshold uint32 `json:"threshold"`

	// CreatedAt is the wall-clock time the group was first sealed.
	CreatedAt int64 `json:"created_at"`
}

// Validate enforces structural invariants. Returns an error on any
// duplicate member IDs / pubkeys, malformed keys, or out-of-range
// threshold.
func (g *Group) Validate() error {
	if g == nil {
		return errors.New("threshold: nil group")
	}
	if g.Version != 1 {
		return fmt.Errorf("threshold: unsupported group version %d", g.Version)
	}
	if g.Origin == "" {
		return errors.New("threshold: group missing origin")
	}
	if len(g.Members) == 0 {
		return errors.New("threshold: group must have >= 1 member")
	}
	if g.Threshold == 0 || int(g.Threshold) > len(g.Members) {
		return fmt.Errorf("threshold: invalid threshold %d for %d members", g.Threshold, len(g.Members))
	}
	seenID := make(map[string]struct{}, len(g.Members))
	seenPub := make(map[string]struct{}, len(g.Members))
	for _, m := range g.Members {
		if m.ID == "" {
			return errors.New("threshold: member with empty ID")
		}
		if _, dup := seenID[m.ID]; dup {
			return fmt.Errorf("threshold: duplicate member ID %q", m.ID)
		}
		seenID[m.ID] = struct{}{}
		if len(m.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("threshold: member %q bad pubkey length %d", m.ID, len(m.PublicKey))
		}
		pkHex := hex.EncodeToString(m.PublicKey)
		if _, dup := seenPub[pkHex]; dup {
			return fmt.Errorf("threshold: duplicate member public key (id=%q)", m.ID)
		}
		seenPub[pkHex] = struct{}{}
	}
	return nil
}

// Canonical returns the deterministic byte encoding signed by member
// public keys. Members are sorted by ID before serialisation so two
// groups with the same membership but different list order hash to the
// same digest.
//
// Format (all integers big-endian):
//
//	u32 Version | u32 len(Origin) | Origin
//	u32 Threshold | u64 CreatedAt | u32 len(Members)
//	for each member (sorted by ID):
//	  u32 len(ID) | ID
//	  u32 len(PublicKey) | PublicKey
//	  u32 len(QuantumPublicKey) | QuantumPublicKey   (length 0 in classical mode)
//
// QuantumPublicKey is part of the digest so two groups with the same
// classical members but different quantum-pubkey assignments hash to
// different digests — defeats hybrid-downgrade by group substitution.
//
// Endpoint and Description are NOT in the canonical bytes — they are
// operational metadata that can change without invalidating signatures.
func (g *Group) Canonical() []byte {
	members := make([]*Member, len(g.Members))
	copy(members, g.Members)
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })

	var buf []byte
	var u32 [4]byte
	var u64 [8]byte

	binary.BigEndian.PutUint32(u32[:], g.Version)
	buf = append(buf, u32[:]...)
	put := func(b []byte) {
		binary.BigEndian.PutUint32(u32[:], uint32(len(b)))
		buf = append(buf, u32[:]...)
		buf = append(buf, b...)
	}
	put([]byte(g.Origin))
	binary.BigEndian.PutUint32(u32[:], g.Threshold)
	buf = append(buf, u32[:]...)
	binary.BigEndian.PutUint64(u64[:], uint64(g.CreatedAt))
	buf = append(buf, u64[:]...)
	binary.BigEndian.PutUint32(u32[:], uint32(len(members)))
	buf = append(buf, u32[:]...)
	for _, m := range members {
		put([]byte(m.ID))
		put(m.PublicKey)
		put(m.QuantumPublicKey)
	}
	return buf
}

// Digest is the SHA-256 of the canonical bytes. Used as the stable
// identifier for a group across rotation certs and storage indexing.
func (g *Group) Digest() []byte {
	sum := sha256.Sum256(g.Canonical())
	return sum[:]
}

// DigestHex is the hex-encoded Digest, suitable for logging.
func (g *Group) DigestHex() string { return hex.EncodeToString(g.Digest()) }

// MemberByID returns the member with the given ID, or nil.
func (g *Group) MemberByID(id string) *Member {
	for _, m := range g.Members {
		if m.ID == id {
			return m
		}
	}
	return nil
}

// Marshal returns JSON-encoded group bytes suitable for storage.
func (g *Group) Marshal() ([]byte, error) {
	return json.MarshalIndent(g, "", "  ")
}

// Unmarshal parses a JSON-encoded group and validates it.
func Unmarshal(data []byte) (*Group, error) {
	var g Group
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, err
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return &g, nil
}
