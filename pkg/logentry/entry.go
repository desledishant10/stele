// Package logentry defines the canonical record format for a single entry
// in the stele log.
//
// Three cryptographic bindings live in an entry:
//
//  1. Envelope.Signature — a producer-side Ed25519 signature, made by the
//     attestor (software / keychain / TPM2 / etc.), proving the data came
//     from a registered producer.
//
//  2. EntryHash — SHA-256 of the entry's canonical bytes. Each entry's
//     PrevHash field equals the previous entry's EntryHash, creating a
//     hash chain.
//
//  3. LeafHash — RFC 6962 leaf hash of the canonical bytes, appended to
//     the Merkle tree.
//
// Because Canonical() includes a hash of the Envelope, tampering with any
// envelope field is detected the same way as tampering with operator
// metadata.
package logentry

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/merkle"
)

// Entry is one record in the log.
type Entry struct {
	Index     uint64           `json:"index"`
	TimeNanos int64            `json:"time_ns"`
	PrevHash  []byte           `json:"prev_hash"`
	Envelope  *attest.Envelope `json:"envelope"`
	Honeypot  bool             `json:"honeypot,omitempty"` // canary entries fire alerts on lookup
	EntryHash []byte           `json:"entry_hash"`
	LeafHash  []byte           `json:"leaf_hash"`
}

// ZeroHash is the all-zeros 32-byte hash used as PrevHash for the very
// first entry in a log.
var ZeroHash = make([]byte, 32)

// Canonical returns the deterministic byte encoding used for hashing.
// Format (all integers big-endian):
//
//	u64 Index | i64 TimeNanos | u32 prevLen | Prev | u32 envHashLen | EnvHash | u8 Honeypot
func (e *Entry) Canonical() []byte {
	prev := e.PrevHash
	if len(prev) == 0 {
		prev = ZeroHash
	}
	envHash := make([]byte, 32)
	if e.Envelope != nil {
		envHash = e.Envelope.Hash()
	}
	buf := make([]byte, 0, 8+8+4+len(prev)+4+len(envHash)+1)
	var u64 [8]byte
	var u32 [4]byte
	binary.BigEndian.PutUint64(u64[:], e.Index)
	buf = append(buf, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], uint64(e.TimeNanos))
	buf = append(buf, u64[:]...)
	binary.BigEndian.PutUint32(u32[:], uint32(len(prev)))
	buf = append(buf, u32[:]...)
	buf = append(buf, prev...)
	binary.BigEndian.PutUint32(u32[:], uint32(len(envHash)))
	buf = append(buf, u32[:]...)
	buf = append(buf, envHash...)
	if e.Honeypot {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	return buf
}

// Seal computes EntryHash and LeafHash and stores them on the entry.
// Callers must have set Envelope before calling Seal.
func (e *Entry) Seal() {
	canon := e.Canonical()
	sum := sha256.Sum256(canon)
	e.EntryHash = sum[:]
	e.LeafHash = merkle.Hasher.HashLeaf(canon)
}

// Verify recomputes EntryHash and LeafHash from the canonical bytes,
// checks they match, and verifies the envelope's producer signature.
// It does not check the hash chain or Merkle proof — those are higher
// level operations.
func (e *Entry) Verify() error {
	if e.Envelope == nil {
		return fmt.Errorf("entry %d: missing envelope", e.Index)
	}
	if err := e.Envelope.Verify(); err != nil {
		return fmt.Errorf("entry %d: envelope: %w", e.Index, err)
	}
	canon := e.Canonical()
	sum := sha256.Sum256(canon)
	if !equalBytes(e.EntryHash, sum[:]) {
		return fmt.Errorf("entry %d: EntryHash mismatch (have %x, want %x)",
			e.Index, e.EntryHash, sum[:])
	}
	leaf := merkle.Hasher.HashLeaf(canon)
	if !equalBytes(e.LeafHash, leaf) {
		return fmt.Errorf("entry %d: LeafHash mismatch (have %x, want %x)",
			e.Index, e.LeafHash, leaf)
	}
	return nil
}

// VerifyChain confirms that `e` correctly follows `prev`. For the first
// entry, pass prev == nil.
func (e *Entry) VerifyChain(prev *Entry) error {
	if prev == nil {
		if !equalBytes(e.PrevHash, ZeroHash) {
			return fmt.Errorf("entry 0: PrevHash must be zero")
		}
		if e.Index != 0 {
			return fmt.Errorf("first entry must have index 0, got %d", e.Index)
		}
		return nil
	}
	if e.Index != prev.Index+1 {
		return fmt.Errorf("entry %d: expected index %d", e.Index, prev.Index+1)
	}
	if !equalBytes(e.PrevHash, prev.EntryHash) {
		return fmt.Errorf("entry %d: PrevHash %x does not chain to entry %d (%x)",
			e.Index, e.PrevHash, prev.Index, prev.EntryHash)
	}
	return nil
}

// New constructs an entry wrapping a producer envelope. The operator
// assigns Index, TimeNanos, and PrevHash; the envelope was signed by the
// producer at envelope creation time. Honeypot flags the entry as a
// canary — see pkg/honeylog for the consumption side.
func New(idx uint64, prevEntry *Entry, env *attest.Envelope, honeypot bool) *Entry {
	prev := append([]byte(nil), ZeroHash...)
	if prevEntry != nil {
		prev = append([]byte(nil), prevEntry.EntryHash...)
	}
	e := &Entry{
		Index:     idx,
		TimeNanos: time.Now().UnixNano(),
		PrevHash:  prev,
		Envelope:  env,
		Honeypot:  honeypot,
	}
	e.Seal()
	return e
}

// Marshal serialises the entry to JSON. Binary fields use base64.
func (e *Entry) Marshal() ([]byte, error) { return json.Marshal(e) }

// Unmarshal parses a JSON-encoded entry.
func Unmarshal(buf []byte) (*Entry, error) {
	var e Entry
	if err := json.Unmarshal(buf, &e); err != nil {
		return nil, err
	}
	if e.EntryHash == nil || e.LeafHash == nil {
		return nil, errors.New("entry missing EntryHash or LeafHash")
	}
	return &e, nil
}

// HexHashes is a small helper for human-readable logging.
func (e *Entry) HexHashes() (entryHex, leafHex, prevHex string) {
	return hex.EncodeToString(e.EntryHash),
		hex.EncodeToString(e.LeafHash),
		hex.EncodeToString(e.PrevHash)
}

func equalBytes(a, b []byte) bool {
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
