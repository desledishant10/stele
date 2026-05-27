// Package readlog provides a tamper-evident append-only journal of every
// read operation served by the operator's API. Each event is signed and
// hash-chained, so an attacker cannot quietly delete or modify the
// record of who read what.
//
// Why this matters. The main stele log makes writes tamper-evident.
// But many real-world breaches are READS — an attacker pulls a sensitive
// entry to learn what is known about them, exfiltrate credentials, or
// scout the environment. Without a read log, the operator has no record
// of who read what.
//
// What this defends against: passive surveillance of the log itself.
// Combined with the honeylog (which alerts on canary reads), this turns
// every public read API call into auditable evidence.
//
// What this does NOT defend against: an attacker with direct disk access
// to the operator's BadgerDB. That attacker bypasses the API entirely.
// For that threat, plus the existing tamper-evident chain on entries,
// you also want HSM-backed operator keys + key-dir fsnotify alerts.
package readlog

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// Event is one record in the read log. Each event chains to its
// predecessor via PrevHash, and the EventHash is signed by the
// journal's private key. Tampering with any field of any past event
// breaks the chain.
type Event struct {
	Index     uint64 `json:"index"`
	TimeNanos int64  `json:"time_ns"`
	PrevHash  []byte `json:"prev_hash"`

	// What was read.
	EntryIdx  uint64 `json:"entry_idx"`
	LeafHash  []byte `json:"leaf_hash"`
	Operation string `json:"operation"` // "get_entry", "range", etc.

	// Who read it (best effort — from HTTP layer).
	CallerIP  string `json:"caller_ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`

	// Sealed fields.
	EventHash []byte `json:"event_hash"`
	Signature []byte `json:"signature"` // ed25519 over Canonical()
	PubKey    []byte `json:"pub_key"`   // journal pubkey (for verification convenience)

	// Hybrid extensions; omitempty for backward compat.
	QuantumPubKey    []byte `json:"quantum_pub_key,omitempty"`
	QuantumSignature []byte `json:"quantum_signature,omitempty"`
}

// Canonical returns the deterministic byte encoding signed by the
// journal's key. Format (all integers big-endian):
//
//	u64 Index | i64 TimeNanos | u32 prevLen | Prev
//	u64 EntryIdx | u32 leafLen | Leaf
//	u32 opLen | op
//	u32 ipLen | ip
//	u32 uaLen | ua
//	u32 qPubLen | qPub                 (length 0 in classical mode)
//
// QuantumPubKey is part of the signed bytes so an attacker cannot
// strip the quantum half without invalidating the classical signature.
func (e *Event) Canonical() []byte {
	var buf []byte
	var u32 [4]byte
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], e.Index)
	buf = append(buf, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], uint64(e.TimeNanos))
	buf = append(buf, u64[:]...)
	put := func(b []byte) {
		binary.BigEndian.PutUint32(u32[:], uint32(len(b)))
		buf = append(buf, u32[:]...)
		buf = append(buf, b...)
	}
	put(e.PrevHash)
	binary.BigEndian.PutUint64(u64[:], e.EntryIdx)
	buf = append(buf, u64[:]...)
	put(e.LeafHash)
	put([]byte(e.Operation))
	put([]byte(e.CallerIP))
	put([]byte(e.UserAgent))
	put(e.QuantumPubKey)
	return buf
}

// Verify recomputes EventHash + checks the signature(s). When the
// event carries a QuantumPubKey, the Dilithium half must also verify.
func (e *Event) Verify() error {
	canon := e.Canonical()
	sum := sha256.Sum256(canon)
	if hex.EncodeToString(e.EventHash) != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("read event %d: EventHash mismatch", e.Index)
	}
	if len(e.PubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("read event %d: bad pubkey length %d", e.Index, len(e.PubKey))
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("read event %d: bad sig length %d", e.Index, len(e.Signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(e.PubKey), canon, e.Signature) {
		return fmt.Errorf("read event %d: classical signature invalid", e.Index)
	}
	if len(e.QuantumPubKey) > 0 || len(e.QuantumSignature) > 0 {
		if len(e.QuantumPubKey) != mode3.PublicKeySize {
			return fmt.Errorf("read event %d: bad quantum pubkey length %d", e.Index, len(e.QuantumPubKey))
		}
		if len(e.QuantumSignature) != mode3.SignatureSize {
			return fmt.Errorf("read event %d: bad quantum sig length %d", e.Index, len(e.QuantumSignature))
		}
		qp := &mode3.PublicKey{}
		if err := qp.UnmarshalBinary(e.QuantumPubKey); err != nil {
			return fmt.Errorf("read event %d: decode quantum pubkey: %w", e.Index, err)
		}
		if !mode3.Verify(qp, canon, e.QuantumSignature) {
			return fmt.Errorf("read event %d: quantum signature invalid", e.Index)
		}
	}
	return nil
}

// Journal is the read-log writer + reader. Events are appended in
// memory + persisted to an append-only file, fsync'd after each write.
type Journal struct {
	mu    sync.Mutex
	path  string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	qPriv *mode3.PrivateKey
	qPub  []byte
	size  uint64
	prev  []byte // EventHash of the most recent event (32 zero bytes if empty)
}

// Open creates or opens a classical-mode journal at `dir`.
func Open(dir string) (*Journal, error) { return openJournal(dir, false) }

// OpenHybrid creates or opens a journal in hybrid mode.
func OpenHybrid(dir string) (*Journal, error) { return openJournal(dir, true) }

func openJournal(dir string, hybrid bool) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	j := &Journal{
		path: filepath.Join(dir, "journal.log"),
		prev: make([]byte, 32),
	}
	if err := j.loadOrCreateKey(filepath.Join(dir, "journal.key"), filepath.Join(dir, "journal.pub")); err != nil {
		return nil, err
	}
	if err := j.loadOrCreateQuantum(dir, hybrid); err != nil {
		return nil, err
	}
	if err := j.replay(); err != nil {
		return nil, err
	}
	return j, nil
}

// IsHybrid reports whether the journal signs every event in hybrid mode.
func (j *Journal) IsHybrid() bool { return j.qPriv != nil }

// QuantumPublicKey returns the journal's Dilithium3 pubkey bytes
// (nil in classical mode).
func (j *Journal) QuantumPublicKey() []byte { return j.qPub }

func (j *Journal) loadOrCreateQuantum(dir string, hybrid bool) error {
	qKey := filepath.Join(dir, "journal-quantum.key")
	if buf, err := os.ReadFile(qKey); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(buf)))
		if err != nil {
			return err
		}
		priv := &mode3.PrivateKey{}
		if err := priv.UnmarshalBinary(raw); err != nil {
			return fmt.Errorf("readlog quantum key: %w", err)
		}
		j.qPriv = priv
		j.qPub, _ = priv.Public().(*mode3.PublicKey).MarshalBinary()
		return nil
	}
	if !hybrid {
		return nil
	}
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	j.qPriv = priv
	j.qPub, _ = pub.MarshalBinary()
	body, err := priv.MarshalBinary()
	if err != nil {
		return err
	}
	if err := os.WriteFile(qKey, []byte(base64.StdEncoding.EncodeToString(body)+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "journal-quantum.pub"),
		[]byte(base64.StdEncoding.EncodeToString(j.qPub)+"\n"), 0o644)
}

func (j *Journal) loadOrCreateKey(keyPath, pubPath string) error {
	if buf, err := os.ReadFile(keyPath); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(buf)))
		if err != nil {
			return err
		}
		if len(raw) != ed25519.PrivateKeySize {
			return fmt.Errorf("readlog: bad key length %d", len(raw))
		}
		j.priv = ed25519.PrivateKey(raw)
		j.pub = j.priv.Public().(ed25519.PublicKey)
		return nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	j.priv = priv
	j.pub = pub
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
}

// replay walks the on-disk journal, verifying every event in order.
// Any chain break or invalid signature aborts startup so the operator
// cannot serve from a tampered read log.
func (j *Journal) replay() error {
	f, err := os.Open(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var prev *Event
	for dec.More() {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			return fmt.Errorf("readlog replay: %w", err)
		}
		if err := ev.Verify(); err != nil {
			return fmt.Errorf("readlog replay: %w", err)
		}
		if prev == nil {
			if !allZeros(ev.PrevHash) {
				return fmt.Errorf("readlog replay: first event PrevHash must be zero")
			}
			if ev.Index != 0 {
				return fmt.Errorf("readlog replay: first event index must be 0, got %d", ev.Index)
			}
		} else {
			if ev.Index != prev.Index+1 {
				return fmt.Errorf("readlog replay: event index gap %d -> %d", prev.Index, ev.Index)
			}
			if hex.EncodeToString(ev.PrevHash) != hex.EncodeToString(prev.EventHash) {
				return fmt.Errorf("readlog replay: event %d PrevHash does not chain", ev.Index)
			}
		}
		prev = &ev
	}
	if prev != nil {
		j.size = prev.Index + 1
		j.prev = append([]byte(nil), prev.EventHash...)
	}
	return nil
}

// Append seals a new ReadEvent and persists it. Hybrid journals
// produce both Ed25519 and Dilithium3 signatures over the same
// canonical bytes.
func (j *Journal) Append(entryIdx uint64, leafHash []byte, op, callerIP, userAgent string) (*Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	ev := &Event{
		Index:     j.size,
		TimeNanos: time.Now().UnixNano(),
		PrevHash:  append([]byte(nil), j.prev...),
		EntryIdx:  entryIdx,
		LeafHash:  append([]byte(nil), leafHash...),
		Operation: op,
		CallerIP:  callerIP,
		UserAgent: userAgent,
		PubKey:    append([]byte(nil), j.pub...),
	}
	// Bind the quantum pubkey into canonical bytes BEFORE signing.
	if j.qPub != nil {
		ev.QuantumPubKey = append([]byte(nil), j.qPub...)
	}
	canon := ev.Canonical()
	sum := sha256.Sum256(canon)
	ev.EventHash = sum[:]
	ev.Signature = ed25519.Sign(j.priv, canon)
	if j.qPriv != nil {
		qsig := make([]byte, mode3.SignatureSize)
		mode3.SignTo(j.qPriv, canon, qsig)
		ev.QuantumSignature = qsig
	}

	// Append the JSON-encoded event to the journal file, fsync, advance
	// in-memory state.
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(append(body, '\n')); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	j.size++
	j.prev = ev.EventHash
	return ev, nil
}

// Size returns the number of events in the journal.
func (j *Journal) Size() uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.size
}

// PublicKey returns the journal's public key.
func (j *Journal) PublicKey() ed25519.PublicKey { return j.pub }

// Range returns events whose Index lies in [from, to). Used by the
// auditing endpoint. Memory-efficient streaming would be better at
// scale; this is fine for read logs up to a few million entries.
func (j *Journal) Range(from, to uint64) ([]*Event, error) {
	if to <= from {
		return nil, errors.New("readlog: to <= from")
	}
	if to-from > 10_000 {
		return nil, errors.New("readlog: range too large (max 10000)")
	}
	f, err := os.Open(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var out []*Event
	for dec.More() {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			return nil, err
		}
		if ev.Index < from {
			continue
		}
		if ev.Index >= to {
			break
		}
		out = append(out, &ev)
	}
	return out, nil
}

func allZeros(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
