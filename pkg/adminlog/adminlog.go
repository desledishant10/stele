// Package adminlog provides a tamper-evident append-only journal of
// every admin-level mutation served by the operator's API: key
// rotations, producer enrollment/revocation, witness add/remove,
// threshold-group swaps. Each event is hash-chained to its predecessor
// and signed by the journal's private key (Ed25519, optionally with
// Dilithium3 in hybrid mode).
//
// Why this matters. The main stele log records what producers wrote.
// The read log records who looked at what. The ADMIN log records who
// changed the *rules*. If an attacker compromises the operator and
// quietly enrolls a producer they control or revokes a producer they
// don't want recording evidence against them, the admin log makes that
// action both detectable (anyone fetching /admin/log spots the entry)
// and non-repudiable (it's signed and chained).
//
// What this does NOT defend against: an attacker who controls the
// operator host AND the admin journal's signing key. That attacker can
// rewrite admin history. The mitigation is the same as for the main
// log — anchor admin journal checkpoints into the external Rekor
// transparency log on a regular cadence, so post-hoc rewrites are
// publicly detectable.
package adminlog

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

// Event is one entry in the admin log.
type Event struct {
	Index     uint64 `json:"index"`
	TimeNanos int64  `json:"time_ns"`
	PrevHash  []byte `json:"prev_hash"`

	// What changed.
	Action  string          `json:"action"`            // e.g. "rotate", "producer_register"
	Subject string          `json:"subject,omitempty"` // affected entity ID
	Outcome string          `json:"outcome"`           // "ok" | "error"
	Err     string          `json:"err,omitempty"`     // present when Outcome == "error"
	Details json.RawMessage `json:"details,omitempty"` // action-specific blob

	// Who did it (best-effort, from HTTP / mTLS layer).
	Actor     string `json:"actor,omitempty"`      // e.g. mTLS CN or X-Stele-Admin token
	CallerIP  string `json:"caller_ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`

	// Sealed fields.
	EventHash []byte `json:"event_hash"`
	PubKey    []byte `json:"pub_key"`
	Signature []byte `json:"signature"`

	// Hybrid mode (post-quantum).
	QuantumPubKey    []byte `json:"quantum_pub_key,omitempty"`
	QuantumSignature []byte `json:"quantum_signature,omitempty"`
}

// Canonical returns the deterministic byte sequence that gets signed.
// Fields are length-prefixed so re-marshalling cannot create
// ambiguity (e.g. an Actor that contains the same bytes as the next
// field's separator).
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
	put([]byte(e.Action))
	put([]byte(e.Subject))
	put([]byte(e.Outcome))
	put([]byte(e.Err))
	put(e.Details)
	put([]byte(e.Actor))
	put([]byte(e.CallerIP))
	put([]byte(e.UserAgent))
	put(e.QuantumPubKey)
	return buf
}

// Verify recomputes EventHash and validates the signature(s). Hybrid
// events require both Ed25519 and Dilithium3 signatures to pass.
func (e *Event) Verify() error {
	canon := e.Canonical()
	sum := sha256.Sum256(canon)
	if hex.EncodeToString(e.EventHash) != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("admin event %d: EventHash mismatch", e.Index)
	}
	if len(e.PubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("admin event %d: bad pubkey length %d", e.Index, len(e.PubKey))
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("admin event %d: bad sig length %d", e.Index, len(e.Signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(e.PubKey), canon, e.Signature) {
		return fmt.Errorf("admin event %d: classical signature invalid", e.Index)
	}
	if len(e.QuantumPubKey) > 0 || len(e.QuantumSignature) > 0 {
		if len(e.QuantumPubKey) != mode3.PublicKeySize {
			return fmt.Errorf("admin event %d: bad quantum pubkey length %d", e.Index, len(e.QuantumPubKey))
		}
		if len(e.QuantumSignature) != mode3.SignatureSize {
			return fmt.Errorf("admin event %d: bad quantum sig length %d", e.Index, len(e.QuantumSignature))
		}
		qp := &mode3.PublicKey{}
		if err := qp.UnmarshalBinary(e.QuantumPubKey); err != nil {
			return fmt.Errorf("admin event %d: decode quantum pubkey: %w", e.Index, err)
		}
		if !mode3.Verify(qp, canon, e.QuantumSignature) {
			return fmt.Errorf("admin event %d: quantum signature invalid", e.Index)
		}
	}
	return nil
}

// Journal is the admin-log writer + reader. Append-only; events are
// persisted to a JSON-lines file and fsync'd after each write.
type Journal struct {
	mu    sync.Mutex
	path  string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	qPriv *mode3.PrivateKey
	qPub  []byte
	size  uint64
	prev  []byte
}

// Open creates or opens a classical-mode admin journal at dir.
func Open(dir string) (*Journal, error) { return openJournal(dir, false) }

// OpenHybrid creates or opens an admin journal in hybrid mode.
func OpenHybrid(dir string) (*Journal, error) { return openJournal(dir, true) }

func openJournal(dir string, hybrid bool) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	j := &Journal{
		path: filepath.Join(dir, "admin.log"),
		prev: make([]byte, 32),
	}
	if err := j.loadOrCreateKey(filepath.Join(dir, "admin.key"), filepath.Join(dir, "admin.pub")); err != nil {
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

// PublicKey is the Ed25519 verification key.
func (j *Journal) PublicKey() ed25519.PublicKey { return j.pub }

// QuantumPublicKey is the Dilithium3 verification key (nil in classical mode).
func (j *Journal) QuantumPublicKey() []byte { return j.qPub }

// Size is the number of events in the journal.
func (j *Journal) Size() uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.size
}

// Action records a single admin action. `details` is optional; pass
// nil if the action has no payload (e.g. rotate).
func (j *Journal) Action(action, subject, outcome, errMsg string, details any, actor, callerIP, userAgent string) (*Event, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var raw json.RawMessage
	if details != nil {
		body, err := json.Marshal(details)
		if err != nil {
			return nil, fmt.Errorf("adminlog: marshal details: %w", err)
		}
		raw = body
	}
	ev := &Event{
		Index:     j.size,
		TimeNanos: time.Now().UnixNano(),
		PrevHash:  append([]byte(nil), j.prev...),
		Action:    action,
		Subject:   subject,
		Outcome:   outcome,
		Err:       errMsg,
		Details:   raw,
		Actor:     actor,
		CallerIP:  callerIP,
		UserAgent: userAgent,
		PubKey:    append([]byte(nil), j.pub...),
	}
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

	body, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("adminlog: marshal event: %w", err)
	}
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("adminlog: open: %w", err)
	}
	if _, err := f.Write(append(body, '\n')); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("adminlog: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("adminlog: fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("adminlog: close: %w", err)
	}
	j.size++
	j.prev = append([]byte(nil), ev.EventHash...)
	return ev, nil
}

// Range returns events [from, to). to == 0 means "to current size".
func (j *Journal) Range(from, to uint64) ([]*Event, error) {
	j.mu.Lock()
	if to == 0 || to > j.size {
		to = j.size
	}
	j.mu.Unlock()
	if from >= to {
		return []*Event{}, nil
	}
	f, err := os.Open(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []*Event{}, nil
		}
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var out []*Event
	for dec.More() {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			return nil, fmt.Errorf("adminlog range: %w", err)
		}
		if ev.Index >= from && ev.Index < to {
			ev2 := ev
			out = append(out, &ev2)
		}
		if ev.Index >= to {
			break
		}
	}
	return out, nil
}

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
			return fmt.Errorf("adminlog replay: %w", err)
		}
		if err := ev.Verify(); err != nil {
			return fmt.Errorf("adminlog replay: %w", err)
		}
		if prev == nil {
			if !allZeros(ev.PrevHash) {
				return fmt.Errorf("adminlog replay: first event PrevHash must be zero")
			}
			if ev.Index != 0 {
				return fmt.Errorf("adminlog replay: first event index must be 0, got %d", ev.Index)
			}
		} else {
			if ev.Index != prev.Index+1 {
				return fmt.Errorf("adminlog replay: index gap %d -> %d", prev.Index, ev.Index)
			}
			if hex.EncodeToString(ev.PrevHash) != hex.EncodeToString(prev.EventHash) {
				return fmt.Errorf("adminlog replay: event %d PrevHash does not chain", ev.Index)
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

func (j *Journal) loadOrCreateKey(keyPath, pubPath string) error {
	if buf, err := os.ReadFile(keyPath); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(buf)))
		if err != nil {
			return err
		}
		if len(raw) != ed25519.PrivateKeySize {
			return fmt.Errorf("adminlog: bad key length %d", len(raw))
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

func (j *Journal) loadOrCreateQuantum(dir string, hybrid bool) error {
	qKey := filepath.Join(dir, "admin-quantum.key")
	if buf, err := os.ReadFile(qKey); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(buf)))
		if err != nil {
			return err
		}
		priv := &mode3.PrivateKey{}
		if err := priv.UnmarshalBinary(raw); err != nil {
			return fmt.Errorf("adminlog quantum key: %w", err)
		}
		j.qPriv = priv
		qpub, err := priv.Public().(*mode3.PublicKey).MarshalBinary()
		if err != nil {
			return fmt.Errorf("adminlog: marshal Dilithium pubkey: %w", err)
		}
		j.qPub = qpub
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
	qpub, err := pub.MarshalBinary()
	if err != nil {
		return fmt.Errorf("adminlog: marshal new Dilithium pubkey: %w", err)
	}
	j.qPub = qpub
	body, err := priv.MarshalBinary()
	if err != nil {
		return err
	}
	if err := os.WriteFile(qKey, []byte(base64.StdEncoding.EncodeToString(body)+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "admin-quantum.pub"),
		[]byte(base64.StdEncoding.EncodeToString(j.qPub)+"\n"), 0o644)
}

func allZeros(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

var _ = errors.New // keep errors import live in case future error paths land
