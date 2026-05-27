package storage

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/dgraph-io/badger/v4"
)

// Producer is the operator's record of an entity allowed to submit entries.
//
// Two protection levels are supported:
//
//   1. Legacy registry mode (Signature == nil): the record is a
//      writeable JSON blob trusted because the operator's admin API
//      put it here. An attacker with disk access (or the admin API)
//      can mutate it; the protection is operational, not cryptographic.
//
//   2. Enrollment mode (Signature != nil): the record carries an
//      Ed25519 signature by the operator's active fwdsec key over the
//      enrollment-relevant fields. core.Log can be configured to
//      REQUIRE enrollment, in which case Append refuses any producer
//      that doesn't carry a verifiable signature against the chain
//      pubkey for OperatorEpoch.
//
// QuantumPublicKey, when present, switches this producer to hybrid
// mode: every envelope it submits MUST carry a matching Dilithium3
// public key AND a valid Dilithium3 signature over the same canonical
// bytes. core.Log.Append refuses non-hybrid envelopes from hybrid
// producers (closes the downgrade attack at ingest).
type Producer struct {
	ID              string `json:"id"`
	PublicKey       []byte `json:"public_key"`        // raw Ed25519 (32 bytes)
	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"` // Dilithium3 (1952 bytes), omitted in classical mode
	AttestationType string `json:"attestation_type"`  // declared at registration
	Description     string `json:"description,omitempty"`
	RegisteredAt    int64  `json:"registered_at"` // unix nano

	// Enrollment ceremony fields. All signed-over by Signature.
	// Scope is a free-form label naming the authorisation boundary,
	// e.g. "logs:audit" or "billing:invoices". The operator decides
	// what scopes mean; stele just records and presents them.
	Scope         string `json:"scope,omitempty"`
	IssuedAt      int64  `json:"issued_at,omitempty"`       // unix nano (signing time)
	ExpiresAt     int64  `json:"expires_at,omitempty"`      // 0 = never expires
	OperatorEpoch uint64 `json:"operator_epoch,omitempty"`  // chain epoch that signed
	Signature     []byte `json:"signature,omitempty"`       // Ed25519 over Canonical()

	// Hybrid post-quantum signature. Required (and only present) when
	// QuantumPublicKey is non-empty AND the operator chain is hybrid.
	QuantumOperatorPubKey []byte `json:"quantum_operator_pub_key,omitempty"`
	QuantumSignature      []byte `json:"quantum_signature,omitempty"`

	// Revocation. Already-logged entries from this producer remain
	// valid because each entry's envelope was signed by the producer
	// at the time and the log is immutable. Future entries are
	// refused by core.Log.Append.
	Revoked      bool   `json:"revoked"`
	RevokedAt    int64  `json:"revoked_at,omitempty"`
	RevokeReason string `json:"revoke_reason,omitempty"`

	// Challenge-response (proof-of-possession) fields. When non-empty,
	// the enrollment was completed via a two-step ceremony: the
	// producer signed a server-issued challenge containing
	// CanonicalEnrollment() + ChallengeNonce, proving control of the
	// private key matching PublicKey at enrollment time. Verifiers
	// who need this stronger guarantee call VerifyConsent.
	//
	// Legacy unilateral enrollments (operator vouches without proof
	// of possession) leave these empty; --require-challenge-response
	// mode refuses such enrollments at Append time.
	ChallengeNonce            []byte `json:"challenge_nonce,omitempty"`
	ChallengeSignature        []byte `json:"challenge_signature,omitempty"`
	QuantumChallengeSignature []byte `json:"quantum_challenge_signature,omitempty"`
}

// ChallengeBytes returns the deterministic bytes the PRODUCER must
// sign to demonstrate possession of the private key matching
// PublicKey. It binds the producer's signature to:
//
//   - the exact enrollment terms (via CanonicalEnrollment)
//   - a one-time server-issued nonce (so the signature can't be
//     replayed against a different enrollment)
//
// Returns nil if ChallengeNonce isn't set (legacy / pre-challenge
// records).
func (p *Producer) ChallengeBytes() []byte {
	if len(p.ChallengeNonce) == 0 {
		return nil
	}
	var buf []byte
	buf = append(buf, []byte("stele-enroll-challenge/v0\n")...)
	canon := p.CanonicalEnrollment()
	buf = append(buf, canon...)
	buf = append(buf, p.ChallengeNonce...)
	return buf
}

// HasChallengeResponse reports whether the producer's enrollment
// carries proof-of-possession (a producer-side signature over the
// challenge).
func (p *Producer) HasChallengeResponse() bool {
	return len(p.ChallengeSignature) > 0
}

// VerifyConsent verifies the producer's signature(s) over the challenge
// bytes, proving they consented to these enrollment terms and held
// the corresponding private key. In hybrid mode (QuantumPublicKey
// present), both classical and quantum signatures must verify.
//
// Returns nil if the proof is valid, an error otherwise. Returns a
// specific sentinel error if the record carries no challenge response
// at all — callers in strict-consent mode should treat that as
// rejection.
func (p *Producer) VerifyConsent() error {
	if !p.HasChallengeResponse() {
		return ErrNoChallengeResponse
	}
	if len(p.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("consent: producer pubkey wrong length %d", len(p.PublicKey))
	}
	if len(p.ChallengeSignature) != ed25519.SignatureSize {
		return fmt.Errorf("consent: classical signature wrong length %d", len(p.ChallengeSignature))
	}
	challenge := p.ChallengeBytes()
	if !ed25519.Verify(ed25519.PublicKey(p.PublicKey), challenge, p.ChallengeSignature) {
		return errors.New("consent: classical signature invalid")
	}
	// Hybrid: if the producer registered a quantum pubkey, they MUST
	// have also signed the challenge with the matching Dilithium key.
	// Refuses downgrade attempts at consent time.
	if len(p.QuantumPublicKey) > 0 {
		if len(p.QuantumChallengeSignature) != mode3.SignatureSize {
			return fmt.Errorf("consent: quantum signature wrong length %d", len(p.QuantumChallengeSignature))
		}
		qp := &mode3.PublicKey{}
		if err := qp.UnmarshalBinary(p.QuantumPublicKey); err != nil {
			return fmt.Errorf("consent: decode quantum pubkey: %w", err)
		}
		if !mode3.Verify(qp, challenge, p.QuantumChallengeSignature) {
			return errors.New("consent: quantum signature invalid")
		}
	}
	return nil
}

// ErrNoChallengeResponse signals that a Producer carries no
// challenge-response evidence. Callers in strict mode should refuse;
// callers in legacy/permissive mode can fall through to the looser
// VerifyEnrollment check.
var ErrNoChallengeResponse = errors.New("producer carries no challenge response")

// CanonicalEnrollment returns the deterministic byte sequence the
// enrollment fields are signed over. Fields are length-prefixed with
// big-endian u32 so a Scope that contains zero bytes can't collide
// with the next field's separator.
//
// Fields included: ID, PublicKey, QuantumPublicKey, Scope, IssuedAt,
// ExpiresAt, OperatorEpoch, AttestationType. Description,
// RegisteredAt, and Revoked-state fields are explicitly NOT signed —
// they're operational metadata the operator can adjust without
// reissuing the enrollment.
func (p *Producer) CanonicalEnrollment() []byte {
	var buf []byte
	var u32 [4]byte
	var u64 [8]byte
	put := func(b []byte) {
		binary.BigEndian.PutUint32(u32[:], uint32(len(b)))
		buf = append(buf, u32[:]...)
		buf = append(buf, b...)
	}
	buf = append(buf, []byte("stele-enrollment/v0\n")...)
	put([]byte(p.ID))
	put(p.PublicKey)
	put(p.QuantumPublicKey)
	put([]byte(p.Scope))
	put([]byte(p.AttestationType))
	binary.BigEndian.PutUint64(u64[:], uint64(p.IssuedAt))
	buf = append(buf, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], uint64(p.ExpiresAt))
	buf = append(buf, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], p.OperatorEpoch)
	buf = append(buf, u64[:]...)
	return buf
}

// HasEnrollment reports whether this Producer carries a signed
// enrollment (any non-nil Signature). Legacy registry-only records
// return false.
func (p *Producer) HasEnrollment() bool {
	return len(p.Signature) > 0
}

// IsExpired reports whether the enrollment has passed its ExpiresAt
// (zero = never expires).
func (p *Producer) IsExpired(now time.Time) bool {
	if p.ExpiresAt == 0 {
		return false
	}
	return now.UnixNano() >= p.ExpiresAt
}

// VerifyEnrollment checks the enrollment signature against the
// operator's chain pubkey at OperatorEpoch. Returns an error if:
//   - the producer carries no signature (call HasEnrollment first
//     to distinguish absent from invalid),
//   - OperatorEpoch isn't present in the chain,
//   - the classical signature doesn't verify,
//   - hybrid: the quantum signature doesn't verify against the
//     operator chain's epoch-N quantum pubkey.
//
// chainPubKey is the function that maps an epoch number to the
// operator's classical pubkey at that epoch; qChainPubKey does the
// same for quantum pubkeys. Implementations live in pkg/fwdsec but
// pkg/storage stays decoupled.
func (p *Producer) VerifyEnrollment(
	chainPubKey func(epoch uint64) ed25519.PublicKey,
	qChainPubKey func(epoch uint64) []byte,
) error {
	if !p.HasEnrollment() {
		return errors.New("producer carries no enrollment signature")
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("enrollment classical signature wrong length %d", len(p.Signature))
	}
	opPub := chainPubKey(p.OperatorEpoch)
	if opPub == nil {
		return fmt.Errorf("enrollment epoch %d not found in operator chain", p.OperatorEpoch)
	}
	canon := p.CanonicalEnrollment()
	if !ed25519.Verify(opPub, canon, p.Signature) {
		return errors.New("enrollment classical signature invalid")
	}
	// Hybrid: when either quantum field is set, both must be set AND
	// verify against the chain's epoch quantum pubkey.
	if len(p.QuantumSignature) > 0 || len(p.QuantumOperatorPubKey) > 0 {
		if len(p.QuantumSignature) != mode3.SignatureSize {
			return fmt.Errorf("enrollment quantum signature wrong length %d", len(p.QuantumSignature))
		}
		if len(p.QuantumOperatorPubKey) != mode3.PublicKeySize {
			return fmt.Errorf("enrollment quantum operator pubkey wrong length %d", len(p.QuantumOperatorPubKey))
		}
		expectedQ := qChainPubKey(p.OperatorEpoch)
		if expectedQ == nil {
			return fmt.Errorf("enrollment claims quantum signature but operator chain has no quantum key at epoch %d", p.OperatorEpoch)
		}
		if !bytesEqual(p.QuantumOperatorPubKey, expectedQ) {
			return errors.New("enrollment quantum operator pubkey does not match chain")
		}
		qp := &mode3.PublicKey{}
		if err := qp.UnmarshalBinary(p.QuantumOperatorPubKey); err != nil {
			return fmt.Errorf("enrollment decode quantum operator pubkey: %w", err)
		}
		if !mode3.Verify(qp, canon, p.QuantumSignature) {
			return errors.New("enrollment quantum signature invalid")
		}
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
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

var prefixProducer = []byte("producer/")

func producerKey(id string) []byte {
	k := make([]byte, len(prefixProducer)+len(id))
	copy(k, prefixProducer)
	copy(k[len(prefixProducer):], id)
	return k
}

// RegisterProducer creates or updates a producer record. Re-registering
// the same ID with a different key is intentionally allowed (it's how
// you rotate a producer's key) but the change is itself logged into the
// main log by the caller for accountability.
func (s *Store) RegisterProducer(p *Producer) error {
	if p == nil || p.ID == "" {
		return errors.New("storage: producer requires id")
	}
	if len(p.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("storage: producer public key wrong length %d", len(p.PublicKey))
	}
	if p.RegisteredAt == 0 {
		p.RegisteredAt = time.Now().UnixNano()
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(producerKey(p.ID), body)
	})
}

// GetProducer fetches a producer's record by ID.
func (s *Store) GetProducer(id string) (*Producer, error) {
	var p *Producer
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(producerKey(id))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return fmt.Errorf("storage: producer %q not registered", id)
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			var rec Producer
			if err := json.Unmarshal(val, &rec); err != nil {
				return err
			}
			p = &rec
			return nil
		})
	})
	return p, err
}

// ListProducers iterates over every registered producer in lexicographic
// ID order.
func (s *Store) ListProducers(fn func(*Producer) error) error {
	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefixProducer); it.ValidForPrefix(prefixProducer); it.Next() {
			err := it.Item().Value(func(val []byte) error {
				var rec Producer
				if err := json.Unmarshal(val, &rec); err != nil {
					return err
				}
				return fn(&rec)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokeProducer marks a producer as revoked; the operator will refuse
// new entries from a revoked producer but already-logged entries remain.
// Optional `reason` is recorded for audit purposes.
func (s *Store) RevokeProducer(id, reason string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(producerKey(id))
		if err != nil {
			return err
		}
		var rec Producer
		err = item.Value(func(val []byte) error { return json.Unmarshal(val, &rec) })
		if err != nil {
			return err
		}
		rec.Revoked = true
		rec.RevokedAt = time.Now().UnixNano()
		rec.RevokeReason = reason
		body, err := json.Marshal(&rec)
		if err != nil {
			return err
		}
		return txn.Set(producerKey(id), body)
	})
}
