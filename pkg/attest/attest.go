// Package attest defines the producer-side attestation that every log entry
// must carry before the operator will accept it.
//
// The threat this defends against: a malicious operator (or an attacker
// who has compromised the operator) cannot insert fabricated entries that
// appear to come from a legitimate producer, because they would have to
// forge a valid Envelope signature using the producer's private key.
//
// The Attestor interface abstracts over key location so a producer can use
// a software key for development, the OS keychain for unattended jobs, or
// a TPM2 / Secure Enclave / SGX-backed key for high-assurance deployments.
// The on-the-wire format does not change between these — only the
// Envelope.Evidence field carries platform-specific data the verifier can
// optionally inspect.
package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// AttestationType labels the kind of evidence in an Envelope.
type AttestationType string

const (
	TypeSoftware      AttestationType = "software"        // file-based Ed25519 key
	TypeKeychain      AttestationType = "keychain"        // OS keychain backed
	TypeTPM2          AttestationType = "tpm2"            // TPM 2.0 attested
	TypeSecureEnclave AttestationType = "secure_enclave"  // Apple Secure Enclave
	TypeSGX           AttestationType = "sgx"             // Intel SGX
	TypeSEV           AttestationType = "sev_snp"         // AMD SEV-SNP
)

// Envelope is what a producer sends to the operator. The operator never
// modifies it; it is incorporated verbatim into the log entry.
//
// Signature covers Canonical(), which excludes the Signature field itself.
// EvidenceHash is included in the signed bytes so the wire-format Evidence
// blob can be omitted from low-volume entries and re-fetched on demand
// while still being bound to the signature.
//
// Hybrid post-quantum: when QuantumPublicKey + QuantumSignature are
// set, the operator validates BOTH the Ed25519 signature AND the
// Dilithium3 signature. The quantum public key is part of the signed
// canonical bytes so an attacker who breaks Ed25519 in the future
// cannot strip the quantum half from a stored envelope.
type Envelope struct {
	ProducerID   string          `json:"producer_id"`
	TimeNanos    int64           `json:"time_ns"`
	Source       string          `json:"source"`
	Data         []byte          `json:"data"`
	PublicKey    []byte          `json:"public_key"`
	Type         AttestationType `json:"attestation_type"`
	EvidenceHash []byte          `json:"evidence_hash,omitempty"`
	Evidence     []byte          `json:"evidence,omitempty"`
	Signature    []byte          `json:"signature"`

	// Hybrid (post-quantum) extensions; omitempty for backward compat.
	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	QuantumSignature []byte `json:"quantum_signature,omitempty"`
}

// Canonical returns the deterministic byte encoding signed by the producer.
//
//	u32 len(ProducerID) || ProducerID
//	i64 TimeNanos
//	u32 len(Source)      || Source
//	u32 len(Data)        || Data
//	u32 len(PublicKey)   || PublicKey
//	u32 len(Type)        || Type
//	u32 len(EvidenceHash)|| EvidenceHash
//	u32 len(QuantumPublicKey) || QuantumPublicKey   (length 0 in classical mode)
//
// Both classical and post-quantum signatures cover the SAME canonical
// bytes, so the quantum half cannot be substituted with one signed
// over different envelope contents.
func (e *Envelope) Canonical() []byte {
	buf := make([]byte, 0, 256+len(e.Data)+len(e.Evidence)+len(e.QuantumPublicKey))
	put := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf = append(buf, l[:]...)
		buf = append(buf, b...)
	}
	put([]byte(e.ProducerID))
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], uint64(e.TimeNanos))
	buf = append(buf, u64[:]...)
	put([]byte(e.Source))
	put(e.Data)
	put(e.PublicKey)
	put([]byte(string(e.Type)))
	put(e.EvidenceHash)
	put(e.QuantumPublicKey) // length 0 in classical mode — still bound
	return buf
}

// Hash returns SHA-256 of the canonical bytes; used as a stable identifier.
func (e *Envelope) Hash() []byte {
	sum := sha256.Sum256(e.Canonical())
	return sum[:]
}

// Verify checks the envelope's signature(s). When QuantumSignature is
// non-empty, the Dilithium half MUST also verify against the
// QuantumPublicKey. If the envelope is hybrid but missing either
// quantum field, Verify returns an error (closes the downgrade path).
func (e *Envelope) Verify() error {
	if len(e.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("envelope: bad public key length %d", len(e.PublicKey))
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("envelope: bad signature length %d", len(e.Signature))
	}
	if len(e.Evidence) > 0 {
		want := sha256.Sum256(e.Evidence)
		if !bytesEqual(want[:], e.EvidenceHash) {
			return errors.New("envelope: EvidenceHash does not match Evidence")
		}
	}
	canon := e.Canonical()
	if !ed25519.Verify(ed25519.PublicKey(e.PublicKey), canon, e.Signature) {
		return errors.New("envelope: invalid producer signature (classical)")
	}
	// Hybrid: both quantum fields must be present together. A partial
	// state — e.g. QuantumPublicKey present but QuantumSignature empty
	// — is rejected to close downgrade attacks.
	if len(e.QuantumPublicKey) > 0 || len(e.QuantumSignature) > 0 {
		if len(e.QuantumPublicKey) != mode3.PublicKeySize {
			return fmt.Errorf("envelope: bad quantum public key length %d", len(e.QuantumPublicKey))
		}
		if len(e.QuantumSignature) != mode3.SignatureSize {
			return fmt.Errorf("envelope: bad quantum signature length %d", len(e.QuantumSignature))
		}
		qPub := &mode3.PublicKey{}
		if err := qPub.UnmarshalBinary(e.QuantumPublicKey); err != nil {
			return fmt.Errorf("envelope: decode quantum pubkey: %w", err)
		}
		if !mode3.Verify(qPub, canon, e.QuantumSignature) {
			return errors.New("envelope: invalid producer signature (quantum)")
		}
	}
	return nil
}

// Attestor is what producers use to sign an envelope.
type Attestor interface {
	ProducerID() string
	Type() AttestationType
	PublicKey() ed25519.PublicKey

	// Sign creates and signs an envelope for the given (source, data).
	// Implementations may attach platform-specific Evidence (TPM quote,
	// SEV attestation report, Secure Enclave secure boot chain, ...) that
	// downstream verifiers can inspect.
	Sign(source string, data []byte) (*Envelope, error)
}

// MarshalEvidence is a small helper for attestors that want to serialise
// structured evidence into the Envelope's Evidence field.
func MarshalEvidence(v any) ([]byte, error) {
	return json.Marshal(v)
}

// SignTime is exposed so tests can pin TimeNanos deterministically.
var SignTime = func() int64 { return time.Now().UnixNano() }

// ----- helpers -----

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
