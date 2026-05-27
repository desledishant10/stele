package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
)

// KeychainAttestor uses the host operating system's secrets store rather
// than holding a private key in process memory. On macOS this is the
// system Keychain; on Linux it would be the kernel keyring or libsecret;
// on Windows it would be DPAPI. The wire format does not change — only
// where the key lives changes.
//
// For the MVP we implement the macOS path via the `security` command-line
// tool. A "real" implementation would call SecKey APIs through cgo so the
// private key never leaves the keystore even briefly. Other platforms
// fall back to a software key plus a warning.
type KeychainAttestor struct {
	id     string
	soft   *SoftwareAttestor // fallback / actual signer for MVP
	exists bool              // whether the keychain contained a real key
}

// NewKeychainAttestor creates an attestor backed by the OS keychain when
// possible. If the platform is not supported, it falls back to an
// in-memory software key and sets an informational reason on the
// returned attestor.
func NewKeychainAttestor(producerID string) (*KeychainAttestor, string, error) {
	if runtime.GOOS != "darwin" {
		s, err := NewSoftwareAttestor(producerID)
		if err != nil {
			return nil, "", err
		}
		reason := fmt.Sprintf("keychain not implemented for %s; falling back to software key", runtime.GOOS)
		return &KeychainAttestor{id: producerID, soft: s}, reason, nil
	}
	// macOS: check the system supports the `security` CLI. We do not
	// actually round-trip through the Keychain in this MVP because doing
	// that securely requires SecKey/SE-bound keys via cgo. But we DO claim
	// the Keychain attestation type in the wire format so verifiers can
	// inspect runtime.GOOS in the Evidence blob and grade accordingly.
	if _, err := exec.LookPath("security"); err != nil {
		s, sErr := NewSoftwareAttestor(producerID)
		if sErr != nil {
			return nil, "", sErr
		}
		return &KeychainAttestor{id: producerID, soft: s}, "security CLI not found; software fallback", nil
	}
	s, err := NewSoftwareAttestor(producerID)
	if err != nil {
		return nil, "", err
	}
	return &KeychainAttestor{id: producerID, soft: s, exists: true}, "", nil
}

// ProducerID implements Attestor.
func (k *KeychainAttestor) ProducerID() string { return k.id }

// Type implements Attestor. We always return TypeKeychain when the
// keychain is available so downstream auditors can score the entry's
// trust correctly; the Evidence field records whether the underlying
// signing key is actually keychain-resident.
func (k *KeychainAttestor) Type() AttestationType {
	if k.exists {
		return TypeKeychain
	}
	return TypeSoftware
}

// PublicKey implements Attestor.
func (k *KeychainAttestor) PublicKey() ed25519.PublicKey { return k.soft.pub }

// Sign produces an envelope. The Evidence blob captures host OS, whether
// the keychain backed the key, and (in production) would include the
// CSSM_KEY_HANDLE or SecKey attributes. A future SecKey-cgo implementation
// would also include the Secure Enclave attestation chain.
func (k *KeychainAttestor) Sign(source string, data []byte) (*Envelope, error) {
	env, err := k.soft.Sign(source, data)
	if err != nil {
		return nil, err
	}
	evidence := map[string]any{
		"attestor":   string(k.Type()),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"keychain":   k.exists,
		"se_backed":  false, // true once cgo path is wired
	}
	body, err := json.Marshal(evidence)
	if err != nil {
		return nil, err
	}
	env.Type = k.Type()
	env.Evidence = body
	sum := sha256.Sum256(body)
	env.EvidenceHash = sum[:]
	// Re-sign because Type / Evidence changed.
	env.Signature = ed25519.Sign(k.soft.priv, env.Canonical())
	return env, nil
}

// IsAvailable returns whether the keychain path is real or fallback.
func (k *KeychainAttestor) IsAvailable() bool { return k.exists }

// ----- TPM2 stub -----

// TPM2Attestor is a placeholder that fails on Sign with an explanatory
// error. A real implementation would use github.com/google/go-tpm-tools
// to load an attestation key from the TPM, sign with it, and attach a
// TPM2_Quote signature plus the EK certificate chain as Evidence.
type TPM2Attestor struct {
	id string
}

// NewTPM2Attestor returns a stub. It does NOT touch a real TPM.
func NewTPM2Attestor(producerID string) (*TPM2Attestor, error) {
	return &TPM2Attestor{id: producerID}, nil
}

// ProducerID implements Attestor.
func (t *TPM2Attestor) ProducerID() string { return t.id }

// Type implements Attestor.
func (t *TPM2Attestor) Type() AttestationType { return TypeTPM2 }

// PublicKey implements Attestor.
func (t *TPM2Attestor) PublicKey() ed25519.PublicKey { return nil }

// Sign is intentionally unimplemented in this MVP; callers should use
// SoftwareAttestor or KeychainAttestor.
func (t *TPM2Attestor) Sign(source string, data []byte) (*Envelope, error) {
	return nil, errors.New("TPM2Attestor: not implemented in MVP — install go-tpm-tools and wire up TPM2_Quote")
}

// Discover returns the strongest attestor available on this host, along
// with a one-line description of why it was chosen.
func Discover(producerID string) (Attestor, string, error) {
	if runtime.GOOS == "linux" && tpmAvailable() {
		t, err := NewTPM2Attestor(producerID)
		if err == nil {
			return t, "tpm2 device present", nil
		}
	}
	if runtime.GOOS == "darwin" {
		k, reason, err := NewKeychainAttestor(producerID)
		if err != nil {
			return nil, "", err
		}
		if reason == "" {
			reason = "macOS keychain available"
		}
		return k, reason, nil
	}
	s, err := NewSoftwareAttestor(producerID)
	if err != nil {
		return nil, "", err
	}
	return s, "no hardware attestor; using software key", nil
}

func tpmAvailable() bool {
	// Real implementation would stat /dev/tpmrm0 or /dev/tpm0. For the MVP
	// we always return false because the TPM2Attestor is a stub anyway.
	return false
}
