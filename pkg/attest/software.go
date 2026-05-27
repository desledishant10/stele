package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// SoftwareAttestor uses a plain Ed25519 key (and optionally a Dilithium3
// key in hybrid mode) held in process memory. It is the lowest-
// assurance Attestor — appropriate for development and for producers
// running on hosts already trusted by other means. For any production
// deployment, prefer KeychainAttestor or TPM2Attestor.
//
// On-disk key file formats:
//
//	classical (legacy):  <base64 ed25519 priv>
//	hybrid:              ed25519: <base64>\ndilithium3: <base64>\n
//
// LoadSoftwareAttestor auto-detects which format.
type SoftwareAttestor struct {
	id    string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	qPriv *mode3.PrivateKey // nil = classical-only
	qPub  []byte            // Dilithium3 public bytes; nil = classical-only
}

// NewSoftwareAttestor generates a fresh Ed25519 keypair (classical mode).
func NewSoftwareAttestor(producerID string) (*SoftwareAttestor, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SoftwareAttestor{id: producerID, priv: priv, pub: pub}, nil
}

// NewHybridSoftwareAttestor generates an Ed25519 + Dilithium3 keypair.
// Envelopes produced by this attestor are post-quantum protected.
func NewHybridSoftwareAttestor(producerID string) (*SoftwareAttestor, error) {
	a, err := NewSoftwareAttestor(producerID)
	if err != nil {
		return nil, err
	}
	qPub, qPriv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	a.qPriv = qPriv
	a.qPub, err = qPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("attest: marshal Dilithium pubkey: %w", err)
	}
	return a, nil
}

// LoadSoftwareAttestor reads a previously-written keypair, auto-
// detecting the classical vs hybrid file format.
func LoadSoftwareAttestor(producerID, privPath string) (*SoftwareAttestor, error) {
	buf, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("read producer key: %w", err)
	}
	if strings.HasPrefix(string(buf), "ed25519:") {
		return loadHybridSoftwareAttestor(producerID, buf)
	}
	raw, err := base64.StdEncoding.DecodeString(string(stripWS(buf)))
	if err != nil {
		return nil, fmt.Errorf("decode producer key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("producer key wrong length %d", len(raw))
	}
	priv := ed25519.PrivateKey(raw)
	pub := priv.Public().(ed25519.PublicKey)
	return &SoftwareAttestor{id: producerID, priv: priv, pub: pub}, nil
}

func loadHybridSoftwareAttestor(producerID string, raw []byte) (*SoftwareAttestor, error) {
	var edB64, dB64 string
	if _, err := fmt.Sscanf(string(raw), "ed25519: %s\ndilithium3: %s", &edB64, &dB64); err != nil {
		return nil, fmt.Errorf("parse hybrid producer key: %w", err)
	}
	edBytes, err := base64.StdEncoding.DecodeString(edB64)
	if err != nil {
		return nil, err
	}
	if len(edBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 component wrong length %d", len(edBytes))
	}
	dBytes, err := base64.StdEncoding.DecodeString(dB64)
	if err != nil {
		return nil, err
	}
	qPriv := &mode3.PrivateKey{}
	if err := qPriv.UnmarshalBinary(dBytes); err != nil {
		return nil, fmt.Errorf("decode dilithium component: %w", err)
	}
	priv := ed25519.PrivateKey(edBytes)
	qPubBytes, _ := qPriv.Public().(*mode3.PublicKey).MarshalBinary()
	return &SoftwareAttestor{
		id:    producerID,
		priv:  priv,
		pub:   priv.Public().(ed25519.PublicKey),
		qPriv: qPriv,
		qPub:  qPubBytes,
	}, nil
}

// WriteKey persists the private key. Hybrid keys use the two-line
// format; classical keys use the legacy single-line format.
func (s *SoftwareAttestor) WriteKey(privPath string) error {
	if s.qPriv == nil {
		return os.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(s.priv)+"\n"), 0o600)
	}
	dBytes, _ := s.qPriv.MarshalBinary()
	body := fmt.Sprintf("ed25519: %s\ndilithium3: %s\n",
		base64.StdEncoding.EncodeToString(s.priv),
		base64.StdEncoding.EncodeToString(dBytes))
	return os.WriteFile(privPath, []byte(body), 0o600)
}

// QuantumPublicKey returns the Dilithium3 public key bytes, or nil if
// this attestor is classical-only.
func (s *SoftwareAttestor) QuantumPublicKey() []byte { return s.qPub }

// IsHybrid reports whether this attestor produces hybrid envelopes.
func (s *SoftwareAttestor) IsHybrid() bool { return s.qPriv != nil }

// ProducerID implements Attestor.
func (s *SoftwareAttestor) ProducerID() string { return s.id }

// Type implements Attestor.
func (s *SoftwareAttestor) Type() AttestationType { return TypeSoftware }

// PublicKey implements Attestor.
func (s *SoftwareAttestor) PublicKey() ed25519.PublicKey { return s.pub }

// Sign builds an envelope, signs the canonical bytes, and attaches the
// signature(s). In hybrid mode it produces both Ed25519 and Dilithium3
// signatures over the same canonical bytes.
func (s *SoftwareAttestor) Sign(source string, data []byte) (*Envelope, error) {
	if s.priv == nil {
		return nil, errors.New("software attestor: no key loaded")
	}
	env := &Envelope{
		ProducerID: s.id,
		TimeNanos:  SignTime(),
		Source:     source,
		Data:       append([]byte(nil), data...),
		PublicKey:  append([]byte(nil), s.pub...),
		Type:       TypeSoftware,
	}
	evidence := []byte(`{"attestor":"software"}`)
	h := sha256.Sum256(evidence)
	env.Evidence = evidence
	env.EvidenceHash = h[:]
	// Hybrid: bind the quantum public key into the canonical bytes
	// BEFORE signing, so the classical signature also commits to it.
	if s.qPub != nil {
		env.QuantumPublicKey = append([]byte(nil), s.qPub...)
	}
	canon := env.Canonical()
	env.Signature = ed25519.Sign(s.priv, canon)
	if s.qPriv != nil {
		qsig := make([]byte, mode3.SignatureSize)
		mode3.SignTo(s.qPriv, canon, qsig)
		env.QuantumSignature = qsig
	}
	return env, nil
}

// SignChallenge signs `challenge` directly (no envelope wrapper, no
// hashing — the caller decides what bytes are signed). Used during
// the proof-of-possession enrollment ceremony: the operator hands the
// producer a server-issued challenge, the producer signs it with
// their private key, and the operator verifies against the registered
// pubkey.
//
// Hybrid attestors produce both classical and Dilithium3 signatures
// so the operator can enforce "no quantum-downgrade" at enrollment
// time. Classical-only attestors return a zero-length quantum sig.
func (s *SoftwareAttestor) SignChallenge(challenge []byte) (classicalSig, quantumSig []byte, err error) {
	if s.priv == nil {
		return nil, nil, errors.New("software attestor: no key loaded")
	}
	classicalSig = ed25519.Sign(s.priv, challenge)
	if s.qPriv != nil {
		quantumSig = make([]byte, mode3.SignatureSize)
		mode3.SignTo(s.qPriv, challenge, quantumSig)
	}
	return classicalSig, quantumSig, nil
}

func stripWS(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			continue
		}
		out = append(out, c)
	}
	return out
}
