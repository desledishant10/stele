// Package hybrid implements post-quantum-ready signing for stele.
//
// Every hybrid signature is the concatenation of TWO independent
// signatures: an Ed25519 (classical) signature and a Dilithium3
// (NIST PQC ML-DSA Level 3) signature. Verification requires BOTH to
// pass. To forge a hybrid signature, an attacker must simultaneously
// break both classical and post-quantum cryptography — strictly
// stronger than either alone.
//
// Why hybrid instead of just Dilithium. The Dilithium scheme is recent
// (NIST FIPS 204, August 2024) and has had less battle-testing than
// Ed25519. By requiring both, an unknown weakness in either scheme
// alone does not compromise the system. This is the same defence-in-
// depth Sigstore, the Go module checksum database, and Cloudflare's
// post-quantum TLS deployments use.
//
// Threat protected against:
//
//   - "Harvest now, decrypt/forge later." A future quantum computer
//     that breaks Ed25519 cannot retroactively forge any hybrid
//     signature this code produces — Dilithium3 remains secure.
//
//   - Unknown Dilithium weakness. If a flaw is found in Dilithium
//     years from now, every hybrid signature produced today still has
//     its Ed25519 layer as a fallback.
//
// Wire format. KeyPair public keys and signatures are byte-concat
// (Ed25519 || Dilithium3) with sizes fixed by both algorithms, so
// parsing requires no length-prefixing. PubKeySize = 32 + 1952 = 1984;
// SignatureSize = 64 + 3293 = 3357.
package hybrid

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// PubKeySize is the byte length of a hybrid public key.
const PubKeySize = ed25519.PublicKeySize + mode3.PublicKeySize // 1984

// SignatureSize is the byte length of a hybrid signature.
const SignatureSize = ed25519.SignatureSize + mode3.SignatureSize // 3357

// PrivKeySize is the byte length of a hybrid private key (the form we
// persist; it includes the seeds needed to reconstruct both halves).
const PrivKeySize = ed25519.PrivateKeySize + mode3.PrivateKeySize

// PublicKey holds both halves of a hybrid public key.
type PublicKey struct {
	Ed     ed25519.PublicKey
	Quantum *mode3.PublicKey
}

// PrivateKey holds both halves of a hybrid private key. Keep secret.
type PrivateKey struct {
	Ed     ed25519.PrivateKey
	Quantum *mode3.PrivateKey
	Pub    *PublicKey
}

// GenerateKey creates a fresh hybrid keypair using crypto/rand.
func GenerateKey(reader io.Reader) (*PrivateKey, error) {
	if reader == nil {
		reader = rand.Reader
	}
	edPub, edPriv, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, fmt.Errorf("hybrid: ed25519 keygen: %w", err)
	}
	dPub, dPriv, err := mode3.GenerateKey(reader)
	if err != nil {
		return nil, fmt.Errorf("hybrid: dilithium keygen: %w", err)
	}
	pub := &PublicKey{Ed: edPub, Quantum: dPub}
	return &PrivateKey{Ed: edPriv, Quantum: dPriv, Pub: pub}, nil
}

// Sign produces a hybrid signature over msg. Result has length
// SignatureSize; ed25519 portion is at [:ed25519.SignatureSize], the
// rest is the Dilithium3 signature.
func (k *PrivateKey) Sign(msg []byte) []byte {
	out := make([]byte, SignatureSize)
	edSig := ed25519.Sign(k.Ed, msg)
	copy(out, edSig)
	mode3.SignTo(k.Quantum, msg, out[ed25519.SignatureSize:])
	return out
}

// Verify checks a hybrid signature against the public key. Returns nil
// iff BOTH halves verify. Failures from either half are surfaced.
func (p *PublicKey) Verify(msg, sig []byte) error {
	if len(sig) != SignatureSize {
		return fmt.Errorf("hybrid: bad signature size %d (want %d)", len(sig), SignatureSize)
	}
	edSig := sig[:ed25519.SignatureSize]
	dSig := sig[ed25519.SignatureSize:]
	if !ed25519.Verify(p.Ed, msg, edSig) {
		return errors.New("hybrid: ed25519 component invalid")
	}
	if !mode3.Verify(p.Quantum, msg, dSig) {
		return errors.New("hybrid: dilithium component invalid")
	}
	return nil
}

// Bytes serialises a hybrid public key as Ed25519 || Dilithium3.
func (p *PublicKey) Bytes() []byte {
	out := make([]byte, PubKeySize)
	copy(out, p.Ed)
	dBytes, _ := p.Quantum.MarshalBinary()
	copy(out[ed25519.PublicKeySize:], dBytes)
	return out
}

// ParsePublicKey decodes a hybrid public key produced by Bytes().
func ParsePublicKey(buf []byte) (*PublicKey, error) {
	if len(buf) != PubKeySize {
		return nil, fmt.Errorf("hybrid pubkey: bad length %d (want %d)", len(buf), PubKeySize)
	}
	ed := ed25519.PublicKey(append([]byte(nil), buf[:ed25519.PublicKeySize]...))
	d := &mode3.PublicKey{}
	if err := d.UnmarshalBinary(buf[ed25519.PublicKeySize:]); err != nil {
		return nil, fmt.Errorf("hybrid pubkey: dilithium: %w", err)
	}
	return &PublicKey{Ed: ed, Quantum: d}, nil
}

// KeyID derives a short hex identifier from a hybrid public key. Like
// fwdsec.KeyID, this is used for display only.
func KeyID(p *PublicKey) string {
	if p == nil {
		return ""
	}
	sum := sha256.Sum256(p.Bytes())
	return hex.EncodeToString(sum[:8])
}

// MarshalPrivate writes the private key to disk in a deterministic
// format: ed25519 seed + Dilithium private bytes, both base64'd on
// separate lines.
func (k *PrivateKey) MarshalPrivate() ([]byte, error) {
	if k.Ed == nil || k.Quantum == nil {
		return nil, errors.New("hybrid: nil components")
	}
	dBytes, err := k.Quantum.MarshalBinary()
	if err != nil {
		return nil, err
	}
	body := fmt.Sprintf("ed25519: %s\ndilithium3: %s\n",
		base64.StdEncoding.EncodeToString(k.Ed),
		base64.StdEncoding.EncodeToString(dBytes),
	)
	return []byte(body), nil
}

// ParsePrivate decodes a private key written by MarshalPrivate.
func ParsePrivate(buf []byte) (*PrivateKey, error) {
	var edB64, dB64 string
	if _, err := fmt.Sscanf(string(buf), "ed25519: %s\ndilithium3: %s", &edB64, &dB64); err != nil {
		return nil, fmt.Errorf("hybrid: parse private: %w", err)
	}
	edBytes, err := base64.StdEncoding.DecodeString(edB64)
	if err != nil {
		return nil, err
	}
	if len(edBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("hybrid: bad ed25519 length %d", len(edBytes))
	}
	dBytes, err := base64.StdEncoding.DecodeString(dB64)
	if err != nil {
		return nil, err
	}
	dPriv := &mode3.PrivateKey{}
	if err := dPriv.UnmarshalBinary(dBytes); err != nil {
		return nil, fmt.Errorf("hybrid: parse dilithium: %w", err)
	}
	edPriv := ed25519.PrivateKey(edBytes)
	pub := &PublicKey{
		Ed:     edPriv.Public().(ed25519.PublicKey),
		Quantum: dPriv.Public().(*mode3.PublicKey),
	}
	return &PrivateKey{Ed: edPriv, Quantum: dPriv, Pub: pub}, nil
}

// WriteFiles persists the keypair: private to privPath (0o600), public
// (base64 of Bytes()) to pubPath (0o644).
func (k *PrivateKey) WriteFiles(privPath, pubPath string) error {
	privBytes, err := k.MarshalPrivate()
	if err != nil {
		return err
	}
	if err := os.WriteFile(privPath, privBytes, 0o600); err != nil {
		return err
	}
	pubB64 := base64.StdEncoding.EncodeToString(k.Pub.Bytes())
	return os.WriteFile(pubPath, []byte(pubB64+"\n"), 0o644)
}

// LoadPrivate reads a keypair previously written by WriteFiles.
func LoadPrivate(privPath string) (*PrivateKey, error) {
	buf, err := os.ReadFile(privPath)
	if err != nil {
		return nil, err
	}
	return ParsePrivate(buf)
}
