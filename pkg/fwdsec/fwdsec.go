// Package fwdsec implements forward-secure signing for stele checkpoints.
//
// The operator's signing key is rotated periodically. Each rotation produces
// a RotationCert: a statement that "the new key for epoch N is P, signed by
// the key for epoch N-1." Once a rotation is published, the previous epoch's
// private key is irreversibly destroyed.
//
// Key storage is pluggable via the KeyStore interface:
//
//   - FileKeyStore (this package): development default. Keys are
//     Ed25519 private-key bytes held on the local filesystem with 0o600
//     permissions. A host-root compromise can read the active key.
//
//   - PKCS11KeyStore (pkg/hsm): production deployment. Keys live inside
//     an HSM (YubiHSM, CloudHSM, Azure KMS HSM, on-prem Thales) and
//     never leave it. A host-root compromise can only request signatures
//     through the HSM, not extract the key.
//
// The forward-secure guarantee composes with the storage choice: even
// with the FileKeyStore, a stolen key only forges current-epoch
// signatures because past epochs' keys have been destroyed. The HSM
// upgrade further restricts what an attacker can do with a current
// compromise — they can ask the HSM to sign but cannot move the key to
// another machine.
package fwdsec

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/desledishant10/stele/pkg/threshold"
)

// RotationCert is a signed statement that a new epoch's public key is
// authorised by the previous epoch's private key. The genesis cert is
// self-signed.
//
// Quantum fields (QuantumPublicKey, QuantumSignedBy, QuantumSignature)
// are populated only when the operator runs in hybrid mode. When
// present, verifiers require BOTH the classical and post-quantum
// signatures to validate. Classical-only deployments leave them empty.
type RotationCert struct {
	Epoch     uint64 `json:"epoch"`
	PublicKey []byte `json:"public_key"`
	StartedAt int64  `json:"started_at"`
	SignedBy  []byte `json:"signed_by"`
	Signature []byte `json:"signature"`

	// Hybrid (post-quantum) extensions; omitempty for backward compat.
	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"` // 1952 bytes when present
	QuantumSignedBy  []byte `json:"quantum_signed_by,omitempty"`  // pubkey that signed the quantum sig
	QuantumSignature []byte `json:"quantum_signature,omitempty"`  // 3293 bytes

	// Threshold extension: when the rotation cert is signed by a
	// t-of-N cosigner quorum (operator running in threshold mode),
	// MemberSigs holds the per-member signatures and the single-sig
	// Signature + QuantumSignature fields are empty. Verification
	// dispatches accordingly.
	//
	// The threshold-mode rotation cert also commits to the GROUP that
	// signed it: ThresholdGroupDigest is the hex digest of the
	// group whose members produced MemberSigs. Auditors look up that
	// group via the operator's published active group and run
	// threshold.VerifyMulti against the canonical bytes.
	ThresholdGroupDigest string                  `json:"threshold_group_digest,omitempty"`
	MemberSigs           []*threshold.MemberSig  `json:"member_sigs,omitempty"`
}

// Canonical returns the deterministic bytes that get signed.
//
// The format includes the quantum public key + threshold group digest
// when present, so an attacker cannot strip either field from a cert
// without invalidating the classical signature.
func (c *RotationCert) Canonical() []byte {
	q := "none"
	if len(c.QuantumPublicKey) > 0 {
		q = hex.EncodeToString(c.QuantumPublicKey)
	}
	tg := c.ThresholdGroupDigest
	if tg == "" {
		tg = "none"
	}
	return []byte(fmt.Sprintf(
		"stele-rotation/v0\nepoch: %d\npublic_key: %s\nstarted_at: %d\nsigned_by: %s\nquantum_public_key: %s\nthreshold_group: %s\n",
		c.Epoch, hex.EncodeToString(c.PublicKey), c.StartedAt, hex.EncodeToString(c.SignedBy), q, tg))
}

// Verify checks the cert's signature(s). Three modes:
//
//   - Single-sig classical (legacy): Signature must verify against
//     SignedBy as an Ed25519 signature.
//   - Single-sig hybrid: classical + the QuantumSignature against
//     QuantumSignedBy as a Dilithium3 signature.
//   - Threshold (with optional hybrid per-member): MemberSigs must
//     reach the threshold of the group whose digest is
//     ThresholdGroupDigest. The classical Signature field is empty.
//     The caller passes the resolved Group via VerifyWithGroup; the
//     bare Verify path returns an error in threshold mode (callers
//     who only have access to the bare cert can't verify a
//     threshold-mode rotation cert anyway).
func (c *RotationCert) Verify() error {
	if len(c.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("rotation cert epoch %d: bad PublicKey length", c.Epoch)
	}
	if len(c.MemberSigs) > 0 {
		return fmt.Errorf("rotation cert epoch %d: threshold-mode cert requires VerifyWithGroup", c.Epoch)
	}
	if len(c.SignedBy) != ed25519.PublicKeySize {
		return fmt.Errorf("rotation cert epoch %d: bad SignedBy length", c.Epoch)
	}
	canon := c.Canonical()
	if !ed25519.Verify(ed25519.PublicKey(c.SignedBy), canon, c.Signature) {
		return fmt.Errorf("rotation cert epoch %d: classical signature invalid", c.Epoch)
	}
	// Hybrid: if any quantum field is set, all must be set + verify.
	if len(c.QuantumPublicKey) > 0 || len(c.QuantumSignature) > 0 || len(c.QuantumSignedBy) > 0 {
		if err := verifyQuantumCert(c, canon); err != nil {
			return fmt.Errorf("rotation cert epoch %d: %w", c.Epoch, err)
		}
	}
	return nil
}

// VerifyWithGroup is the threshold-aware sibling. When MemberSigs is
// non-empty, it validates the cert against the supplied group's
// threshold + members. When MemberSigs is empty it falls through to
// the single-sig path of Verify().
func (c *RotationCert) VerifyWithGroup(group *threshold.Group) error {
	if len(c.MemberSigs) == 0 {
		return c.Verify()
	}
	if group == nil {
		return fmt.Errorf("rotation cert epoch %d: threshold-mode cert requires group", c.Epoch)
	}
	if c.ThresholdGroupDigest != hex.EncodeToString(group.Digest()) {
		return fmt.Errorf("rotation cert epoch %d: group digest mismatch", c.Epoch)
	}
	return threshold.VerifyMulti(group, c.Canonical(), c.MemberSigs)
}

// Chain is the ordered sequence of RotationCerts from genesis (index 0,
// self-signed) to the currently-active epoch. ActiveLocator stores the
// KeyStore-specific identifier for the live private key — the operator
// uses it on restart to reopen the right object in the underlying store
// (file path for FileKeyStore, PKCS#11 label for PKCS11KeyStore).
type Chain struct {
	Origin        string          `json:"origin"`
	Certs         []*RotationCert `json:"certs"`
	ActiveLocator string          `json:"active_locator,omitempty"`
}

// RootPublicKey returns the genesis epoch's public key.
func (c *Chain) RootPublicKey() ed25519.PublicKey {
	if len(c.Certs) == 0 {
		return nil
	}
	return ed25519.PublicKey(c.Certs[0].PublicKey)
}

// ActivePublicKey returns the public key for the latest epoch.
func (c *Chain) ActivePublicKey() ed25519.PublicKey {
	if len(c.Certs) == 0 {
		return nil
	}
	return ed25519.PublicKey(c.Certs[len(c.Certs)-1].PublicKey)
}

// ActiveEpoch is the epoch number whose key is currently active.
func (c *Chain) ActiveEpoch() uint64 {
	if len(c.Certs) == 0 {
		return 0
	}
	return c.Certs[len(c.Certs)-1].Epoch
}

// PublicKeyAt returns the classical Ed25519 public key for a specific
// epoch, or nil if not found.
func (c *Chain) PublicKeyAt(epoch uint64) ed25519.PublicKey {
	for _, cert := range c.Certs {
		if cert.Epoch == epoch {
			return ed25519.PublicKey(cert.PublicKey)
		}
	}
	return nil
}

// QuantumPublicKeyAt returns the Dilithium public key for a specific
// epoch, or nil if the epoch was signed in classical-only mode.
func (c *Chain) QuantumPublicKeyAt(epoch uint64) []byte {
	for _, cert := range c.Certs {
		if cert.Epoch == epoch {
			return cert.QuantumPublicKey
		}
	}
	return nil
}

// VerifyChain walks every cert from genesis forward in classical-style
// trust mode. Threshold-mode rotation certs are accepted only if the
// caller supplied a group via VerifyChainWithGroup. Bare VerifyChain
// is suitable for chains where every cert is single-sig — it rejects
// threshold-signed certs explicitly so verifiers don't accidentally
// pass them through unchecked.
func (c *Chain) VerifyChain(rootPub ed25519.PublicKey) error {
	return c.verifyChain(rootPub, nil)
}

// VerifyChainWithGroup is the threshold-aware sibling. `group`, if
// non-nil, is the static threshold group used to authorise rotation
// certs. Currently v1 assumes a single group for the chain's lifetime.
func (c *Chain) VerifyChainWithGroup(rootPub ed25519.PublicKey, group *threshold.Group) error {
	return c.verifyChain(rootPub, group)
}

func (c *Chain) verifyChain(rootPub ed25519.PublicKey, group *threshold.Group) error {
	if len(c.Certs) == 0 {
		return errors.New("chain: no certs")
	}
	if c.Certs[0].Epoch != 0 {
		return fmt.Errorf("chain: first cert must be epoch 0, got %d", c.Certs[0].Epoch)
	}
	if !bytesEqual(c.Certs[0].PublicKey, rootPub) {
		return errors.New("chain: genesis public key does not match trusted root")
	}
	if !bytesEqual(c.Certs[0].SignedBy, rootPub) {
		return errors.New("chain: genesis must be self-signed (SignedBy == PublicKey)")
	}
	// Genesis self-signed in hybrid mode must also be quantum-self-signed.
	if len(c.Certs[0].QuantumPublicKey) > 0 && !bytesEqual(c.Certs[0].QuantumPublicKey, c.Certs[0].QuantumSignedBy) {
		return errors.New("chain: genesis quantum half must be self-signed")
	}
	for i, cert := range c.Certs {
		// Threshold-mode certs require a group; pass through if provided.
		if len(cert.MemberSigs) > 0 {
			if group == nil {
				return fmt.Errorf("chain: epoch %d is threshold-signed but no group supplied", cert.Epoch)
			}
			if err := cert.VerifyWithGroup(group); err != nil {
				return err
			}
		} else {
			if err := cert.Verify(); err != nil {
				return err
			}
		}
		if i == 0 {
			continue
		}
		prev := c.Certs[i-1]
		if cert.Epoch != prev.Epoch+1 {
			return fmt.Errorf("chain: epoch jump %d -> %d", prev.Epoch, cert.Epoch)
		}
		if cert.StartedAt < prev.StartedAt {
			return fmt.Errorf("chain: epoch %d started before its parent", cert.Epoch)
		}
		// Single-sig classical chain link: this cert was signed by the
		// previous epoch's public key. Threshold-mode certs skip this
		// because they're authorised by the group not by the previous
		// epoch's solo key.
		if len(cert.MemberSigs) == 0 {
			if !bytesEqual(cert.SignedBy, prev.PublicKey) {
				return fmt.Errorf("chain: epoch %d signed by unexpected key", cert.Epoch)
			}
			// Quantum chain link.
			if len(cert.QuantumPublicKey) > 0 || len(cert.QuantumSignedBy) > 0 {
				if !bytesEqual(cert.QuantumSignedBy, prev.QuantumPublicKey) {
					return fmt.Errorf("chain: epoch %d quantum half signed by unexpected key", cert.Epoch)
				}
			}
		}
	}
	return nil
}

// ThresholdRotator is the operator's hook for signing rotation certs
// via a t-of-N cosigner quorum. When set, fwdsec.Signer.Rotate
// produces threshold-mode rotation certs (MemberSigs filled, single
// classical Signature empty). Implementations live in pkg/threshold.
type ThresholdRotator interface {
	// Sign collects t-of-N member signatures over msg and returns them
	// in arbitrary order. The threshold itself is enforced inside the
	// coordinator.
	Sign(ctx context.Context, msg []byte, label string) ([]*threshold.MemberSig, error)

	// Group returns the active group descriptor. The fwdsec layer
	// embeds Group.Digest() into the cert's ThresholdGroupDigest so
	// auditors can identify which group authorised the rotation.
	Group() *threshold.Group
}

// Signer holds the active epoch's private key (via a LiveKey provided by
// the configured KeyStore) and is the only thing that can produce new
// signatures or rotation certs.
//
// In threshold mode, threshRotator (if non-nil) is used to t-of-N-sign
// each rotation cert. The active LiveKey is still used for CHECKPOINTS
// — that path goes through pkg/checkpoint, which has its own threshold
// mechanism. Rotation certs and checkpoints are signed independently.
type Signer struct {
	mu             sync.Mutex
	origin         string
	dir            string // for chain.json
	chain          *Chain
	active         LiveKey
	store          KeyStore
	threshRotator  ThresholdRotator
}

// NewSigner is the convenience constructor for the file-backed store.
// Behaviour is identical to the previous v1 API.
func NewSigner(origin, dir string) (*Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	store, err := NewFileKeyStore(dir)
	if err != nil {
		return nil, err
	}
	return NewSignerWithStore(origin, dir, store)
}

// NewSignerWithStore opens (or creates) a forward-secure signer backed
// by the supplied KeyStore. If no chain exists, a genesis cert is
// created. Otherwise the active locator is read from chain.json and the
// store reopens the corresponding key.
func NewSignerWithStore(origin, dir string, store KeyStore) (*Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Signer{origin: origin, dir: dir, store: store}
	if _, err := os.Stat(s.chainPath()); errors.Is(err, os.ErrNotExist) {
		if err := s.createGenesis(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err := s.loadActive(); err != nil {
		return nil, err
	}
	return s, nil
}

// createGenesis generates the epoch-0 keypair (via the store), writes
// a self-signed cert, and persists the chain. If the store returns a
// hybrid LiveKey (quantum public key non-nil), the cert is hybrid-
// signed.
func (s *Signer) createGenesis() error {
	active, err := s.store.Generate()
	if err != nil {
		return fmt.Errorf("fwdsec: generate genesis key: %w", err)
	}
	pub := active.Public()
	cert := &RotationCert{
		Epoch:     0,
		PublicKey: append([]byte(nil), pub...),
		StartedAt: time.Now().UnixNano(),
		SignedBy:  append([]byte(nil), pub...),
	}
	if qpub := active.QuantumPublic(); qpub != nil {
		cert.QuantumPublicKey = append([]byte(nil), qpub...)
		cert.QuantumSignedBy = append([]byte(nil), qpub...) // self-signed
	}
	canon := cert.Canonical()
	sig, err := active.Sign(canon)
	if err != nil {
		_ = active.Destroy()
		return fmt.Errorf("fwdsec: self-sign genesis (classical): %w", err)
	}
	cert.Signature = sig
	if active.QuantumPublic() != nil {
		qsig, err := active.QuantumSign(canon)
		if err != nil {
			_ = active.Destroy()
			return fmt.Errorf("fwdsec: self-sign genesis (quantum): %w", err)
		}
		cert.QuantumSignature = qsig
	}
	s.chain = &Chain{
		Origin:        s.origin,
		Certs:         []*RotationCert{cert},
		ActiveLocator: active.Locator(),
	}
	s.active = active
	return s.writeChain()
}

// loadActive reads the chain and reopens the active epoch's LiveKey via
// the store.
func (s *Signer) loadActive() error {
	if err := s.readChain(); err != nil {
		return err
	}
	if len(s.chain.Certs) == 0 {
		return errors.New("fwdsec: empty chain")
	}
	if s.chain.Origin != "" && s.chain.Origin != s.origin {
		return fmt.Errorf("fwdsec: origin mismatch (chain=%q, expected=%q)", s.chain.Origin, s.origin)
	}
	if s.chain.ActiveLocator == "" {
		return errors.New("fwdsec: chain missing active_locator (corrupt or pre-v1.1)")
	}
	active, err := s.store.Load(s.chain.ActiveLocator)
	if err != nil {
		return fmt.Errorf("fwdsec: load active key: %w", err)
	}
	// Sanity check: the key the store gave us must match the chain's
	// current public key.
	if !bytesEqual(active.Public(), s.chain.ActivePublicKey()) {
		_ = active.Destroy()
		return errors.New("fwdsec: store returned key with public key that does not match chain")
	}
	s.active = active
	return nil
}

// Sign produces an Ed25519 signature with the active epoch key.
func (s *Signer) Sign(message []byte) (epoch uint64, sig []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return 0, nil, errors.New("fwdsec: no active key")
	}
	out, err := s.active.Sign(message)
	if err != nil {
		return 0, nil, err
	}
	return s.chain.ActiveEpoch(), out, nil
}

// Rotate generates a new epoch keypair via the store, has the current
// key sign the new key's RotationCert, persists the chain, then
// irrevocably destroys the previous epoch's key.
func (s *Signer) Rotate() (*RotationCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return nil, errors.New("fwdsec: no active key")
	}
	prevCert := s.chain.Certs[len(s.chain.Certs)-1]
	prevActive := s.active

	newActive, err := s.store.Generate()
	if err != nil {
		return nil, fmt.Errorf("fwdsec: generate new epoch key: %w", err)
	}
	newPub := newActive.Public()
	cert := &RotationCert{
		Epoch:     prevCert.Epoch + 1,
		PublicKey: append([]byte(nil), newPub...),
		StartedAt: time.Now().UnixNano(),
		SignedBy:  append([]byte(nil), prevCert.PublicKey...),
	}
	// Hybrid: capture the new epoch's quantum public key and bind the
	// rotation cert to be signed by the PREVIOUS epoch's quantum key.
	if qpub := newActive.QuantumPublic(); qpub != nil {
		cert.QuantumPublicKey = append([]byte(nil), qpub...)
		cert.QuantumSignedBy = append([]byte(nil), prevCert.QuantumPublicKey...)
	}
	// Threshold mode: bind the group digest into the cert BEFORE
	// canonicalising so member signatures cover the group identity.
	if s.threshRotator != nil {
		group := s.threshRotator.Group()
		if group == nil {
			_ = newActive.Destroy()
			return nil, errors.New("fwdsec: threshold rotator returned nil group")
		}
		cert.ThresholdGroupDigest = hex.EncodeToString(group.Digest())
	}
	canon := cert.Canonical()

	if s.threshRotator != nil {
		// Collect t-of-N cosigner sigs in parallel.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		sigs, err := s.threshRotator.Sign(ctx, canon, fmt.Sprintf("rotation epoch %d", cert.Epoch))
		if err != nil {
			_ = newActive.Destroy()
			return nil, fmt.Errorf("fwdsec: threshold-sign rotation cert: %w", err)
		}
		cert.MemberSigs = sigs
		// In threshold mode the single-sig fields are left empty; the
		// canonical bytes still carry the prev-epoch public key as
		// SignedBy for the chain-link check.
	} else {
		// Single-sig path (legacy / classical).
		sig, err := prevActive.Sign(canon)
		if err != nil {
			_ = newActive.Destroy()
			return nil, fmt.Errorf("fwdsec: sign rotation cert (classical): %w", err)
		}
		cert.Signature = sig
		if len(cert.QuantumPublicKey) > 0 && len(prevCert.QuantumPublicKey) > 0 {
			qsig, err := prevActive.QuantumSign(canon)
			if err != nil {
				_ = newActive.Destroy()
				return nil, fmt.Errorf("fwdsec: sign rotation cert (quantum): %w", err)
			}
			cert.QuantumSignature = qsig
		}
	}

	s.chain.Certs = append(s.chain.Certs, cert)
	s.chain.ActiveLocator = newActive.Locator()
	if err := s.writeChain(); err != nil {
		// Revert in-memory state. The new key on the store is orphaned
		// but not authorised; periodic janitor work could prune it.
		s.chain.Certs = s.chain.Certs[:len(s.chain.Certs)-1]
		s.chain.ActiveLocator = prevActive.Locator()
		_ = newActive.Destroy()
		return nil, err
	}

	// Destroy the old key BEFORE swapping in the new one, so a crash
	// here does not leave us with two recoverable signing keys.
	if err := prevActive.Destroy(); err != nil {
		return nil, fmt.Errorf("fwdsec: destroy previous key: %w", err)
	}
	s.active = newActive
	return cert, nil
}

// Public returns the active epoch's public key.
func (s *Signer) Public() ed25519.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chain.ActivePublicKey()
}

// ActiveEpoch returns the active epoch's index.
func (s *Signer) ActiveEpoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chain.ActiveEpoch()
}

// Origin returns the operator label.
func (s *Signer) Origin() string { return s.origin }

// Chain returns a deep copy of the rotation chain, safe to publish.
func (s *Signer) Chain() *Chain {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &Chain{
		Origin:        s.chain.Origin,
		ActiveLocator: s.chain.ActiveLocator,
		Certs:         make([]*RotationCert, len(s.chain.Certs)),
	}
	for i, c := range s.chain.Certs {
		copy := *c
		copy.PublicKey = append([]byte(nil), c.PublicKey...)
		copy.SignedBy = append([]byte(nil), c.SignedBy...)
		copy.Signature = append([]byte(nil), c.Signature...)
		out.Certs[i] = &copy
	}
	return out
}

// RootPublicKey returns the genesis epoch's public key.
func (s *Signer) RootPublicKey() ed25519.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chain.RootPublicKey()
}

// QuantumRootPublicKey returns the genesis epoch's Dilithium3 public
// key (nil in classical-only mode).
func (s *Signer) QuantumRootPublicKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.chain.Certs) == 0 {
		return nil
	}
	return s.chain.Certs[0].QuantumPublicKey
}

// Hybrid reports whether the active epoch carries a Dilithium public
// key in the chain (i.e. checkpoints will be hybrid-signed).
func (s *Signer) Hybrid() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return false
	}
	return s.active.QuantumPublic() != nil
}

// QuantumSign delegates to the active LiveKey's quantum signer. Used
// by checkpoint.Signer in hybrid mode.
func (s *Signer) QuantumSign(message []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return nil, errors.New("fwdsec: no active key")
	}
	return s.active.QuantumSign(message)
}

// UseThresholdRotation switches rotation-cert signing into threshold
// mode. From this point on, Rotate() will collect t-of-N cosigner
// signatures via `rotator` instead of using the active LiveKey.
// Genesis certs created before this call are unaffected.
func (s *Signer) UseThresholdRotation(rotator ThresholdRotator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.threshRotator = rotator
}

// Close releases the underlying keystore (e.g. closing an HSM session).
// Safe to call multiple times.
func (s *Signer) Close() error {
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}

// ----- chain persistence -----

func (s *Signer) chainPath() string { return filepath.Join(s.dir, "chain.json") }

func (s *Signer) writeChain() error {
	body, err := json.MarshalIndent(s.chain, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.chainPath() + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.chainPath())
}

func (s *Signer) readChain() error {
	buf, err := os.ReadFile(s.chainPath())
	if err != nil {
		return err
	}
	var chain Chain
	if err := json.Unmarshal(buf, &chain); err != nil {
		return err
	}
	s.chain = &chain
	return nil
}

// KeyID derives a short hex identifier from a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// verifyQuantumCert checks the Dilithium half of a rotation cert. All
// three quantum fields must be present and well-formed.
func verifyQuantumCert(c *RotationCert, canon []byte) error {
	if len(c.QuantumPublicKey) != mode3.PublicKeySize {
		return fmt.Errorf("quantum public key wrong length %d", len(c.QuantumPublicKey))
	}
	if len(c.QuantumSignedBy) != mode3.PublicKeySize {
		return fmt.Errorf("quantum signed-by wrong length %d", len(c.QuantumSignedBy))
	}
	if len(c.QuantumSignature) != mode3.SignatureSize {
		return fmt.Errorf("quantum signature wrong length %d", len(c.QuantumSignature))
	}
	dPub := &mode3.PublicKey{}
	if err := dPub.UnmarshalBinary(c.QuantumSignedBy); err != nil {
		return fmt.Errorf("decode quantum signed_by: %w", err)
	}
	if !mode3.Verify(dPub, canon, c.QuantumSignature) {
		return errors.New("quantum signature invalid")
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
