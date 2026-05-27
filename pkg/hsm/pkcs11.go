//go:build cgo

// Package hsm implements a PKCS#11-backed fwdsec.KeyStore so the
// operator's forward-secure signing keys live inside a Hardware Security
// Module instead of on the operator host's filesystem.
//
// The same code talks to:
//   - SoftHSM2 (free, software simulator, used for tests)
//   - YubiHSM 2 (USB hardware, ~$650, supports Ed25519)
//   - AWS CloudHSM (managed, PKCS#11 client library)
//   - Azure Key Vault Managed HSM (via PKCS#11 broker)
//   - Thales Luna / Entrust nShield (enterprise on-prem HSM)
//
// The only thing that changes between deployments is the path to the
// PKCS#11 module shared library and the credentials (PIN / slot).
//
// What this defends against compared to FileKeyStore: a full root
// compromise of the operator host can no longer steal the signing key.
// The attacker can still ASK the HSM to sign while they are inside
// (until detected and a new epoch is rotated, which destroys the
// HSM-resident key), but they cannot copy the key to another machine.
//
// Cryptographic note. PKCS#11 v3.0 standardised Ed25519 via the
// CKK_EC_EDWARDS key type and CKM_EDDSA signing mechanism. SoftHSM2 2.6+
// and YubiHSM 2 support these. Some legacy HSMs do not — they would
// need EdDSA support added before they can hold stele keys.
package hsm

import (
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"fmt"
	"sync"

	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/miekg/pkcs11"
)

// PKCS#11 v3.0 constants that the upstream miekg/pkcs11 wrapper doesn't
// yet re-export. These are stable values fixed by the OASIS spec.
const (
	ckkECEdwards            uint = 0x00000040 // CKK_EC_EDWARDS
	ckmECEdwardsKeyPairGen  uint = 0x00001055 // CKM_EC_EDWARDS_KEY_PAIR_GEN
	ckmEDDSA                uint = 0x00001057 // CKM_EDDSA
)

// Config configures a PKCS11KeyStore.
type Config struct {
	// Module is the filesystem path to the PKCS#11 shared library, e.g.
	//   /opt/homebrew/lib/softhsm/libsofthsm2.so
	//   /usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so
	//   /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
	Module string

	// SlotID is the slot containing the initialised token.
	SlotID uint

	// PIN is the user PIN for C_Login.
	PIN string

	// KeyPrefix is the label prefix used when generating keys, so
	// multiple stele operators can share one token without collisions.
	// Required.
	KeyPrefix string
}

// PKCS11KeyStore implements fwdsec.KeyStore against a PKCS#11 module.
// One Open() call holds one session for the lifetime of the keystore.
type PKCS11KeyStore struct {
	mu      sync.Mutex
	cfg     Config
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	loggedIn bool
}

// Open initialises the PKCS#11 module, opens a session against the
// configured slot, and logs in. The returned keystore is ready to
// Generate or Load.
func Open(cfg Config) (*PKCS11KeyStore, error) {
	if cfg.Module == "" {
		return nil, errors.New("hsm: Config.Module required")
	}
	if cfg.KeyPrefix == "" {
		return nil, errors.New("hsm: Config.KeyPrefix required")
	}
	ctx := pkcs11.New(cfg.Module)
	if ctx == nil {
		return nil, fmt.Errorf("hsm: failed to load PKCS#11 module %q", cfg.Module)
	}
	if err := ctx.Initialize(); err != nil {
		// Already-initialised is OK if a sibling process opened first.
		if !errors.Is(err, pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
			return nil, fmt.Errorf("hsm: Initialize: %w", err)
		}
	}
	session, err := ctx.OpenSession(cfg.SlotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		_ = ctx.Finalize()
		return nil, fmt.Errorf("hsm: OpenSession(slot=%d): %w", cfg.SlotID, err)
	}
	if err := ctx.Login(session, pkcs11.CKU_USER, cfg.PIN); err != nil {
		// Already-logged-in is OK when the same token is shared.
		if !errors.Is(err, pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN)) {
			_ = ctx.CloseSession(session)
			_ = ctx.Finalize()
			return nil, fmt.Errorf("hsm: Login: %w", err)
		}
	}
	return &PKCS11KeyStore{
		cfg:      cfg,
		ctx:      ctx,
		session:  session,
		loggedIn: true,
	}, nil
}

// Close logs out, closes the session, and finalises the module. Safe to
// call multiple times.
func (p *PKCS11KeyStore) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx == nil {
		return nil
	}
	if p.loggedIn {
		_ = p.ctx.Logout(p.session)
		p.loggedIn = false
	}
	_ = p.ctx.CloseSession(p.session)
	err := p.ctx.Finalize()
	p.ctx.Destroy()
	p.ctx = nil
	return err
}

// ed25519OID is the OID for Ed25519 (RFC 8410): 1.3.101.112.
// PKCS#11 v3.0 specifies that this DER-encoded OID is passed via
// CKA_EC_PARAMS when generating Ed25519 keys.
var ed25519OID = asn1.ObjectIdentifier{1, 3, 101, 112}

// Generate creates a fresh Ed25519 keypair inside the HSM and returns a
// LiveKey bound to it. The private object is non-extractable so even an
// attacker with PKCS#11 access to the token cannot copy it to another
// machine.
func (p *PKCS11KeyStore) Generate() (fwdsec.LiveKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	label := fmt.Sprintf("%s-epoch-%s", p.cfg.KeyPrefix, randHex())
	ecParams, err := asn1.Marshal(ed25519OID)
	if err != nil {
		return nil, fmt.Errorf("hsm: marshal Ed25519 OID: %w", err)
	}

	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, ckkECEdwards),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, ckkECEdwards),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(ckmECEdwardsKeyPairGen, nil),
	}
	pubHandle, privHandle, err := p.ctx.GenerateKeyPair(p.session, mech, pubTemplate, privTemplate)
	if err != nil {
		return nil, fmt.Errorf("hsm: GenerateKeyPair: %w", err)
	}
	pubKey, err := p.readPublicKeyLocked(pubHandle)
	if err != nil {
		_ = p.ctx.DestroyObject(p.session, privHandle)
		_ = p.ctx.DestroyObject(p.session, pubHandle)
		return nil, err
	}
	return &hsmLiveKey{
		store:   p,
		privObj: privHandle,
		pubObj:  pubHandle,
		pubKey:  pubKey,
		label:   label,
	}, nil
}

// Load reopens an existing HSM key pair by label. Both the private and
// public objects must exist; if either is missing, returns an error.
func (p *PKCS11KeyStore) Load(label string) (fwdsec.LiveKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	priv, err := p.findOneLocked(label, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, fmt.Errorf("hsm: load private %q: %w", label, err)
	}
	pub, err := p.findOneLocked(label, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		return nil, fmt.Errorf("hsm: load public %q: %w", label, err)
	}
	pubKey, err := p.readPublicKeyLocked(pub)
	if err != nil {
		return nil, err
	}
	return &hsmLiveKey{
		store:   p,
		privObj: priv,
		pubObj:  pub,
		pubKey:  pubKey,
		label:   label,
	}, nil
}

// findOneLocked locates exactly one PKCS#11 object matching the label
// + class. Caller must hold p.mu.
func (p *PKCS11KeyStore) findOneLocked(label string, class uint) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	if err := p.ctx.FindObjectsInit(p.session, template); err != nil {
		return 0, err
	}
	objs, _, err := p.ctx.FindObjects(p.session, 2)
	_ = p.ctx.FindObjectsFinal(p.session)
	if err != nil {
		return 0, err
	}
	switch len(objs) {
	case 0:
		return 0, fmt.Errorf("no object with label=%q class=%d", label, class)
	case 1:
		return objs[0], nil
	default:
		return 0, fmt.Errorf("multiple objects with label=%q class=%d (got %d)", label, class, len(objs))
	}
}

// readPublicKeyLocked extracts the raw Ed25519 public key bytes from the
// HSM via CKA_EC_POINT. The value can be returned either as a 32-byte
// raw key or as a DER-encoded OCTET STRING wrapping those bytes; we
// handle both shapes here.
func (p *PKCS11KeyStore) readPublicKeyLocked(handle pkcs11.ObjectHandle) (ed25519.PublicKey, error) {
	attrs, err := p.ctx.GetAttributeValue(p.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("hsm: GetAttributeValue(CKA_EC_POINT): %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, errors.New("hsm: empty CKA_EC_POINT")
	}
	v := attrs[0].Value

	// Shape 1: raw 32 bytes (some implementations).
	if len(v) == ed25519.PublicKeySize {
		pub := make([]byte, ed25519.PublicKeySize)
		copy(pub, v)
		return ed25519.PublicKey(pub), nil
	}

	// Shape 2: DER-encoded OCTET STRING (PKCS#11 v3.0 canonical).
	var raw []byte
	if _, err := asn1.Unmarshal(v, &raw); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("hsm: cannot decode CKA_EC_POINT of length %d", len(v))
}

// hsmLiveKey is a LiveKey backed by a PKCS#11 private-key object. The
// private bytes never enter this process's memory; Sign delegates to
// C_Sign inside the HSM.
type hsmLiveKey struct {
	store   *PKCS11KeyStore
	privObj pkcs11.ObjectHandle
	pubObj  pkcs11.ObjectHandle
	pubKey  ed25519.PublicKey
	label   string
}

// Public implements fwdsec.LiveKey.
func (k *hsmLiveKey) Public() ed25519.PublicKey { return k.pubKey }

// Sign implements fwdsec.LiveKey. Calls C_Sign with CKM_EDDSA.
func (k *hsmLiveKey) Sign(msg []byte) ([]byte, error) {
	k.store.mu.Lock()
	defer k.store.mu.Unlock()
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEDDSA, nil)}
	if err := k.store.ctx.SignInit(k.store.session, mech, k.privObj); err != nil {
		return nil, fmt.Errorf("hsm: SignInit: %w", err)
	}
	sig, err := k.store.ctx.Sign(k.store.session, msg)
	if err != nil {
		return nil, fmt.Errorf("hsm: Sign: %w", err)
	}
	return sig, nil
}

// Locator implements fwdsec.LiveKey. We use the PKCS#11 label so a
// future Load() call can find the same objects.
func (k *hsmLiveKey) Locator() string { return k.label }

// QuantumPublic implements fwdsec.LiveKey. PKCS#11 v3.0 does not yet
// specify a CKM for Dilithium; HSM-backed hybrid signing is therefore
// classical-only in v1. Returns nil to signal "not hybrid."
func (k *hsmLiveKey) QuantumPublic() []byte { return nil }

// QuantumSign implements fwdsec.LiveKey.
func (k *hsmLiveKey) QuantumSign(msg []byte) ([]byte, error) {
	return nil, errors.New("hsm livekey: hybrid mode not supported (no PKCS#11 Dilithium mechanism)")
}

// Destroy implements fwdsec.LiveKey. Calls C_DestroyObject on both the
// private and public objects. After Destroy the key is unrecoverable.
func (k *hsmLiveKey) Destroy() error {
	k.store.mu.Lock()
	defer k.store.mu.Unlock()
	var errs []error
	if err := k.store.ctx.DestroyObject(k.store.session, k.privObj); err != nil {
		errs = append(errs, fmt.Errorf("destroy private: %w", err))
	}
	if err := k.store.ctx.DestroyObject(k.store.session, k.pubObj); err != nil {
		errs = append(errs, fmt.Errorf("destroy public: %w", err))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
