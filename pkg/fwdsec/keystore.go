package fwdsec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/desledishant10/stele/pkg/keyguard"
	"github.com/desledishant10/stele/pkg/obs"
)

// LiveKey is a usable private key for one epoch. Implementations may keep
// the key in memory (FileKeyStore) or delegate every Sign call to an HSM
// (pkg/hsm.PKCS11KeyStore). The interface is intentionally minimal: the
// caller never sees raw private bytes.
//
// Hybrid post-quantum: when the LiveKey was generated in hybrid mode,
// QuantumPublic returns the Dilithium3 public key and QuantumSign
// produces a Dilithium3 signature. In classical-only mode, both return
// (nil, nil). Callers can detect hybrid mode by checking
// QuantumPublic() != nil. HSM-backed key stores currently do not
// support Dilithium (no widely-deployed PKCS#11 mechanism yet) so
// hybrid mode is FileKeyStore-only in v1.
type LiveKey interface {
	// Public returns the Ed25519 public key. Cheap, called per signature.
	Public() ed25519.PublicKey
	// Sign computes an Ed25519 signature over msg using the private key.
	Sign(msg []byte) ([]byte, error)
	// Locator returns a stable string identifying this key in its store.
	// The store re-opens the key later via Load(Locator()).
	Locator() string
	// Destroy irrevocably removes the private key material. After Destroy
	// the key cannot sign anything. For file-backed keys this overwrites
	// the on-disk bytes and removes the file; for HSM-backed keys this
	// calls C_DestroyObject on the PKCS#11 object.
	Destroy() error

	// QuantumPublic returns the Dilithium3 public key bytes (1952 B), or
	// nil if this key is classical-only.
	QuantumPublic() []byte
	// QuantumSign produces a Dilithium3 signature, or returns an error
	// if this key is classical-only.
	QuantumSign(msg []byte) ([]byte, error)
}

// KeyStore manages the lifecycle of LiveKeys for the forward-secure
// signing chain. Implementations:
//
//   - FileKeyStore (this package): keys are Ed25519 private bytes held
//     on the local filesystem under 0o600. The locator is the file
//     path.
//
//   - PKCS11KeyStore (pkg/hsm): keys are HSM objects identified by
//     PKCS#11 labels. The locator is the label.
type KeyStore interface {
	// Generate creates a fresh Ed25519 keypair and returns a LiveKey
	// bound to it. The new key is persisted.
	Generate() (LiveKey, error)
	// Load reopens an existing key by its locator. Used at startup to
	// recover the currently-active epoch key.
	Load(locator string) (LiveKey, error)
	// Close releases any backing resources (e.g. closing a PKCS#11
	// session). Safe to call multiple times.
	Close() error
}

// ----- FileKeyStore: software-backed reference implementation -----

// FileKeyStore persists each epoch's private key as a base64-encoded
// Ed25519 private key in a per-epoch file under 0o600 permissions. When
// Hybrid is true, every generated key ALSO carries a Dilithium3 key
// serialised in the same file. Loading recovers both.
type FileKeyStore struct {
	dir    string
	Hybrid bool
}

// NewFileKeyStore creates the directory if it doesn't exist.
func NewFileKeyStore(dir string) (*FileKeyStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileKeyStore{dir: dir}, nil
}

// NewFileKeyStoreHybrid creates a key store whose Generate() also
// produces Dilithium3 keys. Loaded files that lack a quantum half are
// still accepted (backward compat) but Sign-time hybrid operations on
// them will fail.
func NewFileKeyStoreHybrid(dir string) (*FileKeyStore, error) {
	s, err := NewFileKeyStore(dir)
	if err != nil {
		return nil, err
	}
	s.Hybrid = true
	return s, nil
}

// Generate implements KeyStore.
//
// The on-disk file is either:
//
//	classical (legacy):  <base64 ed25519 priv>
//	hybrid:              ed25519: <base64>\ndilithium3: <base64>\n
//
// Load auto-detects which format and constructs the right LiveKey.
func (f *FileKeyStore) Generate() (LiveKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("epoch-%d-%d.key", time.Now().UnixNano(), randSuffix())
	path := filepath.Join(f.dir, name)
	live := &fileLiveKey{priv: priv, pub: pub, path: path}
	protectKey(live.priv)

	if f.Hybrid {
		qPub, qPriv, err := mode3.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("file keystore: dilithium keygen: %w", err)
		}
		live.qPriv = qPriv
		qPubBytes, err := qPub.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("fwdsec: marshal Dilithium pubkey: %w", err)
		}
		live.qPub = qPubBytes
	}

	body, err := live.encodePrivate()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return nil, err
	}
	return live, nil
}

// Load implements KeyStore. Auto-detects classical vs hybrid file
// format based on the first bytes.
func (f *FileKeyStore) Load(locator string) (LiveKey, error) {
	if locator == "" {
		return nil, errors.New("file keystore: empty locator")
	}
	raw, err := os.ReadFile(locator)
	if err != nil {
		return nil, fmt.Errorf("file keystore: read %s: %w", locator, err)
	}
	if strings.HasPrefix(string(raw), "ed25519:") {
		return loadHybridFileKey(locator, raw)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("file keystore: decode: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("file keystore: key length %d, want %d", len(decoded), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(decoded)
	pub := priv.Public().(ed25519.PublicKey)
	protectKey(priv)
	return &fileLiveKey{priv: priv, pub: pub, path: locator}, nil
}

func loadHybridFileKey(path string, raw []byte) (LiveKey, error) {
	var edB64, dB64 string
	if _, err := fmt.Sscanf(string(raw), "ed25519: %s\ndilithium3: %s", &edB64, &dB64); err != nil {
		return nil, fmt.Errorf("file keystore: parse hybrid: %w", err)
	}
	edBytes, err := base64.StdEncoding.DecodeString(edB64)
	if err != nil {
		return nil, err
	}
	if len(edBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("file keystore: ed25519 wrong length %d", len(edBytes))
	}
	dBytes, err := base64.StdEncoding.DecodeString(dB64)
	if err != nil {
		return nil, err
	}
	qPriv := &mode3.PrivateKey{}
	if err := qPriv.UnmarshalBinary(dBytes); err != nil {
		return nil, fmt.Errorf("file keystore: dilithium unmarshal: %w", err)
	}
	priv := ed25519.PrivateKey(edBytes)
	qPubBytes, _ := qPriv.Public().(*mode3.PublicKey).MarshalBinary()
	protectKey(priv)
	return &fileLiveKey{
		priv:  priv,
		pub:   priv.Public().(ed25519.PublicKey),
		path:  path,
		qPriv: qPriv,
		qPub:  qPubBytes,
	}, nil
}

// protectKey applies best-effort OS-level protection to a private key
// slice: mlock the pages so they don't swap to disk, and
// MADV_DONTDUMP so a core dump can't capture them. Failures (e.g.
// ulimit -l too low) are logged but do not abort startup — the worst
// case is "we operate with the same exposure stele had before
// keyguard was added".
func protectKey(b []byte) {
	if err := keyguard.Lock(b); err != nil {
		obs.Warn("keyguard: failed to mlock key memory",
			"err", err,
			"hint", "increase ulimit -l, run with CAP_IPC_LOCK, or accept best-effort")
	}
	if err := keyguard.MarkNoCoreDump(b); err != nil {
		obs.Debug("keyguard: failed to mark key memory no-core-dump", "err", err)
	}
}

// Close implements KeyStore. No resources for the file store.
func (f *FileKeyStore) Close() error { return nil }

// fileLiveKey is a LiveKey backed by an in-memory Ed25519 private key
// plus (in hybrid mode) a Dilithium3 private key. Destroy zeroes both.
type fileLiveKey struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	path  string
	qPriv *mode3.PrivateKey
	qPub  []byte // Dilithium3 public-key bytes; nil = classical-only
}

func (k *fileLiveKey) Public() ed25519.PublicKey { return k.pub }

func (k *fileLiveKey) Sign(msg []byte) ([]byte, error) {
	if k.priv == nil {
		return nil, errors.New("file livekey: destroyed")
	}
	return ed25519.Sign(k.priv, msg), nil
}

func (k *fileLiveKey) QuantumPublic() []byte { return k.qPub }

func (k *fileLiveKey) QuantumSign(msg []byte) ([]byte, error) {
	if k.qPriv == nil {
		return nil, errors.New("file livekey: not hybrid (no Dilithium key)")
	}
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(k.qPriv, msg, sig)
	return sig, nil
}

func (k *fileLiveKey) Locator() string { return k.path }

// encodePrivate produces the on-disk bytes for this key. Classical-only
// keys get the legacy single-line format; hybrid keys get a two-line
// "ed25519: ...\ndilithium3: ...\n" format.
func (k *fileLiveKey) encodePrivate() ([]byte, error) {
	if k.qPriv == nil {
		return []byte(base64.StdEncoding.EncodeToString(k.priv) + "\n"), nil
	}
	dBytes, err := k.qPriv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("fwdsec: marshal Dilithium private key: %w", err)
	}
	return []byte(fmt.Sprintf("ed25519: %s\ndilithium3: %s\n",
		base64.StdEncoding.EncodeToString(k.priv),
		base64.StdEncoding.EncodeToString(dBytes))), nil
}

func (k *fileLiveKey) Destroy() error {
	var firstErr error
	if k.path != "" {
		if st, err := os.Stat(k.path); err == nil {
			noise := make([]byte, st.Size())
			if _, err := rand.Read(noise); err != nil {
				firstErr = fmt.Errorf("fwdsec: randomise key file before destroy: %w", err)
			}
			if err := os.WriteFile(k.path, noise, 0o600); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("fwdsec: overwrite key file: %w", err)
			}
			if err := os.Remove(k.path); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("fwdsec: remove key file: %w", err)
			}
		}
	}
	// Zero in-memory material regardless of disk outcome — best-effort
	// forward secrecy is better than leaving the bytes resident.
	// Unlock the pages before zeroing so they don't stay pinned in
	// the process's mlock budget after the slice becomes garbage.
	if k.priv != nil {
		_ = keyguard.Unlock(k.priv)
		for i := range k.priv {
			k.priv[i] = 0
		}
		k.priv = nil
	}
	k.qPriv = nil // Dilithium internal arrays are GC'd; nothing to zero
	return firstErr
}

// randSuffix returns a non-cryptographic random suffix for file names.
func randSuffix() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
