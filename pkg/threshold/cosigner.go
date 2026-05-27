package threshold

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// Cosigner is the lightweight signing service one threshold-group
// member runs. It holds an Ed25519 key (and optionally a Dilithium3
// key in hybrid mode), accepts SIGN requests over HTTP, and returns
// a MemberSig.
//
// Run one Cosigner per Group member, on independent infrastructure.
type Cosigner struct {
	mu    sync.Mutex
	id    string
	dir   string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	qPriv *mode3.PrivateKey
	qPub  []byte // Dilithium3 public bytes

	// Authorisation: every SIGN request must include an X-Stele-Caller
	// header whose value matches an entry in trustedCallers. This is a
	// minimal token-auth layer — when the cosigner is also behind
	// mTLS, the network identity provides the real gate; the token
	// here is defense in depth.
	trustedCallers map[string]struct{}
}

// NewCosigner opens or creates a CLASSICAL cosigner. Use
// NewHybridCosigner to opt into Ed25519 + Dilithium3 signing.
func NewCosigner(id, dir string, trustedCallers []string) (*Cosigner, error) {
	return newCosigner(id, dir, trustedCallers, false)
}

// NewHybridCosigner opens or creates a HYBRID cosigner.
func NewHybridCosigner(id, dir string, trustedCallers []string) (*Cosigner, error) {
	return newCosigner(id, dir, trustedCallers, true)
}

func newCosigner(id, dir string, trustedCallers []string, hybrid bool) (*Cosigner, error) {
	if id == "" {
		return nil, errors.New("cosigner: id required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c := &Cosigner{id: id, dir: dir, trustedCallers: map[string]struct{}{}}
	for _, t := range trustedCallers {
		c.trustedCallers[t] = struct{}{}
	}
	if err := c.loadOrCreateClassical(); err != nil {
		return nil, err
	}
	if err := c.loadOrCreateQuantum(hybrid); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cosigner) loadOrCreateClassical() error {
	keyPath := filepath.Join(c.dir, "member.key")
	pubPath := filepath.Join(c.dir, "member.pub")

	if buf, err := os.ReadFile(keyPath); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(buf)))
		if err != nil {
			return err
		}
		if len(raw) != ed25519.PrivateKeySize {
			return fmt.Errorf("cosigner: key wrong length %d", len(raw))
		}
		c.priv = ed25519.PrivateKey(raw)
		c.pub = c.priv.Public().(ed25519.PublicKey)
		return nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	c.priv = priv
	c.pub = pub
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
}

func (c *Cosigner) loadOrCreateQuantum(hybrid bool) error {
	qKeyPath := filepath.Join(c.dir, "member-quantum.key")
	if buf, err := os.ReadFile(qKeyPath); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(buf)))
		if err != nil {
			return err
		}
		priv := &mode3.PrivateKey{}
		if err := priv.UnmarshalBinary(raw); err != nil {
			return fmt.Errorf("cosigner quantum key: %w", err)
		}
		c.qPriv = priv
		qPubBytes, err := priv.Public().(*mode3.PublicKey).MarshalBinary()
		if err != nil {
			return fmt.Errorf("cosigner: marshal Dilithium pubkey: %w", err)
		}
		c.qPub = qPubBytes
		return nil
	}
	if !hybrid {
		return nil
	}
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	c.qPriv = priv
	qPubBytes, err := pub.MarshalBinary()
	if err != nil {
		return fmt.Errorf("cosigner: marshal new Dilithium pubkey: %w", err)
	}
	c.qPub = qPubBytes
	body, err := priv.MarshalBinary()
	if err != nil {
		return err
	}
	if err := os.WriteFile(qKeyPath, []byte(base64.StdEncoding.EncodeToString(body)+"\n"), 0o600); err != nil {
		return err
	}
	qPubPath := filepath.Join(c.dir, "member-quantum.pub")
	return os.WriteFile(qPubPath, []byte(base64.StdEncoding.EncodeToString(c.qPub)+"\n"), 0o644)
}

// IsHybrid reports whether this cosigner signs in hybrid mode.
func (c *Cosigner) IsHybrid() bool { return c.qPriv != nil }

// QuantumPublicKey returns the Dilithium3 pubkey bytes (nil = classical-only).
func (c *Cosigner) QuantumPublicKey() []byte { return c.qPub }

// ID returns the member ID.
func (c *Cosigner) ID() string { return c.id }

// PublicKey returns the member's public key.
func (c *Cosigner) PublicKey() ed25519.PublicKey { return c.pub }

// KeyID is a short hex hash of the public key, for display.
func (c *Cosigner) KeyID() string {
	sum := sha256.Sum256(c.pub)
	return hex.EncodeToString(sum[:8])
}

// Sign signs the canonical bytes and returns a MemberSig. In hybrid
// mode both Ed25519 and Dilithium3 signatures are populated.
func (c *Cosigner) Sign(msg []byte) *MemberSig {
	c.mu.Lock()
	defer c.mu.Unlock()
	sig := ed25519.Sign(c.priv, msg)
	ms := &MemberSig{
		MemberID:  c.id,
		PublicKey: append([]byte(nil), c.pub...),
		Signature: sig,
		SignedAt:  time.Now().UnixNano(),
	}
	if c.qPriv != nil {
		qsig := make([]byte, mode3.SignatureSize)
		mode3.SignTo(c.qPriv, msg, qsig)
		ms.QuantumPublicKey = append([]byte(nil), c.qPub...)
		ms.QuantumSignature = qsig
	}
	return ms
}

// SignRequest is what the operator POSTs to /cosigner/v0/sign.
type SignRequest struct {
	// What is being signed. The cosigner does NOT introspect this —
	// it only signs the bytes. The operator is trusted to send well-
	// formed canonical material.
	Message []byte `json:"message"`

	// Optional context label for logging only (e.g. "checkpoint
	// size=42" or "rotation cert epoch 3").
	Context string `json:"context,omitempty"`
}

// SignResponse carries the MemberSig back.
type SignResponse struct {
	Sig *MemberSig `json:"sig"`
}

// IdentityResponse is what GET /cosigner/v0/identity returns.
type IdentityResponse struct {
	ID               string `json:"id"`
	PublicKey        []byte `json:"public_key"`
	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	KeyID            string `json:"key_id"`
}

// NewMux builds the HTTP handler for a Cosigner.
func NewMux(c *Cosigner) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/cosigner/v0/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, errors.New("POST required"))
			return
		}
		if !c.authoriseRequest(r) {
			writeErr(w, http.StatusForbidden, errors.New("caller not authorised"))
			return
		}
		var req SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if len(req.Message) == 0 {
			writeErr(w, http.StatusBadRequest, errors.New("message required"))
			return
		}
		writeJSON(w, http.StatusOK, SignResponse{Sig: c.Sign(req.Message)})
	})
	mux.HandleFunc("/cosigner/v0/identity", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, IdentityResponse{
			ID:               c.ID(),
			PublicKey:        c.PublicKey(),
			QuantumPublicKey: c.QuantumPublicKey(),
			KeyID:            c.KeyID(),
		})
	})
	// /healthz, /readyz, /metrics are mounted by callers via obs.Mount.
	return mux
}

// authoriseRequest enforces the trusted-caller token list (if any).
// An empty trustedCallers set means "allow anyone" — fine for demos
// behind mTLS, never appropriate for production.
func (c *Cosigner) authoriseRequest(r *http.Request) bool {
	if len(c.trustedCallers) == 0 {
		return true
	}
	tok := r.Header.Get("X-Stele-Caller")
	if tok == "" {
		return false
	}
	_, ok := c.trustedCallers[tok]
	return ok
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
