// Package checkpoint defines the signed statement of "the log has size N and
// root R at time T" that gets anchored to external transparency logs and
// countersigned by witnesses.
//
// The Signer is forward-secure: each checkpoint is signed by the active
// epoch's private key, and rotating keys invalidates the attacker's stolen
// material for all past timestamps. See pkg/fwdsec.
package checkpoint

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/threshold"
)

// Checkpoint is the signed statement covering the current Merkle tree state.
//
// Two operator-signing modes are supported:
//
//   - Single-sig: the legacy default. Signature is filled by the
//     forward-secure rotation key. MemberSigs is empty. ThresholdGroupDigest
//     is empty.
//
//   - Threshold (t-of-N): MemberSigs holds independent Ed25519
//     signatures from at least Threshold members of the group whose
//     hex digest is ThresholdGroupDigest. The legacy Signature field
//     is unused (and verifiers ignore it). The active group is
//     published out of band by the operator (alongside the root
//     pubkey) and is referenced here only by digest so a substitution
//     attempt fails verification.
type Checkpoint struct {
	Origin    string `json:"origin"`     // human label of the log instance
	Size      uint64 `json:"size"`       // number of leaves
	RootHash  []byte `json:"root_hash"`  // RFC 6962 Merkle root
	HeadHash  []byte `json:"head_hash"`  // EntryHash of the most recent entry
	TimeNanos int64  `json:"time_ns"`    // signing time
	EpochIdx  uint64 `json:"epoch_idx"`  // forward-secure epoch (single-sig mode)
	KeyID     string `json:"key_id"`     // SHA-256(epoch pubkey)[0:8] in hex
	Beacon    *Beacon `json:"beacon,omitempty"`

	// Single-sig mode:
	Signature []byte `json:"signature,omitempty"`

	// Hybrid post-quantum: when set, the operator was running in
	// --pq-mode hybrid and verifiers require BOTH Signature and
	// QuantumSignature to validate (using the per-epoch quantum
	// pubkey from the rotation chain).
	QuantumSignature []byte `json:"quantum_signature,omitempty"`

	// Threshold mode:
	ThresholdGroupDigest string                  `json:"threshold_group_digest,omitempty"` // hex of group digest
	MemberSigs           []*threshold.MemberSig  `json:"member_sigs,omitempty"`

	// Witness countersignatures (appended post-signing).
	Witnesses []*WitnessSig `json:"witnesses,omitempty"`
}

// Beacon binds a checkpoint to a recent public randomness value that
// could not have existed before the beacon's round. Defeats backdating.
type Beacon struct {
	Source    string `json:"source"`     // e.g. "drand"
	Round     uint64 `json:"round"`
	Value     []byte `json:"value"`      // raw randomness output
	Signature []byte `json:"signature,omitempty"` // beacon-provided sig if available
	ChainHash []byte `json:"chain_hash,omitempty"` // beacon group hash for replay
}

// WitnessSig is one witness's countersignature over the operator's
// already-signed checkpoint.
//
// When QuantumPublicKey + QuantumSignature are set the witness is
// running in hybrid mode and both signatures must verify.
type WitnessSig struct {
	WitnessID string `json:"witness_id"`
	PublicKey []byte `json:"public_key"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
	SignedAt  int64  `json:"signed_at"`

	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	QuantumSignature []byte `json:"quantum_signature,omitempty"`
}

// Canonical returns the deterministic bytes that the operator signs.
// Format is plain text and stable across versions. Both classical and
// post-quantum signatures cover the SAME bytes — the only thing that
// changes in hybrid mode is which keys produce which signature.
//
//	stele/v1
//	origin: <origin>
//	size: <decimal>
//	root: <hex>
//	head: <hex>
//	time: <decimal nanos>
//	epoch: <decimal>
//	beacon: <source>:<round>:<hex-value>     (or "none")
//	threshold_group: <hex digest>            (or "none")
//
// threshold_group is bound into the canonical bytes so an attacker
// cannot substitute a different group's signatures.
func (c *Checkpoint) Canonical() []byte {
	beacon := "none"
	if c.Beacon != nil {
		beacon = fmt.Sprintf("%s:%d:%s", c.Beacon.Source, c.Beacon.Round, hex.EncodeToString(c.Beacon.Value))
	}
	tg := c.ThresholdGroupDigest
	if tg == "" {
		tg = "none"
	}
	return []byte(fmt.Sprintf(
		"stele/v1\norigin: %s\nsize: %d\nroot: %s\nhead: %s\ntime: %d\nepoch: %d\nbeacon: %s\nthreshold_group: %s\n",
		c.Origin, c.Size,
		hex.EncodeToString(c.RootHash),
		hex.EncodeToString(c.HeadHash),
		c.TimeNanos,
		c.EpochIdx,
		beacon,
		tg,
	))
}

// CanonicalForWitness returns the bytes a witness signs: the operator's
// canonical bytes plus the operator's signature. A witness thus attests
// "I saw this checkpoint signed by this operator key at this epoch."
func (c *Checkpoint) CanonicalForWitness() []byte {
	op := c.Canonical()
	out := append([]byte(nil), op...)
	out = append(out, []byte("operator_sig: ")...)
	out = append(out, []byte(hex.EncodeToString(c.Signature))...)
	out = append(out, '\n')
	return out
}

// Signer wraps a forward-secure signer and (optionally) a threshold
// coordinator. When `threshGroup` and `coord` are both non-nil, Sign
// produces a threshold-signed checkpoint instead of a single-sig one.
type Signer struct {
	fws         *fwdsec.Signer
	threshGroup *threshold.Group
	coord       *threshold.Coordinator
}

// NewSigner adopts an existing forward-secure signer in single-sig mode.
func NewSigner(fws *fwdsec.Signer) *Signer { return &Signer{fws: fws} }

// NewThresholdSigner returns a Signer that produces threshold-signed
// checkpoints. `fws` is still used to identify the rotation epoch for
// telemetry, but its key does NOT sign checkpoints in threshold mode —
// only the group members do.
func NewThresholdSigner(fws *fwdsec.Signer, group *threshold.Group, coord *threshold.Coordinator) (*Signer, error) {
	if group == nil || coord == nil {
		return nil, errors.New("checkpoint: threshold signer requires both group and coordinator")
	}
	if err := group.Validate(); err != nil {
		return nil, err
	}
	return &Signer{fws: fws, threshGroup: group, coord: coord}, nil
}

// UnsafeFWS returns the underlying forward-secure signer. The name is
// deliberately ugly — callers should only use this to construct a
// derived Signer (e.g. converting a single-sig signer to a threshold
// signer that reuses the same epoch chain). Mutating the returned
// pointer can break invariants.
func (s *Signer) UnsafeFWS() *fwdsec.Signer { return s.fws }

// Mode returns "single" or "threshold" for logging.
func (s *Signer) Mode() string {
	if s.threshGroup != nil {
		return "threshold"
	}
	return "single"
}

// ThresholdGroup returns the active group (or nil in single-sig mode).
func (s *Signer) ThresholdGroup() *threshold.Group { return s.threshGroup }

// Sign produces a fresh checkpoint for (size, root, head). In
// single-sig mode it signs with the fwdsec rotation key. In threshold
// mode it builds the checkpoint with the group digest pre-set,
// canonicalises, and asks the coordinator to collect ≥ Threshold
// member signatures.
func (s *Signer) Sign(size uint64, root, head []byte, beacon *Beacon) (*Checkpoint, error) {
	pub := s.fws.Public()
	c := &Checkpoint{
		Origin:    s.fws.Origin(),
		Size:      size,
		RootHash:  append([]byte(nil), root...),
		HeadHash:  append([]byte(nil), head...),
		TimeNanos: time.Now().UnixNano(),
		EpochIdx:  s.fws.ActiveEpoch(),
		KeyID:     fwdsec.KeyID(pub),
		Beacon:    beacon,
	}
	if s.threshGroup != nil {
		c.ThresholdGroupDigest = hex.EncodeToString(s.threshGroup.Digest())
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		sigs, err := s.coord.Sign(ctx, c.Canonical(), fmt.Sprintf("checkpoint size=%d", size))
		if err != nil {
			return nil, fmt.Errorf("checkpoint threshold sign: %w", err)
		}
		c.MemberSigs = sigs
		return c, nil
	}
	canon := c.Canonical()
	_, sig, err := s.fws.Sign(canon)
	if err != nil {
		return nil, err
	}
	c.Signature = sig
	if s.fws.Hybrid() {
		qsig, err := s.fws.QuantumSign(canon)
		if err != nil {
			return nil, fmt.Errorf("checkpoint hybrid sign: %w", err)
		}
		c.QuantumSignature = qsig
	}
	return c, nil
}

// Public returns the active epoch public key.
func (s *Signer) Public() ed25519.PublicKey { return s.fws.Public() }

// Origin returns the operator label.
func (s *Signer) Origin() string { return s.fws.Origin() }

// Chain returns the rotation chain.
func (s *Signer) Chain() *fwdsec.Chain { return s.fws.Chain() }

// Rotate produces a new epoch and returns the new RotationCert.
func (s *Signer) Rotate() (*fwdsec.RotationCert, error) { return s.fws.Rotate() }

// Verify checks a checkpoint's operator signature. The verification
// rule dispatches on mode:
//
//   - If c.MemberSigs is non-empty, the checkpoint is threshold-signed.
//     `group` MUST be supplied and its digest must match
//     c.ThresholdGroupDigest. At least group.Threshold valid member
//     sigs must be present.
//
//   - Otherwise the checkpoint is single-sig. `chain` walks to find
//     the epoch's public key, which must match c.KeyID and verify
//     c.Signature.
//
// Witness signatures are NOT validated here — call VerifyWitnesses
// for that.
func Verify(c *Checkpoint, chain *fwdsec.Chain, rootPub ed25519.PublicKey, group *threshold.Group) error {
	if len(c.MemberSigs) > 0 {
		if group == nil {
			return errors.New("checkpoint: threshold-signed but no group supplied")
		}
		if err := group.Validate(); err != nil {
			return fmt.Errorf("threshold group: %w", err)
		}
		if c.ThresholdGroupDigest != hex.EncodeToString(group.Digest()) {
			return fmt.Errorf("checkpoint group digest %s does not match supplied group %s",
				c.ThresholdGroupDigest, hex.EncodeToString(group.Digest()))
		}
		return threshold.VerifyMulti(group, c.Canonical(), c.MemberSigs)
	}

	// Single-sig path (also the classical half of hybrid mode).
	if chain == nil {
		return errors.New("checkpoint: rotation chain required for single-sig verify")
	}
	if err := chain.VerifyChain(rootPub); err != nil {
		return fmt.Errorf("rotation chain: %w", err)
	}
	pub := chain.PublicKeyAt(c.EpochIdx)
	if pub == nil {
		return fmt.Errorf("rotation chain does not contain epoch %d", c.EpochIdx)
	}
	if got := fwdsec.KeyID(pub); got != c.KeyID {
		return fmt.Errorf("checkpoint key_id %s does not match epoch %d (%s)", c.KeyID, c.EpochIdx, got)
	}
	canon := c.Canonical()
	if !ed25519.Verify(pub, canon, c.Signature) {
		return errors.New("checkpoint operator signature invalid (classical)")
	}
	// Hybrid: when the chain registered a quantum public key for this
	// epoch, the checkpoint MUST carry a matching quantum signature.
	// Refusing to fall back to classical-only closes the downgrade
	// attack where an attacker who's broken Ed25519 strips the
	// quantum half from a checkpoint.
	qChainPub := chain.QuantumPublicKeyAt(c.EpochIdx)
	if len(qChainPub) > 0 {
		if len(c.QuantumSignature) == 0 {
			return fmt.Errorf("checkpoint epoch %d: chain has a quantum pubkey but checkpoint is missing quantum_signature (downgrade attempt?)", c.EpochIdx)
		}
		if err := verifyQuantumCheckpoint(qChainPub, canon, c.QuantumSignature); err != nil {
			return fmt.Errorf("checkpoint quantum signature: %w", err)
		}
	} else if len(c.QuantumSignature) > 0 {
		// Quantum sig provided but chain has no quantum pubkey for this
		// epoch — refuse rather than silently ignore.
		return fmt.Errorf("checkpoint epoch %d has quantum signature but chain has no quantum pubkey", c.EpochIdx)
	}
	return nil
}

// verifyQuantumCheckpoint decodes the Dilithium3 pubkey and verifies.
func verifyQuantumCheckpoint(pubBytes, msg, sig []byte) error {
	pub := &mode3.PublicKey{}
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return fmt.Errorf("decode quantum pubkey: %w", err)
	}
	if !mode3.Verify(pub, msg, sig) {
		return errors.New("dilithium signature invalid")
	}
	return nil
}

// VerifyWitnesses checks each WitnessSig against the operator-signed
// canonical bytes. The trust callback returns the trusted classical
// public key (and optionally a quantum public key) for a witness ID.
// A sig is counted if BOTH halves verify when a quantum trust anchor
// is supplied; otherwise classical alone counts.
func VerifyWitnesses(c *Checkpoint, trust func(witnessID string) (ed25519.PublicKey, error)) (validCount int, err error) {
	return VerifyWitnessesHybrid(c, func(id string) (ed25519.PublicKey, []byte, error) {
		ed, err := trust(id)
		return ed, nil, err
	})
}

// VerifyWitnessesHybrid is the hybrid-aware sibling of
// VerifyWitnesses. The trust callback returns both the trusted Ed25519
// pubkey AND the trusted Dilithium3 pubkey (nil = classical-only) for
// a witness. When the trust anchor includes a quantum half, the
// WitnessSig MUST carry a matching one — closes the downgrade attack.
func VerifyWitnessesHybrid(c *Checkpoint, trust func(witnessID string) (classical ed25519.PublicKey, quantum []byte, err error)) (validCount int, err error) {
	msg := c.CanonicalForWitness()
	for _, w := range c.Witnesses {
		pub, qpub, lookupErr := trust(w.WitnessID)
		if lookupErr != nil {
			continue
		}
		if len(w.PublicKey) != ed25519.PublicKeySize || !bytesEqual(w.PublicKey, pub) {
			continue
		}
		if !ed25519.Verify(pub, msg, w.Signature) {
			continue
		}
		// Hybrid: if the trust anchor specifies a quantum pubkey, the
		// witness sig MUST include + verify the quantum half. A
		// missing quantum sig counts as failure (downgrade refused).
		if len(qpub) > 0 {
			if len(w.QuantumPublicKey) == 0 || len(w.QuantumSignature) == 0 {
				continue
			}
			if !bytesEqual(w.QuantumPublicKey, qpub) {
				continue
			}
			qp := &mode3.PublicKey{}
			if err := qp.UnmarshalBinary(w.QuantumPublicKey); err != nil {
				continue
			}
			if !mode3.Verify(qp, msg, w.QuantumSignature) {
				continue
			}
		}
		validCount++
	}
	return validCount, nil
}

// Marshal returns indented JSON.
func (c *Checkpoint) Marshal() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }

// Unmarshal parses JSON.
func Unmarshal(buf []byte) (*Checkpoint, error) {
	var c Checkpoint
	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, err
	}
	return &c, nil
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
