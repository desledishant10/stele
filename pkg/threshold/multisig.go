package threshold

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// MemberSig is one member's signature on a canonical byte sequence.
// MemberID + PublicKey together identify the signer; both are recorded
// so verifiers can detect substitution attacks (an attacker swapping a
// MemberSig's PublicKey for one they control would fail the group
// membership check below).
//
// QuantumPublicKey + QuantumSignature are populated when the cosigner
// runs in hybrid mode. VerifyMulti checks both halves when the group's
// Member has a registered QuantumPublicKey.
type MemberSig struct {
	MemberID  string `json:"member_id"`
	PublicKey []byte `json:"public_key"`
	Signature []byte `json:"signature"`
	SignedAt  int64  `json:"signed_at,omitempty"`

	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	QuantumSignature []byte `json:"quantum_signature,omitempty"`
}

// Verify checks one MemberSig against a canonical message. It does
// not check group membership — that's VerifyMulti's job.
func (s *MemberSig) Verify(msg []byte) error {
	if len(s.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("member sig %q: bad pubkey length %d", s.MemberID, len(s.PublicKey))
	}
	if len(s.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("member sig %q: bad signature length %d", s.MemberID, len(s.Signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(s.PublicKey), msg, s.Signature) {
		return fmt.Errorf("member sig %q: invalid ed25519 signature", s.MemberID)
	}
	return nil
}

// VerifyMulti is the heart of threshold verification. Given a group,
// the canonical bytes that were signed, and a list of MemberSigs, it
// returns nil iff at least Threshold valid signatures from distinct,
// listed members are present.
//
// Specific failure conditions:
//
//   - A MemberSig whose MemberID is not in the group is ignored (does
//     not contribute to the count, does not abort verification — this
//     lets a friendly forward-compat case work where a member was
//     removed since signing).
//
//   - A MemberSig whose PublicKey does not match the group's listed
//     PublicKey for that MemberID is ignored (substitution attempt).
//
//   - A MemberSig whose ed25519 signature does not verify is ignored.
//
//   - Duplicate MemberIDs in the sig list count only once.
//
// If the number of distinct, valid sigs reaches Threshold, return nil.
func VerifyMulti(group *Group, msg []byte, sigs []*MemberSig) error {
	if err := group.Validate(); err != nil {
		return fmt.Errorf("threshold: invalid group: %w", err)
	}
	if len(sigs) == 0 {
		return errors.New("threshold: no signatures provided")
	}
	counted := make(map[string]struct{}, len(sigs))
	valid := 0
	var firstReject error
	for _, s := range sigs {
		if s == nil {
			continue
		}
		if _, dup := counted[s.MemberID]; dup {
			continue
		}
		m := group.MemberByID(s.MemberID)
		if m == nil {
			if firstReject == nil {
				firstReject = fmt.Errorf("unknown member %q", s.MemberID)
			}
			continue
		}
		if hex.EncodeToString(s.PublicKey) != hex.EncodeToString(m.PublicKey) {
			if firstReject == nil {
				firstReject = fmt.Errorf("member %q: public key in sig does not match group's registered key", s.MemberID)
			}
			continue
		}
		if err := s.Verify(msg); err != nil {
			if firstReject == nil {
				firstReject = err
			}
			continue
		}
		// Hybrid: if the group registered a quantum pubkey for this
		// member, the cosig MUST include a matching quantum signature.
		if len(m.QuantumPublicKey) > 0 {
			if len(s.QuantumPublicKey) == 0 || len(s.QuantumSignature) == 0 {
				if firstReject == nil {
					firstReject = fmt.Errorf("member %q: hybrid required but cosig is classical-only (downgrade attempt?)", s.MemberID)
				}
				continue
			}
			if hex.EncodeToString(s.QuantumPublicKey) != hex.EncodeToString(m.QuantumPublicKey) {
				if firstReject == nil {
					firstReject = fmt.Errorf("member %q: quantum pubkey in cosig does not match group's registered quantum key", s.MemberID)
				}
				continue
			}
			qp := &mode3.PublicKey{}
			if err := qp.UnmarshalBinary(s.QuantumPublicKey); err != nil {
				if firstReject == nil {
					firstReject = fmt.Errorf("member %q: decode quantum pubkey: %w", s.MemberID, err)
				}
				continue
			}
			if !mode3.Verify(qp, msg, s.QuantumSignature) {
				if firstReject == nil {
					firstReject = fmt.Errorf("member %q: invalid quantum signature", s.MemberID)
				}
				continue
			}
		}
		counted[s.MemberID] = struct{}{}
		valid++
	}
	if valid < int(group.Threshold) {
		if firstReject != nil {
			return fmt.Errorf("threshold: only %d/%d valid sigs (need >= %d); first rejection: %w",
				valid, len(sigs), group.Threshold, firstReject)
		}
		return fmt.Errorf("threshold: only %d valid sigs (need >= %d)", valid, group.Threshold)
	}
	return nil
}
