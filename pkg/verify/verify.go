// Package verify is the client-side cryptographic audit. It does not need
// access to the log's database — it only takes the operator's public key
// plus whatever artifacts (entries, proofs, checkpoints, anchors) the
// auditor obtains from the server or a witness.
//
// All Verify* functions are pure: same inputs always produce the same
// result. That makes them safe to embed in CI pipelines, scheduled audit
// jobs, or third-party monitoring services.
package verify

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/logentry"
	"github.com/desledishant10/stele/pkg/merkle"
	"github.com/desledishant10/stele/pkg/threshold"
)

// Verifier holds the trust anchors required to validate stele artefacts:
// the origin label, the operator's GENESIS public key (the trust anchor
// the auditor obtained out-of-band), and the rotation chain the operator
// publishes via the API. Callers refresh the chain whenever the operator
// rotates.
type Verifier struct {
	Origin        string
	RootPublicKey ed25519.PublicKey
	Chain         *fwdsec.Chain

	// ThresholdGroup, when non-nil, switches Checkpoint verification
	// into threshold mode: the checkpoint's MemberSigs must include
	// ≥ Threshold valid signatures from this group's members.
	ThresholdGroup *threshold.Group

	// MinWitnesses, if > 0, requires that many distinct witness
	// signatures on each checkpoint. WitnessTrust resolves a witness ID
	// to that witness's public key (nil if unknown — call ignored).
	MinWitnesses int
	WitnessTrust func(witnessID string) (ed25519.PublicKey, error)
}

// Checkpoint verifies the operator signature, origin label, and (if
// configured) the witness signature quorum.
func (v *Verifier) Checkpoint(c *checkpoint.Checkpoint) error {
	if c.Origin != v.Origin {
		return fmt.Errorf("checkpoint origin %q does not match expected %q", c.Origin, v.Origin)
	}
	if err := checkpoint.Verify(c, v.Chain, v.RootPublicKey, v.ThresholdGroup); err != nil {
		return err
	}
	if v.MinWitnesses > 0 {
		trust := v.WitnessTrust
		if trust == nil {
			return errors.New("checkpoint: MinWitnesses set but WitnessTrust is nil")
		}
		valid, err := checkpoint.VerifyWitnesses(c, trust)
		if err != nil {
			return err
		}
		if valid < v.MinWitnesses {
			return fmt.Errorf("checkpoint: %d valid witness signatures, want >= %d", valid, v.MinWitnesses)
		}
	}
	return nil
}

// Inclusion checks that `entry` is committed by the Merkle root of size
// `treeSize`. Caller is expected to have already verified the checkpoint
// that produced (treeSize, root).
func (v *Verifier) Inclusion(entry *logentry.Entry, treeSize uint64, proof [][]byte, root []byte) error {
	if err := entry.Verify(); err != nil {
		return fmt.Errorf("entry self-verify: %w", err)
	}
	if entry.Index >= treeSize {
		return fmt.Errorf("entry index %d not in tree of size %d", entry.Index, treeSize)
	}
	return merkle.VerifyInclusion(entry.Index, treeSize, entry.LeafHash, proof, root)
}

// Consistency proves the tree of `oldSize` (with root `oldRoot`) is a prefix
// of the tree of `newSize` (with root `newRoot`).
func (v *Verifier) Consistency(oldSize uint64, oldRoot []byte, newSize uint64, newRoot []byte, proof [][]byte) error {
	return merkle.VerifyConsistency(oldSize, newSize, proof, oldRoot, newRoot)
}

// EntryChain validates a contiguous sequence of entries:
//   - each entry self-verifies (canonical hash matches stored hash);
//   - each entry's PrevHash equals the previous entry's EntryHash;
//   - indices increase by 1 starting from entries[0].Index.
// The first entry's PrevHash must be the all-zero hash iff its index is 0.
func (v *Verifier) EntryChain(entries []*logentry.Entry) error {
	if len(entries) == 0 {
		return errors.New("chain: empty entry list")
	}
	var prev *logentry.Entry
	for i, e := range entries {
		if err := e.Verify(); err != nil {
			return fmt.Errorf("chain[%d]: %w", i, err)
		}
		if err := e.VerifyChain(prev); err != nil {
			return fmt.Errorf("chain[%d]: %w", i, err)
		}
		prev = e
	}
	return nil
}

// AnchorChain takes a sequence of anchored Records (in size-ascending order)
// and verifies:
//   - every checkpoint signature is valid for this origin;
//   - every consistency proof (paired with the previous checkpoint's root)
//     is valid;
//   - sizes are monotonically non-decreasing.
//
// `consistencyProofs[i]` must be the proof from anchors[i-1].Size to
// anchors[i].Size. consistencyProofs[0] is ignored (no predecessor).
//
// If the operator ever rewrote history, one of the proofs here will fail.
func (v *Verifier) AnchorChain(records []*anchor.Record, consistencyProofs [][][]byte) error {
	if len(records) == 0 {
		return errors.New("anchor chain: empty")
	}
	if len(consistencyProofs) != len(records) {
		return fmt.Errorf("anchor chain: %d records but %d proofs", len(records), len(consistencyProofs))
	}
	var prev *checkpoint.Checkpoint
	for i, rec := range records {
		if rec.Checkpoint == nil {
			return fmt.Errorf("anchor chain[%d]: missing checkpoint", i)
		}
		if err := v.Checkpoint(rec.Checkpoint); err != nil {
			return fmt.Errorf("anchor chain[%d]: %w", i, err)
		}
		if prev != nil {
			if rec.Checkpoint.Size < prev.Size {
				return fmt.Errorf("anchor chain[%d]: size %d < previous %d",
					i, rec.Checkpoint.Size, prev.Size)
			}
			if rec.Checkpoint.Size == prev.Size {
				// Same size means same root, otherwise the operator forked.
				if !equalBytes(rec.Checkpoint.RootHash, prev.RootHash) {
					return fmt.Errorf("anchor chain[%d]: same size %d but different root", i, rec.Checkpoint.Size)
				}
			} else {
				err := v.Consistency(prev.Size, prev.RootHash,
					rec.Checkpoint.Size, rec.Checkpoint.RootHash, consistencyProofs[i])
				if err != nil {
					return fmt.Errorf("anchor chain[%d]: %w", i, err)
				}
			}
		}
		prev = rec.Checkpoint
	}
	return nil
}

func equalBytes(a, b []byte) bool {
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
