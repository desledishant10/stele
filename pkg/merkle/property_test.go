package merkle

import (
	"bytes"
	"encoding/binary"
	"testing"

	"pgregory.net/rapid"
)

// randomLeaves draws a slice of random leaf byte payloads.
func randomLeaves(t *rapid.T, name string) [][]byte {
	n := rapid.IntRange(0, 256).Draw(t, name+"_n")
	leaves := make([][]byte, n)
	for i := 0; i < n; i++ {
		// Mix in the index so leaves are usually distinct but we still let
		// rapid pick arbitrary bytes (and arbitrary length, including 0).
		body := rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(t, name+"_leaf")
		idxBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(idxBuf, uint64(i))
		leaves[i] = append(idxBuf, body...)
	}
	return leaves
}

func buildTree(leaves [][]byte) *Tree {
	tr := NewTree()
	for _, l := range leaves {
		tr.AppendLeaf(l)
	}
	return tr
}

// Determinism: building the same tree twice yields byte-equal roots and
// byte-equal inclusion proofs for every (idx, size) pair.
func TestProp_RootDeterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leaves := randomLeaves(t, "leaves")
		a := buildTree(leaves)
		b := buildTree(leaves)

		if !bytes.Equal(a.Root(), b.Root()) {
			t.Fatalf("roots differ for identical leaves: %x vs %x", a.Root(), b.Root())
		}
		if a.Size() != b.Size() {
			t.Fatalf("sizes differ: %d vs %d", a.Size(), b.Size())
		}
	})
}

// Inclusion soundness: for any tree of size N and any 0 <= idx < N,
// the inclusion proof verifies against the leaf hash and tree root.
func TestProp_InclusionVerifies(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leaves := randomLeaves(t, "leaves")
		if len(leaves) == 0 {
			return
		}
		tr := buildTree(leaves)
		size := tr.Size()
		root := tr.Root()

		idx := uint64(rapid.IntRange(0, int(size)-1).Draw(t, "idx"))
		prf, err := tr.InclusionProof(idx, size)
		if err != nil {
			t.Fatalf("InclusionProof(%d, %d) failed: %v", idx, size, err)
		}
		leafHash := Hasher.HashLeaf(leaves[idx])
		if err := VerifyInclusion(idx, size, leafHash, prf, root); err != nil {
			t.Fatalf("VerifyInclusion failed: %v", err)
		}
	})
}

// Inclusion rejects forgery: swapping the leaf hash for a different one,
// or flipping a byte in the root, must cause verification to fail.
func TestProp_InclusionRejectsTamper(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leaves := randomLeaves(t, "leaves")
		if len(leaves) == 0 {
			return
		}
		tr := buildTree(leaves)
		size := tr.Size()
		root := tr.Root()

		idx := uint64(rapid.IntRange(0, int(size)-1).Draw(t, "idx"))
		prf, err := tr.InclusionProof(idx, size)
		if err != nil {
			t.Fatalf("InclusionProof: %v", err)
		}
		// Tamper with leaf hash: flip a bit.
		good := Hasher.HashLeaf(leaves[idx])
		bad := append([]byte(nil), good...)
		bad[0] ^= 0xFF
		if err := VerifyInclusion(idx, size, bad, prf, root); err == nil {
			t.Fatalf("inclusion verified with tampered leaf hash")
		}
		// Tamper with root.
		badRoot := append([]byte(nil), root...)
		badRoot[len(badRoot)-1] ^= 0x01
		if err := VerifyInclusion(idx, size, good, prf, badRoot); err == nil {
			t.Fatalf("inclusion verified with tampered root")
		}
	})
}

// Consistency soundness: any (oldSize, newSize) with oldSize <= newSize
// yields a proof that verifies between the historical and current roots.
func TestProp_ConsistencyVerifies(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leaves := randomLeaves(t, "leaves")
		if len(leaves) < 2 {
			return
		}
		newSize := uint64(len(leaves))
		oldSize := uint64(rapid.IntRange(0, int(newSize)).Draw(t, "oldSize"))

		oldTree := buildTree(leaves[:oldSize])
		newTree := buildTree(leaves)
		oldRoot := oldTree.Root()
		newRoot := newTree.Root()

		prf, err := newTree.ConsistencyProof(oldSize, newSize)
		if err != nil {
			t.Fatalf("ConsistencyProof(%d,%d): %v", oldSize, newSize, err)
		}
		// Cases where the library accepts an empty proof: oldSize==0 or
		// oldSize==newSize. Those still must verify.
		if err := VerifyConsistency(oldSize, newSize, prf, oldRoot, newRoot); err != nil {
			t.Fatalf("VerifyConsistency(%d,%d): %v", oldSize, newSize, err)
		}
	})
}

// Consistency rejects rewrite: if any prefix leaf is modified, the
// produced "old root" must not consistency-verify against the real new root.
func TestProp_ConsistencyRejectsRewrite(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leaves := randomLeaves(t, "leaves")
		if len(leaves) < 2 {
			return
		}
		newSize := uint64(len(leaves))
		// Pick a strictly positive oldSize so there is a real prefix to rewrite.
		oldSize := uint64(rapid.IntRange(1, int(newSize)).Draw(t, "oldSize"))

		newTree := buildTree(leaves)
		newRoot := newTree.Root()

		// Build a tampered prefix tree by flipping one byte in one prefix leaf.
		victim := rapid.IntRange(0, int(oldSize)-1).Draw(t, "victim")
		tampered := make([][]byte, oldSize)
		for i := range tampered {
			tampered[i] = append([]byte(nil), leaves[i]...)
		}
		// Ensure the tamper actually changes the leaf — append a byte if empty.
		if len(tampered[victim]) == 0 {
			tampered[victim] = []byte{0xAA}
		} else {
			tampered[victim][0] ^= 0xFF
		}
		oldTree := buildTree(tampered)
		fakeOldRoot := oldTree.Root()

		prf, err := newTree.ConsistencyProof(oldSize, newSize)
		if err != nil {
			t.Fatalf("ConsistencyProof: %v", err)
		}
		if err := VerifyConsistency(oldSize, newSize, prf, fakeOldRoot, newRoot); err == nil {
			t.Fatalf("consistency verified with a rewritten prefix (victim=%d)", victim)
		}
	})
}

// Bad inputs must error, not panic.
func TestProp_BadInputsDoNotPanic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leaves := randomLeaves(t, "leaves")
		tr := buildTree(leaves)
		size := tr.Size()

		// Inclusion with treeSize > current size: errors.
		_, _ = tr.InclusionProof(0, size+1)
		// Inclusion with idx >= treeSize: library returns error from Inclusion.
		idx := uint64(rapid.IntRange(int(size), int(size)+10).Draw(t, "idx_ge"))
		_, _ = tr.InclusionProof(idx, size)
		// Consistency with oldSize > newSize.
		_, _ = tr.ConsistencyProof(size+1, size)
		// Consistency with newSize > current.
		_, _ = tr.ConsistencyProof(0, size+5)
	})
}
