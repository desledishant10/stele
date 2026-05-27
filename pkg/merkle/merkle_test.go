package merkle

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEmptyTreeRoot(t *testing.T) {
	tr := NewTree()
	if tr.Size() != 0 {
		t.Fatalf("empty size = %d, want 0", tr.Size())
	}
	if !bytes.Equal(tr.Root(), Hasher.EmptyRoot()) {
		t.Fatalf("empty root mismatch")
	}
}

func TestAppendAndInclusion(t *testing.T) {
	tr := NewTree()
	const N = 17 // intentionally not a power of 2
	leafHashes := make([][]byte, N)
	for i := 0; i < N; i++ {
		data := []byte{byte(i), 0xCC}
		h, idx := tr.AppendLeaf(data)
		if idx != uint64(i) {
			t.Fatalf("AppendLeaf returned idx %d, want %d", idx, i)
		}
		leafHashes[i] = h
	}
	if tr.Size() != N {
		t.Fatalf("Size = %d, want %d", tr.Size(), N)
	}
	root := tr.Root()
	for i := 0; i < N; i++ {
		proof, err := tr.InclusionProof(uint64(i), N)
		if err != nil {
			t.Fatalf("InclusionProof(%d, %d): %v", i, N, err)
		}
		if err := VerifyInclusion(uint64(i), N, leafHashes[i], proof, root); err != nil {
			t.Fatalf("VerifyInclusion(%d): %v", i, err)
		}
	}
}

func TestTamperedInclusionProofFails(t *testing.T) {
	tr := NewTree()
	for i := 0; i < 8; i++ {
		tr.AppendLeaf([]byte{byte(i)})
	}
	leafHash, _ := tr.AppendLeaf([]byte("target"))
	proof, err := tr.InclusionProof(8, 9)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the proof.
	if len(proof) == 0 {
		t.Fatal("expected non-empty proof")
	}
	tampered := append([][]byte{}, proof...)
	tampered[0] = append([]byte(nil), tampered[0]...)
	tampered[0][0] ^= 0x01
	if err := VerifyInclusion(8, 9, leafHash, tampered, tr.Root()); err == nil {
		t.Fatal("expected tampered proof to fail")
	}
}

func TestConsistencyAcrossManySizes(t *testing.T) {
	tr := NewTree()
	const N = 32
	roots := make([][]byte, N+1)
	roots[0] = append([]byte(nil), tr.Root()...)
	for i := 1; i <= N; i++ {
		tr.AppendLeaf([]byte{byte(i)})
		roots[i] = append([]byte(nil), tr.Root()...)
	}
	// For every pair (old, new) with old < new, verify consistency.
	for old := uint64(1); old < N; old++ {
		for newSize := old + 1; newSize <= N; newSize++ {
			proof, err := tr.ConsistencyProof(old, newSize)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d,%d): %v", old, newSize, err)
			}
			if err := VerifyConsistency(old, newSize, proof, roots[old], roots[newSize]); err != nil {
				t.Fatalf("VerifyConsistency(%d,%d): %v", old, newSize, err)
			}
		}
	}
}

func TestConsistencyFailsOnForkedRoot(t *testing.T) {
	tr := NewTree()
	for i := 0; i < 5; i++ {
		tr.AppendLeaf([]byte{byte(i)})
	}
	oldRoot := append([]byte(nil), tr.Root()...)
	for i := 5; i < 9; i++ {
		tr.AppendLeaf([]byte{byte(i)})
	}
	newRoot := tr.Root()
	proof, err := tr.ConsistencyProof(5, 9)
	if err != nil {
		t.Fatal(err)
	}
	// Pretend the old root was different.
	fake := append([]byte(nil), oldRoot...)
	fake[0] ^= 0xFF
	if err := VerifyConsistency(5, 9, proof, fake, newRoot); err == nil {
		t.Fatal("expected forked old root to fail")
	}
}

func TestEmptyConsistency(t *testing.T) {
	tr := NewTree()
	for i := 0; i < 3; i++ {
		tr.AppendLeaf([]byte{byte(i)})
	}
	proof, err := tr.ConsistencyProof(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Consistency from 0 is vacuous.
	if err := VerifyConsistency(0, 3, proof, nil, tr.Root()); err != nil {
		t.Fatal(err)
	}
}

func TestRandomBigTree(t *testing.T) {
	tr := NewTree()
	const N = 500
	leaves := make([][]byte, N)
	for i := 0; i < N; i++ {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		h, _ := tr.AppendLeaf(buf)
		leaves[i] = h
	}
	root := tr.Root()
	for _, i := range []int{0, 1, 17, 256, N - 1, N / 2} {
		proof, err := tr.InclusionProof(uint64(i), N)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", i, err)
		}
		if err := VerifyInclusion(uint64(i), N, leaves[i], proof, root); err != nil {
			t.Fatalf("VerifyInclusion(%d): %v", i, err)
		}
	}
	for _, pair := range [][2]uint64{{1, N}, {2, 100}, {99, 500}, {256, 257}} {
		proof, err := tr.ConsistencyProof(pair[0], pair[1])
		if err != nil {
			t.Fatalf("ConsistencyProof(%d,%d): %v", pair[0], pair[1], err)
		}
		// Compute both the old and the new root by replaying the matching
		// prefix of leaves through fresh trees — these are what the proof
		// must connect.
		oldSub, newSub := NewTree(), NewTree()
		for i := uint64(0); i < pair[0]; i++ {
			oldSub.AppendLeafHash(leaves[i])
		}
		for i := uint64(0); i < pair[1]; i++ {
			newSub.AppendLeafHash(leaves[i])
		}
		if err := VerifyConsistency(pair[0], pair[1], proof, oldSub.Root(), newSub.Root()); err != nil {
			t.Fatalf("VerifyConsistency(%d,%d): %v", pair[0], pair[1], err)
		}
	}
}
