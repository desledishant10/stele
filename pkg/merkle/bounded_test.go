package merkle

import (
	"crypto/rand"
	"testing"
)

// TestBoundedTree_CapsInternalNodes confirms the LRU bound on internal
// nodes does not exceed the configured cap, even when the tree grows
// well past it.
func TestBoundedTree_CapsInternalNodes(t *testing.T) {
	const N = 1000
	const cap = 50
	tree := NewBoundedTree(cap)

	leafSeen := make([][]byte, N)
	for i := 0; i < N; i++ {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		h, idx := tree.AppendLeaf(buf)
		leafSeen[i] = h
		if idx != uint64(i) {
			t.Fatalf("index mismatch at %d: got %d", i, idx)
		}
	}

	leaves, internal := tree.CacheSize()
	if leaves != N {
		t.Fatalf("expected %d leaves retained, got %d", N, leaves)
	}
	if internal > cap {
		t.Fatalf("internal node count %d exceeded cap %d", internal, cap)
	}
}

// TestBoundedTree_ProofsSurviveEviction confirms that an evicted
// internal node is correctly recomputed at proof time, so even with
// an aggressive cap the proofs still verify against the current root.
func TestBoundedTree_ProofsSurviveEviction(t *testing.T) {
	const N = 200
	const cap = 5
	tree := NewBoundedTree(cap)

	leafHashes := make([][]byte, N)
	for i := 0; i < N; i++ {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		h, _ := tree.AppendLeaf(buf)
		leafHashes[i] = h
	}
	root := tree.Root()

	// Now request proofs for entries scattered through the log. Anything
	// not at the right edge will need at least some recomputation because
	// the tiny cap evicted aggressively.
	for _, idx := range []uint64{0, 1, 7, 42, 99, 150, 199} {
		prf, err := tree.InclusionProof(idx, uint64(N))
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", idx, err)
		}
		if err := VerifyInclusion(idx, uint64(N), leafHashes[idx], prf, root); err != nil {
			t.Fatalf("VerifyInclusion(%d) failed: %v", idx, err)
		}
	}
}

// TestBoundedTree_UnboundedMatchesLegacy: NewBoundedTree(0) should
// behave identically to the legacy NewTree() for any small log.
func TestBoundedTree_UnboundedMatchesLegacy(t *testing.T) {
	const N = 64
	legacy := NewTree()
	bounded := NewBoundedTree(0)

	for i := 0; i < N; i++ {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		legacy.AppendLeaf(buf)
		bounded.AppendLeaf(buf)
	}

	if string(legacy.Root()) != string(bounded.Root()) {
		t.Fatalf("roots differ: legacy=%x bounded=%x", legacy.Root(), bounded.Root())
	}

	legacyLeaves, legacyInternal := legacy.CacheSize()
	boundedLeaves, boundedInternal := bounded.CacheSize()
	if legacyLeaves != boundedLeaves {
		t.Fatalf("leaf counts differ: legacy=%d bounded=%d", legacyLeaves, boundedLeaves)
	}
	if legacyInternal != boundedInternal {
		t.Fatalf("internal counts differ: legacy=%d bounded=%d", legacyInternal, boundedInternal)
	}
}
