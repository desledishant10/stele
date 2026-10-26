package merkle

import (
	"crypto/rand"
	"errors"
	"testing"
)

// countingLeafStore is an in-memory LeafStore that records reads and can be
// made to fail, so tests can assert read-through behaviour and error
// propagation on the proof hot path.
type countingLeafStore struct {
	leaves map[uint64][]byte
	reads  int
	failAt uint64 // index whose read returns an error; use ^uint64(0) for none
}

func newCountingLeafStore() *countingLeafStore {
	return &countingLeafStore{leaves: make(map[uint64][]byte), failAt: ^uint64(0)}
}

func (c *countingLeafStore) GetLeafHash(idx uint64) ([]byte, bool, error) {
	c.reads++
	if idx == c.failAt {
		return nil, false, errors.New("simulated leaf store failure")
	}
	h, ok := c.leaves[idx]
	return h, ok, nil
}

func (c *countingLeafStore) PutLeafHash(idx uint64, hash []byte) {
	c.leaves[idx] = append([]byte(nil), hash...)
}

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

// TestStoreBackedTree_CapsLeaves confirms the leaf LRU honours its cap while
// the tree grows well past it — the property that makes Merkle RSS O(cap)
// rather than O(log size).
func TestStoreBackedTree_CapsLeaves(t *testing.T) {
	const N = 1000
	const leafCap = 64
	ls := newCountingLeafStore()
	tree := NewBoundedTreeWithStore(50, leafCap, ls)

	for i := 0; i < N; i++ {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		tree.AppendLeaf(buf)
	}

	leaves, internal := tree.CacheSize()
	if leaves > leafCap {
		t.Fatalf("resident leaf count %d exceeded cap %d", leaves, leafCap)
	}
	if internal > 50 {
		t.Fatalf("internal node count %d exceeded cap 50", internal)
	}
	if len(ls.leaves) != N {
		t.Fatalf("store should hold every leaf: got %d want %d", len(ls.leaves), N)
	}
}

// TestStoreBackedTree_ProofsReadThroughStore confirms proofs still verify
// when leaves have been evicted from the in-memory LRU and must be read back
// from the store, and that doing so actually touches the store.
func TestStoreBackedTree_ProofsReadThroughStore(t *testing.T) {
	const N = 300
	const leafCap = 8
	ls := newCountingLeafStore()
	tree := NewBoundedTreeWithStore(5, leafCap, ls)

	leafHashes := make([][]byte, N)
	for i := 0; i < N; i++ {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		h, _ := tree.AppendLeaf(buf)
		leafHashes[i] = h
	}
	root := tree.Root()

	before := ls.reads
	for _, idx := range []uint64{0, 1, 7, 42, 99, 150, 299} {
		prf, err := tree.InclusionProof(idx, uint64(N))
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", idx, err)
		}
		if err := VerifyInclusion(idx, uint64(N), leafHashes[idx], prf, root); err != nil {
			t.Fatalf("VerifyInclusion(%d) failed: %v", idx, err)
		}
	}
	if ls.reads == before {
		t.Fatalf("expected proofs on an evicted log to read leaves from the store, but store was never hit")
	}
}

// TestStoreBackedTree_PropagatesStoreError confirms a backing-store read
// failure surfaces as a proof error rather than a silent wrong answer.
func TestStoreBackedTree_PropagatesStoreError(t *testing.T) {
	const N = 128
	ls := newCountingLeafStore()
	tree := NewBoundedTreeWithStore(2, 2, ls) // tiny caps force reads

	for i := 0; i < N; i++ {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		tree.AppendLeaf(buf)
	}
	// A proof for leaf 0 does not read leaf 0 itself (the subject is supplied
	// to the verifier), but under these tiny caps it recomputes evicted
	// right-hand siblings by reading their leaf ranges. Fail one of those
	// (index 50, not among the few LRU-resident recent leaves) and the error
	// must surface rather than yield a silent wrong proof.
	ls.failAt = 50

	if _, err := tree.InclusionProof(0, uint64(N)); err == nil {
		t.Fatalf("expected InclusionProof to surface the leaf store error, got nil")
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
