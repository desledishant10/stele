// Package merkle wraps the canonical transparency-dev/merkle library to
// provide an RFC 6962 Merkle tree that can produce inclusion and consistency
// proofs with a bounded in-memory footprint.
//
// The tree stores internal node hashes so arbitrary proofs are cheap. For a
// log with N entries this is O(N) memory unless a max-node bound is
// configured via NewBoundedTree. With a bound, older internal nodes are
// evicted from the in-memory map and recomputed on demand from the leaves
// (slower proofs but bounded RSS).
//
// Leaves (level-0 nodes) are held behind a LeafStore rather than pinned in
// RAM. steled backs the LeafStore with BadgerDB (the leaf/ keyspace) and
// keeps only a small LRU of recently-touched leaves in memory, so total
// Merkle RSS is O(LRU caps), not O(log size), for arbitrarily large logs.
// See issue #8.
package merkle

import (
	"container/list"
	"fmt"

	tdmerkle "github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// Hasher is the RFC 6962 SHA-256 hasher used by Certificate Transparency and
// Sigstore Rekor.
var Hasher tdmerkle.LogHasher = rfc6962.DefaultHasher

// HashSize is the size in bytes of a single hash (SHA-256).
const HashSize = 32

// LeafStore is the durable home for leaf (level-0) hashes. The Merkle tree
// reads a leaf through it on the proof hot path and holds only a small LRU in
// memory. steled satisfies it with the BadgerDB leaf/ keyspace; tests use the
// in-memory default from NewTree / NewBoundedTree.
//
// GetLeafHash returns (hash, true, nil) when a leaf is stored for idx,
// (nil, false, nil) when none is, and a non-nil error only on a backing-store
// failure. PutLeafHash records a leaf for later retrieval; it is a no-op in
// deployments where the caller has already persisted the leaf durably (steled
// writes it atomically with the entry) and never fails from the tree's view.
type LeafStore interface {
	GetLeafHash(idx uint64) (hash []byte, ok bool, err error)
	PutLeafHash(idx uint64, hash []byte)
}

// memLeafStore is the default in-memory LeafStore. It retains every leaf and
// is used by NewTree / NewBoundedTree so tests and short-lived processes keep
// the pre-v0.1.7 behaviour without a disk dependency.
type memLeafStore struct {
	leaves map[uint64][]byte
}

func (m *memLeafStore) GetLeafHash(idx uint64) ([]byte, bool, error) {
	h, ok := m.leaves[idx]
	return h, ok, nil
}

func (m *memLeafStore) PutLeafHash(idx uint64, hash []byte) {
	m.leaves[idx] = append([]byte(nil), hash...)
}

// Tree is an append-only Merkle tree with a bounded in-memory footprint.
//
// Memory layout:
//   - Leaves (level-0 nodes) live in the LeafStore. A bounded LRU keeps the
//     most-recently-touched leaves resident; a miss reads through to the
//     store. computeNode rebuilds any evicted internal node from leaves, so
//     the store must hold every leaf.
//   - Internal nodes (level >= 1) are LRU-evictable when
//     NewBoundedTree(maxInternal > 0) is used. On eviction, a subsequent
//     proof that needs the node recomputes it from the leaves.
//
// When maxInternal == 0 (default via NewTree), no internal node is ever
// evicted. When maxLeaf == 0, the leaf LRU is unbounded — legacy behaviour,
// used by the in-memory constructors.
type Tree struct {
	rng *compact.Range

	leafStore LeafStore
	leafLRU   *list.List               // front = most recent
	leafIdx   map[uint64]*list.Element // idx -> LRU element
	maxLeaf   int                      // 0 = unbounded

	internal    map[compact.NodeID]*list.Element // level >= 1, LRU-managed
	lru         *list.List                       // front = most recent
	maxInternal int                              // 0 = unbounded
}

type lruEntry struct {
	id   compact.NodeID
	hash []byte
}

type leafLRUEntry struct {
	idx  uint64
	hash []byte
}

// NewTree returns an unbounded in-memory tree. Suitable for tests and
// short-lived processes; for production-shape steled use
// NewBoundedTreeWithStore with a disk-backed LeafStore and reasonable caps.
func NewTree() *Tree {
	return NewBoundedTree(0)
}

// NewBoundedTree returns a tree that retains at most maxInternalNodes non-leaf
// node hashes in memory. Leaves are kept in an in-memory store (unbounded), so
// this constructor's footprint is still O(log size) in leaves — it exists for
// tests and backward compatibility. Production steled uses
// NewBoundedTreeWithStore.
//
// Set maxInternalNodes = 0 for legacy fully-unbounded behaviour.
func NewBoundedTree(maxInternalNodes int) *Tree {
	return NewBoundedTreeWithStore(maxInternalNodes, 0, &memLeafStore{leaves: make(map[uint64][]byte)})
}

// NewBoundedTreeWithStore returns a tree that holds at most maxInternalNodes
// internal node hashes and at most maxLeafNodes leaf hashes in memory, reading
// leaves through ls on a miss.
//
// Sizing: ~130 B per cached internal node and ~80 B per cached leaf (hash +
// map + LRU bookkeeping). With disk-backed leaves, steady-state Merkle RSS is
// roughly maxInternalNodes*130 + maxLeafNodes*80 bytes regardless of log size.
//
// maxInternalNodes = 0 disables internal eviction; maxLeafNodes = 0 disables
// leaf eviction (unbounded leaf LRU). ls must not be nil.
func NewBoundedTreeWithStore(maxInternalNodes, maxLeafNodes int, ls LeafStore) *Tree {
	if ls == nil {
		panic("merkle: LeafStore must not be nil")
	}
	factory := &compact.RangeFactory{Hash: Hasher.HashChildren}
	return &Tree{
		rng:         factory.NewEmptyRange(0),
		leafStore:   ls,
		leafLRU:     list.New(),
		leafIdx:     make(map[uint64]*list.Element),
		maxLeaf:     maxLeafNodes,
		internal:    make(map[compact.NodeID]*list.Element),
		lru:         list.New(),
		maxInternal: maxInternalNodes,
	}
}

// putLeaf records a leaf in the durable store and the in-memory LRU.
func (t *Tree) putLeaf(idx uint64, hash []byte) {
	cp := append([]byte(nil), hash...)
	t.leafStore.PutLeafHash(idx, cp)
	if el, ok := t.leafIdx[idx]; ok {
		el.Value.(*leafLRUEntry).hash = cp
		t.leafLRU.MoveToFront(el)
		return
	}
	el := t.leafLRU.PushFront(&leafLRUEntry{idx: idx, hash: cp})
	t.leafIdx[idx] = el
	if t.maxLeaf > 0 && t.leafLRU.Len() > t.maxLeaf {
		if oldest := t.leafLRU.Back(); oldest != nil {
			t.leafLRU.Remove(oldest)
			delete(t.leafIdx, oldest.Value.(*leafLRUEntry).idx)
		}
	}
}

// putNode stores hash for id. Leaves go through putLeaf; internal nodes go to
// the LRU-managed internal map.
func (t *Tree) putNode(id compact.NodeID, hash []byte) {
	if id.Level == 0 {
		t.putLeaf(id.Index, hash)
		return
	}
	cp := append([]byte(nil), hash...)
	if el, ok := t.internal[id]; ok {
		el.Value.(*lruEntry).hash = cp
		t.lru.MoveToFront(el)
		return
	}
	el := t.lru.PushFront(&lruEntry{id: id, hash: cp})
	t.internal[id] = el
	if t.maxInternal > 0 && t.lru.Len() > t.maxInternal {
		oldest := t.lru.Back()
		if oldest != nil {
			t.lru.Remove(oldest)
			delete(t.internal, oldest.Value.(*lruEntry).id)
		}
	}
}

// CacheSize returns (resident_leaf_count, internal_node_count). Useful for
// telemetry + tests. The leaf count is the LRU residency, not the log size.
func (t *Tree) CacheSize() (leaves, internal int) {
	return t.leafLRU.Len(), t.lru.Len()
}

// Size returns the current number of leaves.
func (t *Tree) Size() uint64 { return t.rng.End() }

// Root returns the current Merkle root, or the RFC 6962 empty root when no
// leaves have been appended.
func (t *Tree) Root() []byte {
	if t.Size() == 0 {
		return Hasher.EmptyRoot()
	}
	root, err := t.rng.GetRootHash(nil)
	if err != nil {
		// GetRootHash only errors on inconsistent internal state, which we
		// have not produced. If it ever fires, that is a programmer bug.
		panic(fmt.Sprintf("merkle: GetRootHash failed: %v", err))
	}
	return root
}

// AppendLeaf hashes raw data as a leaf, appends it, and returns the resulting
// leaf hash and its 0-based index.
func (t *Tree) AppendLeaf(data []byte) (leafHash []byte, idx uint64) {
	leafHash = Hasher.HashLeaf(data)
	idx = t.AppendLeafHash(leafHash)
	return leafHash, idx
}

// AppendLeafHash appends an already-hashed leaf. Used during replay from
// storage so we do not double-hash.
func (t *Tree) AppendLeafHash(leafHash []byte) uint64 {
	idx := t.rng.End()
	// The leaf itself lives at level 0.
	t.putNode(compact.NewNodeID(0, idx), leafHash)
	if err := t.rng.Append(leafHash, func(id compact.NodeID, hash []byte) {
		t.putNode(id, hash)
	}); err != nil {
		panic(fmt.Sprintf("merkle: Append failed: %v", err))
	}
	return idx
}

// nodeHash returns the hash at the given node ID. For a leaf it checks the
// in-memory LRU first, then reads through to the LeafStore (refreshing the
// LRU on a hit). For an internal node it returns the cached hash if resident;
// a miss (evicted node, or an ephemeral right-edge node) leaves it to the
// caller to recompute. A non-nil error signals a LeafStore failure and is
// distinct from a plain cache/store miss (ok == false, err == nil).
func (t *Tree) nodeHash(id compact.NodeID) (hash []byte, ok bool, err error) {
	if id.Level == 0 {
		if el, hit := t.leafIdx[id.Index]; hit {
			t.leafLRU.MoveToFront(el)
			return el.Value.(*leafLRUEntry).hash, true, nil
		}
		h, found, serr := t.leafStore.GetLeafHash(id.Index)
		if serr != nil {
			return nil, false, fmt.Errorf("merkle: leaf store read L0[%d]: %w", id.Index, serr)
		}
		if !found {
			return nil, false, nil
		}
		// Promote the freshly-read leaf into the resident LRU.
		t.putLeaf(id.Index, h)
		return h, true, nil
	}
	el, hit := t.internal[id]
	if !hit {
		return nil, false, nil
	}
	t.lru.MoveToFront(el)
	return el.Value.(*lruEntry).hash, true, nil
}

// InclusionProof returns the proof that the leaf at `idx` is in the tree of
// size `treeSize`. The returned proof is a slice of sibling hashes; pass it
// to VerifyInclusion together with the leaf hash and expected root.
func (t *Tree) InclusionProof(idx, treeSize uint64) ([][]byte, error) {
	if treeSize > t.Size() {
		return nil, fmt.Errorf("merkle: treeSize %d exceeds current size %d", treeSize, t.Size())
	}
	nodes, err := proof.Inclusion(idx, treeSize)
	if err != nil {
		return nil, fmt.Errorf("merkle: building inclusion node list: %w", err)
	}
	return t.materialise(nodes)
}

// ConsistencyProof returns the proof that a tree of size `oldSize` is a
// prefix of a tree of size `newSize`. An empty proof is returned when
// oldSize == 0 (vacuously consistent) or oldSize == newSize.
func (t *Tree) ConsistencyProof(oldSize, newSize uint64) ([][]byte, error) {
	if oldSize > newSize {
		return nil, fmt.Errorf("merkle: oldSize %d > newSize %d", oldSize, newSize)
	}
	if newSize > t.Size() {
		return nil, fmt.Errorf("merkle: newSize %d exceeds current size %d", newSize, t.Size())
	}
	if oldSize == 0 || oldSize == newSize {
		return [][]byte{}, nil
	}
	nodes, err := proof.Consistency(oldSize, newSize)
	if err != nil {
		return nil, fmt.Errorf("merkle: building consistency node list: %w", err)
	}
	return t.materialise(nodes)
}

// materialise turns a proof.Nodes description into the actual sibling hashes.
// Some "ephemeral" nodes have to be recomputed by hashing a range of leaves
// because they correspond to right-edge subtrees that are not aligned to a
// perfect power of two.
func (t *Tree) materialise(nodes proof.Nodes) ([][]byte, error) {
	hashes := make([][]byte, 0, len(nodes.IDs))
	for _, id := range nodes.IDs {
		h, ok, err := t.nodeHash(id)
		if err != nil {
			return nil, err
		}
		if !ok {
			rehashed, err := t.computeNode(id)
			if err != nil {
				return nil, fmt.Errorf("merkle: cannot materialise node L%d[%d]: %w", id.Level, id.Index, err)
			}
			h = rehashed
		}
		hashes = append(hashes, h)
	}
	return nodes.Rehash(hashes, Hasher.HashChildren)
}

// computeNode rehashes a subtree node from its leaf coverage. We only ever
// reach this path for ephemeral right-edge nodes — proper internal nodes
// are cached when the compact.Range visits them. Because an ephemeral
// subtree is not aligned to a 2^L boundary, its halves are NOT the
// standard NodeID children; we have to split at the largest power-of-two
// boundary inside the leaf range, exactly how RFC 6962 defines an
// asymmetric subtree's root.
func (t *Tree) computeNode(id compact.NodeID) ([]byte, error) {
	begin, end := id.Coverage()
	if end > t.Size() {
		end = t.Size()
	}
	if begin >= end {
		return nil, fmt.Errorf("empty coverage for L%d[%d]", id.Level, id.Index)
	}
	return t.subRoot(begin, end)
}

// subRoot computes the root of the subtree covering leaves [begin, end).
// Recursion bottoms out at single leaves.
func (t *Tree) subRoot(begin, end uint64) ([]byte, error) {
	if begin+1 == end {
		h, ok, err := t.nodeHash(compact.NewNodeID(0, begin))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("missing leaf %d", begin)
		}
		return h, nil
	}
	span := end - begin
	k := uint64(1)
	for k*2 < span {
		k *= 2
	}
	split := begin + k
	left, err := t.subRoot(begin, split)
	if err != nil {
		return nil, err
	}
	right, err := t.subRoot(split, end)
	if err != nil {
		return nil, err
	}
	return Hasher.HashChildren(left, right), nil
}

// VerifyInclusion is a convenience pass-through to the library so callers do
// not have to import two merkle packages.
func VerifyInclusion(idx, treeSize uint64, leafHash []byte, prf [][]byte, root []byte) error {
	return proof.VerifyInclusion(Hasher, idx, treeSize, leafHash, prf, root)
}

// VerifyConsistency is a convenience pass-through.
func VerifyConsistency(oldSize, newSize uint64, prf [][]byte, oldRoot, newRoot []byte) error {
	return proof.VerifyConsistency(Hasher, oldSize, newSize, prf, oldRoot, newRoot)
}
