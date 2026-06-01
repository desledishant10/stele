// Package merkle wraps the canonical transparency-dev/merkle library to
// provide an in-memory RFC 6962 Merkle tree that can produce inclusion and
// consistency proofs.
//
// The tree stores every internal node hash (not just the rightmost spine) so
// arbitrary proofs are cheap. For a log with N entries this is O(N) memory
// unless a max-node bound is configured via NewBoundedTree. With a bound,
// older nodes are evicted from the in-memory map and recomputed on demand
// via the leaf store (slower proofs but bounded RSS). See issue #8.
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

// Tree is an append-only Merkle tree backed by an in-memory node store.
//
// Memory layout:
//   - Leaves (level 0 nodes) are ALWAYS retained. They are tiny
//     (~32 B + overhead each) and required by computeNode to rebuild
//     any evicted internal node.
//   - Internal nodes (level >= 1) are LRU-evictable when
//     NewBoundedTree(maxInternal > 0) is used. On eviction, a
//     subsequent proof that needs the node will recompute it from
//     the surviving leaves via computeNode (slower proof, bounded RSS).
//
// When maxInternal == 0 (default via NewTree), no internal node is
// ever evicted — legacy unbounded behaviour.
type Tree struct {
	rng         *compact.Range
	leaves      map[uint64][]byte                // idx -> leaf hash, never evicted
	internal    map[compact.NodeID]*list.Element // level >= 1, LRU-managed
	lru         *list.List                       // front = most recent
	maxInternal int                              // 0 = unbounded
}

type lruEntry struct {
	id   compact.NodeID
	hash []byte
}

// NewTree returns an unbounded in-memory tree. Suitable for tests and
// short-lived processes; for production-shape steled use NewBoundedTree
// with a reasonable internal-node cap.
func NewTree() *Tree {
	return NewBoundedTree(0)
}

// NewBoundedTree returns a tree that retains at most maxInternalNodes
// non-leaf node hashes in memory. Leaves are always retained.
//
// Sizing: ~130 B per cached internal node (hash + map + LRU bookkeeping).
// 1,000,000 internal nodes ≈ 130 MiB. The leaf count scales linearly with
// log size (~64 B / entry including overhead), so total Merkle RSS for a
// log of N entries with cap C is roughly N*64 + min(N, C)*130 bytes.
//
// Set maxInternalNodes = 0 for legacy unbounded behaviour.
func NewBoundedTree(maxInternalNodes int) *Tree {
	factory := &compact.RangeFactory{Hash: Hasher.HashChildren}
	return &Tree{
		rng:         factory.NewEmptyRange(0),
		leaves:      make(map[uint64][]byte),
		internal:    make(map[compact.NodeID]*list.Element),
		lru:         list.New(),
		maxInternal: maxInternalNodes,
	}
}

// putNode stores hash for id. Leaves go to the leaves map (no eviction);
// internal nodes go to the LRU-managed internal map.
func (t *Tree) putNode(id compact.NodeID, hash []byte) {
	cp := append([]byte(nil), hash...)
	if id.Level == 0 {
		t.leaves[id.Index] = cp
		return
	}
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

// CacheSize returns (leaf_count, internal_node_count). Useful for
// telemetry + tests.
func (t *Tree) CacheSize() (leaves, internal int) {
	return len(t.leaves), t.lru.Len()
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

// nodeHash returns the hash at the given node ID. If the node was not
// previously visited (e.g. an "ephemeral" right-edge node that requires
// rehashing for a specific proof, or an evicted internal node), the
// caller must compute it from leaves. A successful internal lookup
// refreshes the LRU position so frequently-proven nodes stay resident.
func (t *Tree) nodeHash(id compact.NodeID) ([]byte, bool) {
	if id.Level == 0 {
		h, ok := t.leaves[id.Index]
		return h, ok
	}
	el, ok := t.internal[id]
	if !ok {
		return nil, false
	}
	t.lru.MoveToFront(el)
	return el.Value.(*lruEntry).hash, true
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
		h, ok := t.nodeHash(id)
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
		h, ok := t.nodeHash(compact.NewNodeID(0, begin))
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
