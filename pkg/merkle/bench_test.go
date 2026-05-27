package merkle

import (
	"encoding/binary"
	"testing"
)

func benchTree(b *testing.B, n int) *Tree {
	b.Helper()
	tr := NewTree()
	buf := make([]byte, 8)
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		tr.AppendLeaf(buf)
	}
	return tr
}

// Measure the pure leaf-append cost (no signing, no storage).
func BenchmarkAppendLeaf(b *testing.B) {
	tr := NewTree()
	buf := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(buf, uint64(i))
		tr.AppendLeaf(buf)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "leaves/sec")
}

// Inclusion-proof generation cost vs. tree size. The proof size is
// O(log N) so the time should scale similarly.
func BenchmarkInclusionProof_1K(b *testing.B)  { benchInclusion(b, 1_000) }
func BenchmarkInclusionProof_10K(b *testing.B) { benchInclusion(b, 10_000) }
func BenchmarkInclusionProof_100K(b *testing.B) {
	if testing.Short() {
		b.Skip("skipped under -short")
	}
	benchInclusion(b, 100_000)
}

func benchInclusion(b *testing.B, n int) {
	tr := benchTree(b, n)
	size := tr.Size()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := uint64(i) % size
		if _, err := tr.InclusionProof(idx, size); err != nil {
			b.Fatal(err)
		}
	}
}

// Consistency-proof generation across a random old/new split.
func BenchmarkConsistencyProof_10K(b *testing.B) {
	tr := benchTree(b, 10_000)
	newSize := tr.Size()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		oldSize := uint64(i) % newSize
		if _, err := tr.ConsistencyProof(oldSize, newSize); err != nil {
			b.Fatal(err)
		}
	}
}

// Root recomputation. Cheap because compact.Range caches the spine,
// but worth tracking — if it ever regresses, every checkpoint slows down.
func BenchmarkRoot_10K(b *testing.B) {
	tr := benchTree(b, 10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tr.Root()
	}
}
