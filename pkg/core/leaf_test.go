package core

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/merkle"
	"github.com/desledishant10/stele/pkg/storage"
)

// openLeafCappedLog builds a Log over dir with aggressive Merkle caps so
// proofs are forced onto the disk read-through path, plus a registered
// producer. Caller closes the returned store.
func openLeafCappedLog(t *testing.T, dir string) (*Log, *storage.Store, *attest.SoftwareAttestor) {
	t.Helper()
	st, err := storage.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	fws, err := fwdsec.NewSigner("test.local/log", filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	sink, err := anchor.NewFileSink(filepath.Join(dir, "anchor.log"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(context.Background(), Options{
		Store:                st,
		Signer:               checkpoint.NewSigner(fws),
		Sinks:                []anchor.Sink{sink},
		MerkleCacheNodes:     4,
		MerkleLeafCacheNodes: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	prod, err := attest.NewSoftwareAttestor("test-producer")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RegisterProducer(&storage.Producer{
		ID:              "test-producer",
		PublicKey:       prod.PublicKey(),
		AttestationType: string(attest.TypeSoftware),
	}); err != nil {
		t.Fatal(err)
	}
	return l, st, prod
}

func verifyAllProofs(t *testing.T, l *Log, n uint64) {
	t.Helper()
	root := l.Root()
	for _, idx := range []uint64{0, 1, 13, n / 2, n - 2, n - 1} {
		if idx >= n {
			continue
		}
		e, err := l.Get(idx)
		if err != nil {
			t.Fatalf("Get(%d): %v", idx, err)
		}
		prf, err := l.InclusionProof(idx, n)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", idx, err)
		}
		if err := merkle.VerifyInclusion(idx, n, e.LeafHash, prf, root); err != nil {
			t.Fatalf("VerifyInclusion(%d) after read-through failed: %v", idx, err)
		}
	}
}

// TestLeafReadThroughAcrossRestart appends under a tiny leaf cap (so most
// leaves are evicted from RAM and must be read back from the store),
// restarts the Log via a fresh replay, and confirms proofs still verify —
// the end-to-end guarantee behind the O(cap) memory fix.
func TestLeafReadThroughAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	const N = 80

	l, st, prod := openLeafCappedLog(t, dir)
	for i := 0; i < N; i++ {
		env, err := prod.Sign("test", []byte(fmt.Sprintf("payload-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.Append(env, false); err != nil {
			t.Fatal(err)
		}
	}
	rootBefore := l.Root()
	verifyAllProofs(t, l, N) // leaves evicted → served from store
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Restart: fresh store + Log over the same dir triggers a full replay.
	l2, st2, _ := openLeafCappedLog(t, dir)
	defer st2.Close()
	if string(l2.Root()) != string(rootBefore) {
		t.Fatalf("root changed across restart: before=%x after=%x", rootBefore, l2.Root())
	}
	verifyAllProofs(t, l2, N)
}

// TestReplayBackfillsMissingLeaves simulates a pre-v0.1.7 log — entries on
// disk with no leaf/ mirror — by deleting the leaf keys, then confirms a
// fresh Log replay backfills them and serves correct proofs afterwards.
func TestReplayBackfillsMissingLeaves(t *testing.T) {
	dir := t.TempDir()
	const N = 40

	l, st, prod := openLeafCappedLog(t, dir)
	for i := 0; i < N; i++ {
		env, err := prod.Sign("test", []byte(fmt.Sprintf("payload-%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.Append(env, false); err != nil {
			t.Fatal(err)
		}
	}
	rootBefore := l.Root()

	// Strip the leaf/ mirror to emulate a log written before it existed.
	for i := uint64(0); i < N; i++ {
		if err := st.DeleteLeafHash(i); err != nil {
			t.Fatalf("DeleteLeafHash(%d): %v", i, err)
		}
	}
	if _, ok, _ := st.GetLeafHash(0); ok {
		t.Fatal("precondition: leaf mirror should be stripped")
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Replay must backfill and still land on the same root + valid proofs.
	l2, st2, _ := openLeafCappedLog(t, dir)
	defer st2.Close()
	if _, ok, _ := st2.GetLeafHash(0); !ok {
		t.Fatal("replay did not backfill the leaf mirror")
	}
	if string(l2.Root()) != string(rootBefore) {
		t.Fatalf("root changed after backfill replay: before=%x after=%x", rootBefore, l2.Root())
	}
	verifyAllProofs(t, l2, N)
}
