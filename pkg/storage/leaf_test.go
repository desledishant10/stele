package storage

import (
	"bytes"
	"testing"

	"github.com/desledishant10/stele/pkg/logentry"
)

// TestAppendEntry_WritesLeafMirror confirms AppendEntry persists the compact
// leaf/ mirror atomically with the entry, and that GetLeafHash reads it back.
func TestAppendEntry_WritesLeafMirror(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	e := &logentry.Entry{Index: 0, PrevHash: logentry.ZeroHash}
	e.Seal()
	if err = st.AppendEntry(e); err != nil {
		t.Fatalf("AppendEntry: %v", err)
	}

	got, ok, err := st.GetLeafHash(0)
	if err != nil {
		t.Fatalf("GetLeafHash: %v", err)
	}
	if !ok {
		t.Fatal("GetLeafHash(0): leaf mirror missing after AppendEntry")
	}
	if !bytes.Equal(got, e.LeafHash) {
		t.Fatalf("leaf mirror mismatch: got %x want %x", got, e.LeafHash)
	}
}

// TestGetLeafHash_Miss confirms an index with no stored leaf reports a clean
// miss (ok == false, err == nil) rather than an error — the signal the core
// replay path uses to decide whether to backfill.
func TestGetLeafHash_Miss(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	if _, ok, err := st.GetLeafHash(99); err != nil || ok {
		t.Fatalf("GetLeafHash(99) on empty store: got ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

// TestPutLeafHash_Roundtrip confirms the backfill writer round-trips, which is
// what core.replay relies on for pre-v0.1.7 logs.
func TestPutLeafHash_Roundtrip(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	want := bytes.Repeat([]byte{0xab}, 32)
	if err = st.PutLeafHash(7, want); err != nil {
		t.Fatalf("PutLeafHash: %v", err)
	}
	got, ok, err := st.GetLeafHash(7)
	if err != nil || !ok {
		t.Fatalf("GetLeafHash(7): ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("roundtrip mismatch: got %x want %x", got, want)
	}
}
