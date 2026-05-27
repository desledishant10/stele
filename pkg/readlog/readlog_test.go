package readlog

import (
	"encoding/hex"
	"testing"
)

func TestAppendVerifyReplay(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf := []byte("01234567890123456789012345678901")
	for i := 0; i < 5; i++ {
		ev, err := j.Append(uint64(i), leaf, "get_entry", "127.0.0.1:12345", "test-agent")
		if err != nil {
			t.Fatal(err)
		}
		if ev.Index != uint64(i) {
			t.Fatalf("event index %d, want %d", ev.Index, i)
		}
		if err := ev.Verify(); err != nil {
			t.Fatalf("event self-verify: %v", err)
		}
	}
	// Re-open: replay walks the file and checks every event + chain.
	j2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if j2.Size() != 5 {
		t.Fatalf("replayed size %d, want 5", j2.Size())
	}
	events, err := j2.Range(0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("range returned %d events, want 5", len(events))
	}
	// Chain integrity: every event's PrevHash matches the previous one's EventHash.
	for i := 1; i < len(events); i++ {
		if hex.EncodeToString(events[i].PrevHash) != hex.EncodeToString(events[i-1].EventHash) {
			t.Fatalf("chain break at event %d", events[i].Index)
		}
	}
}

func TestTamperedEventDetected(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf := []byte("11111111111111111111111111111111")
	ev, _ := j.Append(0, leaf, "get_entry", "1.2.3.4", "ua")
	if err := ev.Verify(); err != nil {
		t.Fatal(err)
	}
	// Tamper with the event in memory.
	ev.EntryIdx = 999
	if err := ev.Verify(); err == nil {
		t.Fatal("tamper should break verification")
	}
}
