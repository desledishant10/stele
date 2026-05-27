package adminlog

import (
	"encoding/json"
	"testing"
)

func TestAppendAndReplay(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := j.Size(); got != 0 {
		t.Fatalf("fresh journal size = %d, want 0", got)
	}

	// Record three actions.
	if _, err := j.Action("rotate", "", "ok", "", map[string]int{"from_epoch": 0, "to_epoch": 1}, "alice", "10.0.0.1", "stele/test"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Action("producer_register", "alice@svc", "ok", "", map[string]string{"public_key": "AAAA="}, "alice", "10.0.0.1", "stele/test"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Action("witness_remove", "stale-witness", "error", "witness not found", nil, "bob", "10.0.0.2", "stele/test"); err != nil {
		t.Fatal(err)
	}
	if got := j.Size(); got != 3 {
		t.Fatalf("after 3 appends size = %d, want 3", got)
	}

	// Re-open: replay must succeed + size persists.
	j2, err := Open(dir)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	if got := j2.Size(); got != 3 {
		t.Fatalf("re-opened size = %d, want 3", got)
	}

	// Range fetch + per-event Verify().
	events, err := j2.Range(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("Range returned %d events, want 3", len(events))
	}
	for i, ev := range events {
		if got, want := ev.Index, uint64(i); got != want {
			t.Fatalf("event %d: Index = %d", i, got)
		}
		if err := ev.Verify(); err != nil {
			t.Fatalf("event %d: Verify: %v", i, err)
		}
	}
	// Hash-chain links.
	for i := 1; i < len(events); i++ {
		if string(events[i].PrevHash) != string(events[i-1].EventHash) {
			t.Fatalf("event %d PrevHash does not chain", i)
		}
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := j.Action("rotate", "", "ok", "", nil, "alice", "10.0.0.1", "stele/test")
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the recorded action.
	ev.Action = "producer_register" // changed AFTER signing
	if err := ev.Verify(); err == nil {
		t.Fatal("Verify accepted tampered Action field")
	}
}

func TestDetailsAreOptional(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := j.Action("rotate", "", "ok", "", nil, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Details) != 0 {
		t.Fatalf("nil details should produce empty raw, got %s", ev.Details)
	}
	if err := ev.Verify(); err != nil {
		t.Fatalf("verify nil-details event: %v", err)
	}
}

func TestDetailsMustBeValidJSON(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Pass something json.Marshal will reject (a channel).
	ch := make(chan int)
	_, err = j.Action("rotate", "", "ok", "", ch, "", "", "")
	if err == nil {
		t.Fatal("expected marshal error for non-JSON-able details")
	}
	if j.Size() != 0 {
		t.Fatalf("failed Action should not have advanced size; got %d", j.Size())
	}
}

func TestRangeRoundTripPreservesAction(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		Action  string
		Subject string
		Outcome string
	}
	cases := []want{
		{"rotate", "", "ok"},
		{"producer_register", "alice", "ok"},
		{"witness_add", "w1", "ok"},
	}
	for _, c := range cases {
		if _, err := j.Action(c.Action, c.Subject, c.Outcome, "", nil, "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	events, err := j.Range(0, 0) // 0 means "to current size"
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		got := events[i]
		if got.Action != c.Action || got.Subject != c.Subject || got.Outcome != c.Outcome {
			t.Fatalf("event %d: got %+v, want %+v", i, got, c)
		}
		// Sanity: each event JSON-round-trips.
		body, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		var back Event
		if err := json.Unmarshal(body, &back); err != nil {
			t.Fatal(err)
		}
		if err := back.Verify(); err != nil {
			t.Fatalf("round-tripped event %d verify: %v", i, err)
		}
	}
}
