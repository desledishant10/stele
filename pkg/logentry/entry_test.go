package logentry

import (
	"bytes"
	"testing"

	"github.com/desledishant10/stele/pkg/attest"
)

// helper: build a fresh producer attestor + a sealed envelope
func mkEnvelope(t *testing.T, source string, data []byte) *attest.Envelope {
	t.Helper()
	a, err := attest.NewSoftwareAttestor("test-producer")
	if err != nil {
		t.Fatal(err)
	}
	env, err := a.Sign(source, data)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestSealAndVerifyRoundTrip(t *testing.T) {
	e := New(0, nil, mkEnvelope(t, "host-a", []byte("hello")), false)
	if err := e.Verify(); err != nil {
		t.Fatalf("verify after seal: %v", err)
	}
	if !bytes.Equal(e.PrevHash, ZeroHash) {
		t.Fatalf("first entry must have zero PrevHash")
	}
}

func TestVerifyDetectsEnvelopeDataTampering(t *testing.T) {
	e := New(0, nil, mkEnvelope(t, "host-a", []byte("hello")), false)
	e.Envelope.Data[0] = 'X'
	if err := e.Verify(); err == nil {
		t.Fatal("verify should fail after envelope data tamper")
	}
}

func TestVerifyDetectsHoneypotFlagTampering(t *testing.T) {
	e := New(0, nil, mkEnvelope(t, "host-a", []byte("hello")), false)
	e.Honeypot = !e.Honeypot
	if err := e.Verify(); err == nil {
		t.Fatal("verify should fail after honeypot bit tamper")
	}
}

func TestChain(t *testing.T) {
	e0 := New(0, nil, mkEnvelope(t, "h", []byte("a")), false)
	e1 := New(1, e0, mkEnvelope(t, "h", []byte("b")), false)
	e2 := New(2, e1, mkEnvelope(t, "h", []byte("c")), false)

	if err := e0.VerifyChain(nil); err != nil {
		t.Fatalf("entry 0 chain: %v", err)
	}
	if err := e1.VerifyChain(e0); err != nil {
		t.Fatalf("entry 1 chain: %v", err)
	}
	if err := e2.VerifyChain(e1); err != nil {
		t.Fatalf("entry 2 chain: %v", err)
	}

	e2.PrevHash[0] ^= 0xFF
	if err := e2.VerifyChain(e1); err == nil {
		t.Fatal("chain should fail with tampered prev")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	prev := New(6, nil, mkEnvelope(t, "src", []byte("p")), false)
	e := New(7, prev, mkEnvelope(t, "src", []byte("payload")), true)
	buf, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Unmarshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := back.Verify(); err != nil {
		t.Fatalf("verify after round-trip: %v", err)
	}
	if back.Index != e.Index ||
		!bytes.Equal(back.Envelope.Data, e.Envelope.Data) ||
		back.Honeypot != e.Honeypot ||
		!bytes.Equal(back.EntryHash, e.EntryHash) {
		t.Fatalf("round-trip mismatch")
	}
}
