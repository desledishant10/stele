package mirror

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/api"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/core"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/storage"
)

// buildOperator stands up a fully-configured core.Log with a registered
// producer ready to send envelopes. Returns the operator, its CLI
// helpers, and a teardown func.
func buildOperator(t *testing.T) (*core.Log, *attest.SoftwareAttestor, *storage.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := storage.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	fws, err := fwdsec.NewSigner("test.local/log", filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	signer := checkpoint.NewSigner(fws)
	sink, _ := anchor.NewFileSink(filepath.Join(dir, "anchor.log"))

	op, err := core.New(context.Background(), core.Options{
		Store:  st,
		Signer: signer,
		Sinks:  []anchor.Sink{sink},
	})
	if err != nil {
		t.Fatal(err)
	}
	prod, err := attest.NewSoftwareAttestor("test-producer")
	if err != nil {
		t.Fatal(err)
	}
	if err := op.RegisterProducer(&storage.Producer{
		ID:              "test-producer",
		PublicKey:       prod.PublicKey(),
		AttestationType: string(attest.TypeSoftware),
	}); err != nil {
		t.Fatal(err)
	}
	return op, prod, st
}

func TestMirrorReplicatesEntries(t *testing.T) {
	op, prod, opStore := buildOperator(t)
	defer opStore.Close()

	// Append 5 entries to operator.
	for i := 0; i < 5; i++ {
		env, err := prod.Sign("h", []byte("data"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := op.Append(env, false); err != nil {
			t.Fatal(err)
		}
	}

	// Serve operator API.
	opSrv := httptest.NewServer(api.NewMux(&api.Server{Log: op}))
	defer opSrv.Close()

	// Build a mirror pulling from it.
	mirrorDir := t.TempDir()
	mst, err := storage.Open(filepath.Join(mirrorDir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer mst.Close()
	m, err := New(Config{
		Upstream:  opSrv.URL,
		HTTP:      opSrv.Client(),
		PollEvery: 50 * time.Millisecond,
		ChunkSize: 32,
	}, mst)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	// Wait until the mirror catches up.
	deadline := time.Now().Add(2 * time.Second)
	for m.Size() < 5 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if m.Size() != 5 {
		t.Fatalf("mirror size %d, want 5", m.Size())
	}

	// Mirror entries must equal operator entries byte-for-byte.
	for i := uint64(0); i < 5; i++ {
		mirrorEntry, err := m.GetEntry(i)
		if err != nil {
			t.Fatal(err)
		}
		opEntry, err := op.Get(i)
		if err != nil {
			t.Fatal(err)
		}
		if hashOf(mirrorEntry) != hashOf(opEntry) {
			t.Fatalf("entry %d hash mismatch (mirror=%s op=%s)", i, hashOf(mirrorEntry), hashOf(opEntry))
		}
	}

	// New entries continue to replicate.
	for i := 5; i < 12; i++ {
		env, _ := prod.Sign("h", []byte("more"))
		_, _ = op.Append(env, false)
	}
	deadline = time.Now().Add(2 * time.Second)
	for m.Size() < 12 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if m.Size() != 12 {
		t.Fatalf("mirror size %d, want 12", m.Size())
	}
}

func TestMirrorRejectsTamperedEntry(t *testing.T) {
	op, prod, opStore := buildOperator(t)
	defer opStore.Close()

	env, _ := prod.Sign("h", []byte("first"))
	if _, err := op.Append(env, false); err != nil {
		t.Fatal(err)
	}

	// Build a fake operator that returns a forged entry — same shape but
	// with a tampered Envelope.Data.
	tampered := &fakeServer{op: op, tamperIndex: 0}
	srv := httptest.NewServer(tampered)
	defer srv.Close()

	mirrorDir := t.TempDir()
	mst, err := storage.Open(filepath.Join(mirrorDir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer mst.Close()
	m, err := New(Config{
		Upstream: srv.URL,
		HTTP:     srv.Client(),
		PollEvery: 100 * time.Millisecond,
		ChunkSize: 32,
	}, mst)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.syncOnce(context.Background()); err == nil {
		t.Fatal("mirror should reject tampered entry")
	}
	if m.Size() != 0 {
		t.Fatalf("nothing should have been accepted; got size %d", m.Size())
	}
}
