package core

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/storage"
	"github.com/desledishant10/stele/pkg/verify"
)

// testRig bundles a Log with a registered producer attestor so tests can
// append without worrying about registry boilerplate.
type testRig struct {
	Log      *Log
	Signer   *checkpoint.Signer
	Sink     *anchor.FileSink
	Store    *storage.Store
	Producer *attest.SoftwareAttestor
}

func newRig(t *testing.T, dir string) *testRig {
	t.Helper()
	st, err := storage.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	fws, err := fwdsec.NewSigner("test.local/log", filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	signer := checkpoint.NewSigner(fws)
	sink, err := anchor.NewFileSink(filepath.Join(dir, "anchor.log"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(context.Background(), Options{
		Store:  st,
		Signer: signer,
		Sinks:  []anchor.Sink{sink},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Register a default producer.
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
	return &testRig{Log: l, Signer: signer, Sink: sink, Store: st, Producer: prod}
}

func (r *testRig) appendStr(t *testing.T, source, data string) {
	t.Helper()
	env, err := r.Producer.Sign(source, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Log.Append(env, false); err != nil {
		t.Fatal(err)
	}
}

func TestAppendGetAndProof(t *testing.T) {
	dir := t.TempDir()
	r := newRig(t, dir)
	defer r.Store.Close()

	const N = 25
	for i := 0; i < N; i++ {
		r.appendStr(t, "test", fmt.Sprintf("payload-%d", i))
	}
	if r.Log.Size() != N {
		t.Fatalf("size %d, want %d", r.Log.Size(), N)
	}

	cp, err := r.Log.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	v := &verify.Verifier{Origin: r.Signer.Origin(), RootPublicKey: r.Signer.Chain().RootPublicKey(), Chain: r.Signer.Chain()}
	if err := v.Checkpoint(cp); err != nil {
		t.Fatalf("checkpoint verify: %v", err)
	}

	entry, err := r.Log.Get(13)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := r.Log.InclusionProof(13, N)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Inclusion(entry, N, proof, cp.RootHash); err != nil {
		t.Fatalf("inclusion verify: %v", err)
	}
}

func TestRejectsEnvelopeFromUnregisteredProducer(t *testing.T) {
	dir := t.TempDir()
	r := newRig(t, dir)
	defer r.Store.Close()

	imposter, err := attest.NewSoftwareAttestor("not-registered")
	if err != nil {
		t.Fatal(err)
	}
	env, err := imposter.Sign("h", []byte("malice"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Log.Append(env, false); err == nil {
		t.Fatal("expected unregistered producer to be rejected")
	}
}

func TestRejectsEnvelopeWithWrongKey(t *testing.T) {
	dir := t.TempDir()
	r := newRig(t, dir)
	defer r.Store.Close()

	// Register a producer ID but try to sign with a different key.
	other, _ := attest.NewSoftwareAttestor("test-producer")
	env, err := other.Sign("h", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Log.Append(env, false); err == nil {
		t.Fatal("expected mismatched-key envelope to be rejected")
	}
}

func TestReplayAfterReopen(t *testing.T) {
	dir := t.TempDir()
	r := newRig(t, dir)
	for i := 0; i < 10; i++ {
		r.appendStr(t, "a", fmt.Sprintf("e-%d", i))
	}
	rootBefore := append([]byte(nil), r.Log.Root()...)

	if err := r.Store.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-open the forward-secure signer from the same key directory; the
	// chain + active key persist across restarts.
	fws2, err := fwdsec.NewSigner(r.Log.Origin(), filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	signer2 := checkpoint.NewSigner(fws2)

	st2, err := storage.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	l2, err := New(context.Background(), Options{Store: st2, Signer: signer2})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if l2.Size() != 10 {
		t.Fatalf("replayed size %d, want 10", l2.Size())
	}
	if !bytes.Equal(l2.Root(), rootBefore) {
		t.Fatal("replayed root does not match")
	}
}

// TestReplayProtectionRefusesDuplicateEnvelope confirms that an
// envelope hash already accepted cannot be re-ingested. The defence
// works on the canonical envelope bytes, so re-using ANY field
// (including the time stamp) would still be the same envelope.
func TestReplayProtectionRefusesDuplicateEnvelope(t *testing.T) {
	dir := t.TempDir()
	r := newRig(t, dir)
	defer r.Store.Close()

	// Build one envelope and submit it twice.
	env, err := r.Producer.Sign("host", []byte("the same payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Log.Append(env, false); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if _, err := r.Log.Append(env, false); err == nil {
		t.Fatal("second append of the SAME envelope should have been refused (replay protection)")
	}
	// Submitting a DIFFERENT envelope from the same producer still works.
	env2, err := r.Producer.Sign("host", []byte("a different payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Log.Append(env2, false); err != nil {
		t.Fatalf("a different envelope must still be appendable: %v", err)
	}
}

func TestAnchorAndChainVerification(t *testing.T) {
	dir := t.TempDir()
	r := newRig(t, dir)
	defer r.Store.Close()

	for i := 0; i < 7; i++ {
		r.appendStr(t, "x", fmt.Sprintf("e-%d", i))
	}
	if _, err := r.Log.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Log.Anchor(); err != nil {
		t.Fatal(err)
	}
	for i := 7; i < 20; i++ {
		r.appendStr(t, "x", fmt.Sprintf("e-%d", i))
	}
	if _, err := r.Log.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Log.Anchor(); err != nil {
		t.Fatal(err)
	}
	records, err := r.Sink.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) < 2 {
		t.Fatalf("expected >=2 anchor records, got %d", len(records))
	}

	v := &verify.Verifier{Origin: r.Signer.Origin(), RootPublicKey: r.Signer.Chain().RootPublicKey(), Chain: r.Signer.Chain()}
	cproofs := make([][][]byte, len(records))
	for i := 1; i < len(records); i++ {
		p, err := r.Log.ConsistencyProof(records[i-1].Checkpoint.Size, records[i].Checkpoint.Size)
		if err != nil {
			t.Fatal(err)
		}
		cproofs[i] = p
	}
	if err := v.AnchorChain(records, cproofs); err != nil {
		t.Fatalf("anchor chain verify: %v", err)
	}
}
