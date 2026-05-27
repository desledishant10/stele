package witness

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
)

// newTestOperator returns a freshly-initialised forward-secure signer
// + checkpoint signer the test can use to mint signed checkpoints.
func newTestOperator(t *testing.T, origin string) (*checkpoint.Signer, *fwdsec.Chain) {
	t.Helper()
	fws, err := fwdsec.NewSigner(origin, filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint.NewSigner(fws), fws.Chain()
}

func newTestWitness(t *testing.T, id string) *Server {
	t.Helper()
	s, err := NewServer(id, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCosignAcceptsThenRejectsFork(t *testing.T) {
	op, _ := newTestOperator(t, "test.local/log")
	w := newTestWitness(t, "auditor-x")
	if err := w.AddOperator(&WatchedOperator{
		Origin:        "test.local/log",
		RootPublicKey: op.Chain().RootPublicKey(),
	}); err != nil {
		t.Fatal(err)
	}

	// Honest checkpoint at size 5.
	root := []byte("01234567890123456789012345678901")
	head := make([]byte, 32)
	c1, err := op.Sign(5, root, head, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Cosign(c1, op.Chain(), nil); err != nil {
		t.Fatalf("first cosign should succeed: %v", err)
	}

	// Same size, DIFFERENT root — operator misbehaving.
	root2 := []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	c2, err := op.Sign(5, root2, head, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Cosign(c2, op.Chain(), nil); err == nil {
		t.Fatal("second cosign should detect fork and refuse")
	}
	// Origin should now be flagged forked; subsequent appends refused.
	root3 := []byte("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY")
	c3, err := op.Sign(6, root3, head, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Cosign(c3, op.Chain(), nil); err == nil {
		t.Fatal("cosign should remain refused after fork is flagged")
	}
	if len(w.ListForks()) == 0 {
		t.Fatal("expected at least one recorded fork")
	}
}

func TestGossipDetectsForkAcrossWitnesses(t *testing.T) {
	op, _ := newTestOperator(t, "test.local/log")

	// Two witnesses, neither has seen the other's data yet.
	wA := newTestWitness(t, "auditor-A")
	wB := newTestWitness(t, "auditor-B")
	for _, w := range []*Server{wA, wB} {
		if err := w.AddOperator(&WatchedOperator{
			Origin:        "test.local/log",
			RootPublicKey: op.Chain().RootPublicKey(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// A sees root R1 at size 5.
	rootA := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	head := make([]byte, 32)
	c1, _ := op.Sign(5, rootA, head, nil)
	if _, err := wA.Cosign(c1, op.Chain(), nil); err != nil {
		t.Fatal(err)
	}

	// B sees root R2 at size 5. Operator is forking.
	rootB := []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	c2, _ := op.Sign(5, rootB, head, nil)
	if _, err := wB.Cosign(c2, op.Chain(), nil); err != nil {
		t.Fatal(err)
	}

	// Now serve wB over HTTP so wA can gossip with it.
	srvB := httptest.NewServer(NewMux(wB))
	defer srvB.Close()

	if err := wA.AddPeer(&Peer{
		ID:        "auditor-B",
		URL:       srvB.URL,
		PublicKey: wB.PublicKey(),
	}); err != nil {
		t.Fatal(err)
	}

	// Run one gossip round manually.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	wA.gossipRound(ctx, GossipConfig{HTTP: srvB.Client(), Interval: time.Second})

	forks := wA.ListForks()
	if len(forks) == 0 {
		t.Fatal("expected wA to record a fork after gossip")
	}
	f := forks[0]
	if f.Origin != "test.local/log" || f.Size != 5 {
		t.Fatalf("unexpected fork shape: %+v", f)
	}
	if f.OurCheckpoint == nil || f.TheirCheckpoint == nil {
		t.Fatal("evidence must include both signed checkpoints")
	}
	// wA must refuse to cosign anything new for this operator.
	c3, _ := op.Sign(6, []byte("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"), head, nil)
	if _, err := wA.Cosign(c3, op.Chain(), nil); err == nil {
		t.Fatal("wA should refuse cosign after gossip-detected fork")
	}
}

// TestDishonestPeerContradictionIsAuditable simulates a peer that lies
// about its seen map. The first /seen-signed response says size 5 = R1;
// after we accept it, the peer changes its story to size 5 = R2 and
// signs the new statement. The gossip layer must:
//
//   - persist both signed statements (so we have the dishonesty as
//     mathematical evidence);
//   - record a fork for the affected origin;
//   - refuse further Cosign for that origin.
func TestDishonestPeerContradictionIsAuditable(t *testing.T) {
	// "Dishonest" peer is just a witness whose seen map we'll mutate
	// between two gossip calls.
	op, _ := newTestOperator(t, "test.local/log")
	dishonestWitness := newTestWitness(t, "dishonest-W")
	if err := dishonestWitness.AddOperator(&WatchedOperator{
		Origin:        "test.local/log",
		RootPublicKey: op.Chain().RootPublicKey(),
	}); err != nil {
		t.Fatal(err)
	}
	// Cosign a real checkpoint so the witness's seen map is non-empty.
	c1, _ := op.Sign(5, []byte("11111111111111111111111111111111"), make([]byte, 32), nil)
	if _, err := dishonestWitness.Cosign(c1, op.Chain(), nil); err != nil {
		t.Fatal(err)
	}

	// Wrap dishonestWitness in an HTTP server so we can drive gossip
	// against it like a real peer.
	srv := httptest.NewServer(NewMux(dishonestWitness))
	defer srv.Close()

	// The "honest" witness that will record the dishonest peer's
	// statements and detect the contradiction.
	honest := newTestWitness(t, "honest-X")
	if err := honest.AddOperator(&WatchedOperator{
		Origin:        "test.local/log",
		RootPublicKey: op.Chain().RootPublicKey(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := honest.AddPeer(&Peer{
		ID:        "dishonest-W",
		URL:       srv.URL,
		PublicKey: dishonestWitness.PublicKey(),
	}); err != nil {
		t.Fatal(err)
	}

	// First gossip round: honest fetches and persists the (truthful)
	// statement about R1 at size 5.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	honest.gossipRound(ctx, GossipConfig{HTTP: srv.Client(), Interval: time.Second})

	attestations := honest.PeerAttestations("dishonest-W")
	if len(attestations) != 1 {
		t.Fatalf("expected 1 attestation after first round, got %d", len(attestations))
	}
	if got := attestations[0].Statement.Seen[5]; got != "3131313131313131313131313131313131313131313131313131313131313131" {
		t.Fatalf("first statement should record R1 at size 5; got %s", got)
	}

	// Now the dishonest peer is bribed — it MUTATES its seen map to
	// say R2 at size 5 and re-issues a SignedSeen.
	dishonestWitness.mu.Lock()
	dishonestWitness.seen["test.local/log"][5] = "2222222222222222222222222222222222222222222222222222222222222222"
	dishonestWitness.mu.Unlock()

	// Second gossip round: honest re-fetches and notices the
	// contradiction with its persisted history.
	honest.gossipRound(ctx, GossipConfig{HTTP: srv.Client(), Interval: time.Second})

	attestations = honest.PeerAttestations("dishonest-W")
	if len(attestations) != 2 {
		t.Fatalf("expected 2 attestations after second round, got %d", len(attestations))
	}
	// Both statements are signed by the same key; together they prove
	// the peer was dishonest.
	if err := attestations[0].Statement.Verify(); err != nil {
		t.Fatalf("first signed statement should verify: %v", err)
	}
	if err := attestations[1].Statement.Verify(); err != nil {
		t.Fatalf("second signed statement should verify: %v", err)
	}
	if attestations[0].Statement.Seen[5] == attestations[1].Statement.Seen[5] {
		t.Fatal("expected contradicting roots in the two statements")
	}

	// A fork must be recorded so the operator is informed.
	forks := honest.ListForks()
	if len(forks) == 0 {
		t.Fatal("expected a fork to be recorded for the dishonest peer")
	}
	// The fork must reference the dishonest peer.
	found := false
	for _, f := range forks {
		if f.TheirPeerID == "dishonest-W" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("fork should be attributed to dishonest-W")
	}

	// Further cosigning for that origin should be refused.
	c2, _ := op.Sign(6, []byte("33333333333333333333333333333333"), make([]byte, 32), nil)
	if _, err := honest.Cosign(c2, op.Chain(), nil); err == nil {
		t.Fatal("honest witness should refuse to cosign after detecting a dishonest peer")
	}
}

func TestForkClearAllowsCosignAgain(t *testing.T) {
	op, _ := newTestOperator(t, "test.local/log")
	w := newTestWitness(t, "auditor-x")
	w.AddOperator(&WatchedOperator{
		Origin:        "test.local/log",
		RootPublicKey: op.Chain().RootPublicKey(),
	})
	c1, _ := op.Sign(1, []byte("11111111111111111111111111111111"), make([]byte, 32), nil)
	_, _ = w.Cosign(c1, op.Chain(), nil)
	c2, _ := op.Sign(1, []byte("22222222222222222222222222222222"), make([]byte, 32), nil)
	_, err := w.Cosign(c2, op.Chain(), nil)
	if err == nil {
		t.Fatal("expected fork rejection")
	}
	w.ClearFork("test.local/log")
	// New size, no contradiction — should now succeed.
	c3, _ := op.Sign(2, []byte("33333333333333333333333333333333"), make([]byte, 32), nil)
	if _, err := w.Cosign(c3, op.Chain(), nil); err != nil {
		t.Fatalf("cosign should succeed after fork cleared: %v", err)
	}
}
