package threshold

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"testing"
	"time"
)

func mkMember(t *testing.T, id string) (*Member, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Member{ID: id, PublicKey: pub}, priv
}

func TestGroupDigestStableUnderMemberOrder(t *testing.T) {
	mA, _ := mkMember(t, "alice")
	mB, _ := mkMember(t, "bob")
	mC, _ := mkMember(t, "carol")
	g1 := &Group{Version: 1, Origin: "test.local/log", Threshold: 2, CreatedAt: 1, Members: []*Member{mA, mB, mC}}
	g2 := &Group{Version: 1, Origin: "test.local/log", Threshold: 2, CreatedAt: 1, Members: []*Member{mC, mA, mB}}
	if g1.DigestHex() != g2.DigestHex() {
		t.Fatalf("digest unstable under reordering: %s vs %s", g1.DigestHex(), g2.DigestHex())
	}
}

func TestGroupValidate(t *testing.T) {
	mA, _ := mkMember(t, "alice")
	mB, _ := mkMember(t, "bob")
	cases := []struct {
		name string
		g    *Group
		ok   bool
	}{
		{"good", &Group{Version: 1, Origin: "o", Threshold: 1, Members: []*Member{mA}}, true},
		{"threshold too high", &Group{Version: 1, Origin: "o", Threshold: 3, Members: []*Member{mA, mB}}, false},
		{"threshold zero", &Group{Version: 1, Origin: "o", Threshold: 0, Members: []*Member{mA}}, false},
		{"no members", &Group{Version: 1, Origin: "o", Threshold: 1}, false},
		{"duplicate id", &Group{Version: 1, Origin: "o", Threshold: 1, Members: []*Member{mA, {ID: "alice", PublicKey: mB.PublicKey}}}, false},
		{"bad version", &Group{Version: 99, Origin: "o", Threshold: 1, Members: []*Member{mA}}, false},
		{"no origin", &Group{Version: 1, Threshold: 1, Members: []*Member{mA}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.g.Validate()
			if (err == nil) != c.ok {
				t.Fatalf("got err=%v, want ok=%v", err, c.ok)
			}
		})
	}
}

func TestVerifyMultiThresholdSemantics(t *testing.T) {
	mA, kA := mkMember(t, "alice")
	mB, kB := mkMember(t, "bob")
	mC, _ := mkMember(t, "carol")
	g := &Group{Version: 1, Origin: "test.local/log", Threshold: 2, CreatedAt: 1, Members: []*Member{mA, mB, mC}}

	msg := []byte("the canonical bytes")

	sigA := &MemberSig{MemberID: "alice", PublicKey: mA.PublicKey, Signature: ed25519.Sign(kA, msg)}
	sigB := &MemberSig{MemberID: "bob", PublicKey: mB.PublicKey, Signature: ed25519.Sign(kB, msg)}

	// Exactly threshold sigs -> OK.
	if err := VerifyMulti(g, msg, []*MemberSig{sigA, sigB}); err != nil {
		t.Fatalf("2/2 sigs should pass: %v", err)
	}

	// Below threshold -> fail.
	if err := VerifyMulti(g, msg, []*MemberSig{sigA}); err == nil {
		t.Fatal("1/2 should fail")
	}

	// Sig from a non-member is ignored.
	mD, kD := mkMember(t, "mallory")
	sigD := &MemberSig{MemberID: "mallory", PublicKey: mD.PublicKey, Signature: ed25519.Sign(kD, msg)}
	if err := VerifyMulti(g, msg, []*MemberSig{sigA, sigD}); err == nil {
		t.Fatal("alice + mallory should fail (only alice counts)")
	}

	// Substitution: alice's MemberID but mallory's pubkey + signature.
	swapped := &MemberSig{MemberID: "alice", PublicKey: mD.PublicKey, Signature: ed25519.Sign(kD, msg)}
	if err := VerifyMulti(g, msg, []*MemberSig{swapped, sigB}); err == nil {
		t.Fatal("substitution attack should be detected")
	}

	// Duplicate counts once.
	dup := &MemberSig{MemberID: "alice", PublicKey: mA.PublicKey, Signature: ed25519.Sign(kA, msg)}
	if err := VerifyMulti(g, msg, []*MemberSig{sigA, dup}); err == nil {
		t.Fatal("duplicate sigs should not satisfy threshold")
	}
}

// End-to-end: 3 cosigner daemons + a 2-of-3 group + a Coordinator
// that collects threshold signatures over HTTP.
func TestCosignerDaemonsEndToEnd(t *testing.T) {
	c1, _ := NewCosigner("alice", t.TempDir(), nil)
	c2, _ := NewCosigner("bob", t.TempDir(), nil)
	c3, _ := NewCosigner("carol", t.TempDir(), nil)

	srv1 := httptest.NewServer(NewMux(c1))
	srv2 := httptest.NewServer(NewMux(c2))
	srv3 := httptest.NewServer(NewMux(c3))
	defer srv1.Close()
	defer srv2.Close()
	defer srv3.Close()

	group := &Group{
		Version: 1, Origin: "test.local/log", Threshold: 2, CreatedAt: 1,
		Members: []*Member{
			{ID: "alice", PublicKey: c1.PublicKey(), Endpoint: srv1.URL},
			{ID: "bob",   PublicKey: c2.PublicKey(), Endpoint: srv2.URL},
			{ID: "carol", PublicKey: c3.PublicKey(), Endpoint: srv3.URL},
		},
	}
	if err := group.Validate(); err != nil {
		t.Fatal(err)
	}

	coord := NewCoordinator(group)
	coord.HTTP = srv1.Client()

	msg := []byte("test canonical bytes")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sigs, err := coord.Sign(ctx, msg, "test")
	if err != nil {
		t.Fatal(err)
	}
	if uint32(len(sigs)) < group.Threshold {
		t.Fatalf("got %d sigs, want >= %d", len(sigs), group.Threshold)
	}
	if err := VerifyMulti(group, msg, sigs); err != nil {
		t.Fatal(err)
	}
}

func TestCoordinatorRefusesWhenTooManyCosignersDown(t *testing.T) {
	c1, _ := NewCosigner("alice", t.TempDir(), nil)
	srv1 := httptest.NewServer(NewMux(c1))
	defer srv1.Close()

	mB, _ := mkMember(t, "bob")
	mC, _ := mkMember(t, "carol")
	group := &Group{
		Version: 1, Origin: "test.local/log", Threshold: 2, CreatedAt: 1,
		Members: []*Member{
			{ID: "alice", PublicKey: c1.PublicKey(), Endpoint: srv1.URL},
			{ID: "bob",   PublicKey: mB.PublicKey, Endpoint: "http://127.0.0.1:1"}, // down
			{ID: "carol", PublicKey: mC.PublicKey, Endpoint: "http://127.0.0.1:2"}, // down
		},
	}
	coord := NewCoordinator(group)
	coord.HTTP = srv1.Client()
	coord.Timeout = 200 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := coord.Sign(ctx, []byte("x"), ""); err == nil {
		t.Fatal("expected failure when only 1 of 3 cosigners is reachable and threshold is 2")
	}
}
