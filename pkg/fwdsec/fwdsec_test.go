package fwdsec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"

	"github.com/desledishant10/stele/pkg/threshold"
)

func TestGenesisCreatesSelfSignedRoot(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner("origin", dir)
	if err != nil {
		t.Fatal(err)
	}
	chain := s.Chain()
	if len(chain.Certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(chain.Certs))
	}
	if chain.Certs[0].Epoch != 0 {
		t.Fatal("genesis must be epoch 0")
	}
	if err := chain.VerifyChain(s.RootPublicKey()); err != nil {
		t.Fatalf("genesis chain should verify: %v", err)
	}
}

func TestSignAndRotate(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner("origin", dir)
	if err != nil {
		t.Fatal(err)
	}

	// Sign in epoch 0.
	msg := []byte("hello")
	epoch0, sig0, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if epoch0 != 0 {
		t.Fatalf("expected epoch 0, got %d", epoch0)
	}
	pub0 := s.Chain().PublicKeyAt(0)
	if !ed25519.Verify(pub0, msg, sig0) {
		t.Fatal("epoch 0 signature failed to verify")
	}

	// Rotate to epoch 1.
	cert, err := s.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Epoch != 1 {
		t.Fatalf("expected new cert epoch 1, got %d", cert.Epoch)
	}
	if s.ActiveEpoch() != 1 {
		t.Fatal("ActiveEpoch did not advance after Rotate")
	}

	// Sign in epoch 1.
	epoch1, sig1, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if epoch1 != 1 {
		t.Fatalf("expected epoch 1, got %d", epoch1)
	}
	pub1 := s.Chain().PublicKeyAt(1)
	if !ed25519.Verify(pub1, msg, sig1) {
		t.Fatal("epoch 1 signature failed to verify")
	}

	// Old signature still verifies against the old key in the chain.
	if !ed25519.Verify(pub0, msg, sig0) {
		t.Fatal("old signature should still verify against old key")
	}
	// And old key != new key.
	if ed25519.PublicKey(pub0).Equal(pub1) {
		t.Fatal("rotation did not change the public key")
	}
}

func TestChainAcrossSignerReopens(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewSigner("origin", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Rotate(); err != nil {
		t.Fatal(err)
	}
	// Now epoch 2 is active.

	s2, err := NewSigner("origin", dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if s2.ActiveEpoch() != 2 {
		t.Fatalf("expected reopened active epoch 2, got %d", s2.ActiveEpoch())
	}
	if err := s2.Chain().VerifyChain(s2.RootPublicKey()); err != nil {
		t.Fatalf("reopened chain invalid: %v", err)
	}
}

func TestRotatedKeyIsDestroyedOnDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner("origin", dir)
	if err != nil {
		t.Fatal(err)
	}
	preLocator := s.Chain().ActiveLocator
	if preLocator == "" {
		t.Fatal("no active locator after genesis")
	}
	if _, err := os.Stat(preLocator); err != nil {
		t.Fatalf("pre-rotation locator file missing: %v", err)
	}
	if _, err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	postLocator := s.Chain().ActiveLocator
	if postLocator == preLocator {
		t.Fatal("rotation did not change active locator")
	}
	if _, err := os.Stat(preLocator); !os.IsNotExist(err) {
		t.Fatalf("pre-rotation key file still on disk: %v", err)
	}
	if _, err := os.Stat(postLocator); err != nil {
		t.Fatalf("post-rotation key file missing: %v", err)
	}
}

// fakeRotator pretends to be a t-of-N cosigner quorum by holding the
// member keys in-process. Production uses pkg/threshold.Coordinator
// which fans out HTTP to independent stele-cosigner daemons.
type fakeRotator struct {
	priv1 ed25519.PrivateKey
	pub1  ed25519.PublicKey
	priv2 ed25519.PrivateKey
	pub2  ed25519.PublicKey
	g     *threshold.Group
}

func newFakeRotator(t *testing.T, origin string) *fakeRotator {
	t.Helper()
	p1, k1, _ := ed25519.GenerateKey(rand.Reader)
	p2, k2, _ := ed25519.GenerateKey(rand.Reader)
	g := &threshold.Group{
		Version:   1,
		Origin:    origin,
		Threshold: 2,
		CreatedAt: 1,
		Members: []*threshold.Member{
			{ID: "alice", PublicKey: p1},
			{ID: "bob", PublicKey: p2},
		},
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	return &fakeRotator{priv1: k1, pub1: p1, priv2: k2, pub2: p2, g: g}
}

func (f *fakeRotator) Sign(_ context.Context, msg []byte, _ string) ([]*threshold.MemberSig, error) {
	return []*threshold.MemberSig{
		{MemberID: "alice", PublicKey: f.pub1, Signature: ed25519.Sign(f.priv1, msg)},
		{MemberID: "bob",   PublicKey: f.pub2, Signature: ed25519.Sign(f.priv2, msg)},
	}, nil
}

func (f *fakeRotator) Group() *threshold.Group { return f.g }

func TestThresholdRotationCertProducedAndVerified(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner("test.local/log", dir)
	if err != nil {
		t.Fatal(err)
	}
	rotator := newFakeRotator(t, "test.local/log")
	s.UseThresholdRotation(rotator)

	cert, err := s.Rotate()
	if err != nil {
		t.Fatalf("threshold-mode Rotate: %v", err)
	}
	if cert.Epoch != 1 {
		t.Fatalf("expected new epoch 1, got %d", cert.Epoch)
	}
	if len(cert.Signature) != 0 {
		t.Fatal("threshold cert should leave the single-sig Signature field empty")
	}
	if len(cert.MemberSigs) < 2 {
		t.Fatalf("threshold cert should carry 2 member sigs, got %d", len(cert.MemberSigs))
	}
	// The cert must verify only via VerifyWithGroup.
	if err := cert.Verify(); err == nil {
		t.Fatal("bare Verify should refuse a threshold-mode cert")
	}
	if err := cert.VerifyWithGroup(rotator.Group()); err != nil {
		t.Fatalf("VerifyWithGroup: %v", err)
	}
	// A chain walk that supplies the group must accept it.
	if err := s.Chain().VerifyChainWithGroup(s.RootPublicKey(), rotator.Group()); err != nil {
		t.Fatalf("VerifyChainWithGroup: %v", err)
	}
	// Bare VerifyChain refuses (correctly — caller didn't supply trust anchor for the group).
	if err := s.Chain().VerifyChain(s.RootPublicKey()); err == nil {
		t.Fatal("bare VerifyChain should refuse a chain containing threshold-mode certs")
	}
}

func TestThresholdRotationCertBelowQuorumRejected(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewSigner("test.local/log", dir)

	// A rotator that returns ONE sig when the threshold is 2.
	r := newFakeRotator(t, "test.local/log")
	below := &belowQuorumRotator{base: r}
	s.UseThresholdRotation(below)

	cert, err := s.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyWithGroup(r.Group()); err == nil {
		t.Fatal("cert with only 1 of 2 required member sigs should fail verification")
	}
}

type belowQuorumRotator struct{ base *fakeRotator }

func (b *belowQuorumRotator) Sign(ctx context.Context, msg []byte, label string) ([]*threshold.MemberSig, error) {
	sigs, err := b.base.Sign(ctx, msg, label)
	if err != nil { return nil, err }
	return sigs[:1], nil
}

func (b *belowQuorumRotator) Group() *threshold.Group { return b.base.Group() }

func TestForgedCertRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSigner("origin", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	chain := s.Chain()

	// Attacker tampers with the public key of epoch 1.
	chain.Certs[1].PublicKey = make([]byte, ed25519.PublicKeySize)
	_, _ = rand.Read(chain.Certs[1].PublicKey)

	if err := chain.VerifyChain(s.RootPublicKey()); err == nil {
		t.Fatal("VerifyChain should reject tampered cert")
	}
}
