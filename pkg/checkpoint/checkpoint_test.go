package checkpoint

import (
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/desledishant10/stele/pkg/fwdsec"
)

func newTestSigner(t *testing.T, origin string) *Signer {
	t.Helper()
	fws, err := fwdsec.NewSigner(origin, filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	return NewSigner(fws)
}

func TestSignAndVerify(t *testing.T) {
	s := newTestSigner(t, "example.com/log")
	root := make([]byte, 32)
	head := make([]byte, 32)
	_, _ = rand.Read(root)
	_, _ = rand.Read(head)
	c, err := s.Sign(42, root, head, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(c, s.Chain(), s.Chain().RootPublicKey(), nil); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyFailsOnTamperedSize(t *testing.T) {
	s := newTestSigner(t, "origin")
	c, _ := s.Sign(1, make([]byte, 32), make([]byte, 32), nil)
	c.Size = 2
	if err := Verify(c, s.Chain(), s.Chain().RootPublicKey(), nil); err == nil {
		t.Fatal("verify should fail after size tamper")
	}
}

func TestVerifyFailsOnTamperedRoot(t *testing.T) {
	s := newTestSigner(t, "origin")
	c, _ := s.Sign(1, make([]byte, 32), make([]byte, 32), nil)
	c.RootHash[0] ^= 0xFF
	if err := Verify(c, s.Chain(), s.Chain().RootPublicKey(), nil); err == nil {
		t.Fatal("verify should fail after root tamper")
	}
}

func TestVerifyFailsWithWrongRoot(t *testing.T) {
	s := newTestSigner(t, "origin")
	other := newTestSigner(t, "origin")
	c, _ := s.Sign(1, make([]byte, 32), make([]byte, 32), nil)
	if err := Verify(c, other.Chain(), other.Chain().RootPublicKey(), nil); err == nil {
		t.Fatal("verify should fail with different signer's chain")
	}
}

func TestVerifyAfterRotation(t *testing.T) {
	s := newTestSigner(t, "origin")
	c0, _ := s.Sign(1, make([]byte, 32), make([]byte, 32), nil)
	if _, err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	c1, _ := s.Sign(2, make([]byte, 32), make([]byte, 32), nil)
	chain := s.Chain()
	root := chain.RootPublicKey()
	if err := Verify(c0, chain, root, nil); err != nil {
		t.Fatalf("pre-rotation checkpoint should still verify: %v", err)
	}
	if err := Verify(c1, chain, root, nil); err != nil {
		t.Fatalf("post-rotation checkpoint should verify: %v", err)
	}
	if c0.EpochIdx == c1.EpochIdx {
		t.Fatal("rotation did not advance epoch")
	}
}

func TestVerifyFailsOnWrongOrigin(t *testing.T) {
	s := newTestSigner(t, "origin-a")
	c, _ := s.Sign(3, make([]byte, 32), make([]byte, 32), nil)
	c.Origin = "origin-b"
	if err := Verify(c, s.Chain(), s.Chain().RootPublicKey(), nil); err == nil {
		t.Fatal("verify should fail after origin tamper")
	}
}
