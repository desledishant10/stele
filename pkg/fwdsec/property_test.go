package fwdsec

import (
	"crypto/ed25519"
	"os"
	"testing"

	"pgregory.net/rapid"
)

// mkdir creates a fresh temp dir for a rapid iteration and registers a
// cleanup. rapid.T does not implement testing.T.TempDir, so we roll our own.
func mkdir(t *rapid.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "stele-fwdsec-prop-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// For any sequence of 0..N rotations, the resulting chain must verify
// against its own genesis root and the active key must sign messages
// the chain agrees with.
func TestProp_ChainVerifiesAfterAnyRotations(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nRotations := rapid.IntRange(0, 6).Draw(t, "rotations")

		dir := mkdir(t)
		s, err := NewSigner("origin", dir)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })

		for i := 0; i < nRotations; i++ {
			if _, err := s.Rotate(); err != nil {
				t.Fatalf("Rotate(%d): %v", i, err)
			}
		}

		chain := s.Chain()
		if uint64(len(chain.Certs)) != uint64(nRotations)+1 {
			t.Fatalf("expected %d certs, got %d", nRotations+1, len(chain.Certs))
		}
		if err := chain.VerifyChain(s.RootPublicKey()); err != nil {
			t.Fatalf("chain failed to verify after %d rotations: %v", nRotations, err)
		}
		// Active signature round-trip.
		msg := rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(t, "msg")
		epoch, sig, err := s.Sign(msg)
		if err != nil {
			t.Fatalf("Sign after %d rotations: %v", nRotations, err)
		}
		if epoch != s.ActiveEpoch() {
			t.Fatalf("Sign returned epoch %d, want %d", epoch, s.ActiveEpoch())
		}
		pub := chain.PublicKeyAt(epoch)
		if pub == nil {
			t.Fatalf("PublicKeyAt(%d) returned nil", epoch)
		}
		if !ed25519.Verify(pub, msg, sig) {
			t.Fatalf("active-epoch signature failed to verify")
		}
	})
}

// All public keys across the chain are distinct: rotation generates a
// fresh key per epoch, never a repeat.
func TestProp_ChainKeysDistinct(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nRotations := rapid.IntRange(0, 6).Draw(t, "rotations")
		dir := mkdir(t)
		s, err := NewSigner("origin", dir)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		for i := 0; i < nRotations; i++ {
			if _, err := s.Rotate(); err != nil {
				t.Fatalf("Rotate(%d): %v", i, err)
			}
		}
		chain := s.Chain()
		seen := make(map[string]struct{}, len(chain.Certs))
		for _, c := range chain.Certs {
			if _, dup := seen[string(c.PublicKey)]; dup {
				t.Fatalf("duplicate public key at epoch %d", c.Epoch)
			}
			seen[string(c.PublicKey)] = struct{}{}
		}
	})
}

// VerifyChain with a wrong root MUST fail. The root is the only trust
// anchor for the chain.
func TestProp_ChainRejectsWrongRoot(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nRotations := rapid.IntRange(0, 4).Draw(t, "rotations")
		dir := mkdir(t)
		s, err := NewSigner("origin", dir)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		for i := 0; i < nRotations; i++ {
			if _, err := s.Rotate(); err != nil {
				t.Fatalf("Rotate: %v", err)
			}
		}
		chain := s.Chain()
		realRoot := s.RootPublicKey()
		// Build a forged root that differs by one byte.
		forged := append(ed25519.PublicKey(nil), realRoot...)
		forged[rapid.IntRange(0, len(forged)-1).Draw(t, "byte")] ^= 0xFF
		if err := chain.VerifyChain(forged); err == nil {
			t.Fatalf("chain verified against forged root")
		}
	})
}

// Tampering with any byte of any non-genesis cert's classical signature
// MUST cause VerifyChain to fail.
func TestProp_ChainRejectsTamperedSignature(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Need at least one rotation to have a non-genesis cert.
		nRotations := rapid.IntRange(1, 4).Draw(t, "rotations")
		dir := mkdir(t)
		s, err := NewSigner("origin", dir)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		for i := 0; i < nRotations; i++ {
			if _, err := s.Rotate(); err != nil {
				t.Fatalf("Rotate: %v", err)
			}
		}
		chain := s.Chain()
		victim := rapid.IntRange(1, len(chain.Certs)-1).Draw(t, "victim")
		// Flip a byte in the signature.
		if len(chain.Certs[victim].Signature) == 0 {
			t.Skipf("victim has empty signature (threshold mode not used here)")
		}
		bytePos := rapid.IntRange(0, len(chain.Certs[victim].Signature)-1).Draw(t, "byte")
		chain.Certs[victim].Signature[bytePos] ^= 0xFF
		if err := chain.VerifyChain(s.RootPublicKey()); err == nil {
			t.Fatalf("chain verified after tampering signature in epoch %d", victim)
		}
	})
}

// Tampering with a PublicKey field re-binds the cert to a different key
// AND breaks the chain-link signature check.
func TestProp_ChainRejectsTamperedPublicKey(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nRotations := rapid.IntRange(1, 4).Draw(t, "rotations")
		dir := mkdir(t)
		s, err := NewSigner("origin", dir)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		for i := 0; i < nRotations; i++ {
			if _, err := s.Rotate(); err != nil {
				t.Fatalf("Rotate: %v", err)
			}
		}
		chain := s.Chain()
		victim := rapid.IntRange(0, len(chain.Certs)-1).Draw(t, "victim")
		bytePos := rapid.IntRange(0, len(chain.Certs[victim].PublicKey)-1).Draw(t, "byte")
		chain.Certs[victim].PublicKey[bytePos] ^= 0xFF
		if err := chain.VerifyChain(s.RootPublicKey()); err == nil {
			t.Fatalf("chain verified after tampering PublicKey in epoch %d", victim)
		}
	})
}

// Reordering certs (swap two non-adjacent epochs) must break VerifyChain
// because epochs are sequential and signed-by relationships break.
func TestProp_ChainRejectsReordering(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Need at least 3 certs so we can swap two distinct middle ones.
		nRotations := rapid.IntRange(2, 5).Draw(t, "rotations")
		dir := mkdir(t)
		s, err := NewSigner("origin", dir)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		for i := 0; i < nRotations; i++ {
			if _, err := s.Rotate(); err != nil {
				t.Fatalf("Rotate: %v", err)
			}
		}
		chain := s.Chain()
		// Pick two distinct indices in [0, len-1].
		i := rapid.IntRange(0, len(chain.Certs)-1).Draw(t, "i")
		j := rapid.IntRange(0, len(chain.Certs)-1).Draw(t, "j")
		if i == j {
			return // skip degenerate swap
		}
		chain.Certs[i], chain.Certs[j] = chain.Certs[j], chain.Certs[i]
		if err := chain.VerifyChain(s.RootPublicKey()); err == nil {
			t.Fatalf("chain verified after swapping certs %d <-> %d", i, j)
		}
	})
}
