package hybrid

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	k, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hybrid sign me")
	sig := k.Sign(msg)
	if len(sig) != SignatureSize {
		t.Fatalf("sig size %d, want %d", len(sig), SignatureSize)
	}
	if err := k.Pub.Verify(msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestTamperEd25519HalfDetected(t *testing.T) {
	k, _ := GenerateKey(nil)
	msg := []byte("x")
	sig := k.Sign(msg)
	sig[0] ^= 0xFF // flip a bit in the Ed25519 half
	if err := k.Pub.Verify(msg, sig); err == nil {
		t.Fatal("verify should fail when ed25519 half is tampered")
	}
}

func TestTamperDilithiumHalfDetected(t *testing.T) {
	k, _ := GenerateKey(nil)
	msg := []byte("x")
	sig := k.Sign(msg)
	// Flip a byte in the dilithium half.
	sig[ed25519.SignatureSize+10] ^= 0xFF
	if err := k.Pub.Verify(msg, sig); err == nil {
		t.Fatal("verify should fail when dilithium half is tampered")
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	k, _ := GenerateKey(nil)
	encoded := k.Pub.Bytes()
	if len(encoded) != PubKeySize {
		t.Fatalf("encoded pubkey size %d, want %d", len(encoded), PubKeySize)
	}
	decoded, err := ParsePublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test")
	sig := k.Sign(msg)
	if err := decoded.Verify(msg, sig); err != nil {
		t.Fatalf("verify with decoded pubkey: %v", err)
	}
}

func TestPrivateKeyFilesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "k.priv")
	pub := filepath.Join(dir, "k.pub")
	k, _ := GenerateKey(nil)
	if err := k.WriteFiles(priv, pub); err != nil {
		t.Fatal(err)
	}
	k2, err := LoadPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("after reload")
	sig := k2.Sign(msg)
	if err := k.Pub.Verify(msg, sig); err != nil {
		t.Fatalf("verify after key round-trip: %v", err)
	}
	// Cross-check: the reloaded private's public must match the
	// original's public bytes.
	if string(k.Pub.Bytes()) != string(k2.Pub.Bytes()) {
		t.Fatal("reloaded public key bytes differ from original")
	}
}

func TestSignaturesDiffer(t *testing.T) {
	k, _ := GenerateKey(nil)
	a := k.Sign([]byte("msg a"))
	b := k.Sign([]byte("msg b"))
	// Two different messages must produce two different sigs.
	if string(a) == string(b) {
		t.Fatal("different messages should produce different signatures")
	}
}
