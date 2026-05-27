package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/storage"
)

// TestChallenge_HappyPath: a producer signs the challenge with the
// real private key. Confirm succeeds; the resulting record carries
// both operator and producer signatures.
func TestChallenge_HappyPath(t *testing.T) {
	l, prod := enrollRig(t, false)
	begin, err := l.BeginEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
		Scope:     "logs:audit",
		Validity:  1 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if begin.ChallengeID == "" || len(begin.ChallengeBytes) == 0 {
		t.Fatal("BeginEnrollment should return a non-empty challenge")
	}

	classicalSig, qSig, err := prod.SignChallenge(begin.ChallengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(qSig) != 0 {
		t.Fatalf("classical attestor should not produce a quantum sig (got %d bytes)", len(qSig))
	}

	rec, err := l.ConfirmEnrollment(begin.ChallengeID, classicalSig, qSig)
	if err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}
	if !rec.HasEnrollment() {
		t.Fatal("rec must have operator enrollment signature")
	}
	if !rec.HasChallengeResponse() {
		t.Fatal("rec must have producer challenge response")
	}
	if err := rec.VerifyConsent(); err != nil {
		t.Fatalf("VerifyConsent: %v", err)
	}
	chain := l.signer.Chain()
	if err := rec.VerifyEnrollment(chain.PublicKeyAt, chain.QuantumPublicKeyAt); err != nil {
		t.Fatalf("VerifyEnrollment: %v", err)
	}
}

// TestChallenge_WrongKeyRejected: producer signs with a DIFFERENT
// private key than the one claimed in BeginEnrollment. The challenge
// signature won't verify against the registered pubkey.
func TestChallenge_WrongKeyRejected(t *testing.T) {
	l, prod := enrollRig(t, false)
	// Begin claims prod's pubkey.
	begin, err := l.BeginEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Sign with an UNRELATED key.
	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badSig := ed25519.Sign(attackerPriv, begin.ChallengeBytes)
	_, err = l.ConfirmEnrollment(begin.ChallengeID, badSig, nil)
	if err == nil {
		t.Fatal("ConfirmEnrollment should refuse a sig from the wrong key")
	}
	if !strings.Contains(err.Error(), "consent") {
		t.Fatalf("error should mention consent, got: %v", err)
	}
}

// TestChallenge_TamperedChallengeBytesRejected: producer signs a
// modified version of the challenge bytes (e.g. trying to upgrade
// their own scope). The signature is valid against the producer's
// pubkey but doesn't verify against the ORIGINAL challenge stored
// server-side, so Confirm rejects.
func TestChallenge_TamperedChallengeBytesRejected(t *testing.T) {
	l, prod := enrollRig(t, false)
	begin, err := l.BeginEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
		Scope:     "logs:audit",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Producer signs a modified version of the challenge — they're
	// trying to commit to different terms than the server issued.
	tampered := append([]byte(nil), begin.ChallengeBytes...)
	tampered[5] ^= 0xFF
	badSig, _, err := prod.SignChallenge(tampered)
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.ConfirmEnrollment(begin.ChallengeID, badSig, nil)
	if err == nil {
		t.Fatal("ConfirmEnrollment should refuse a sig over tampered bytes")
	}
}

// TestChallenge_UnknownChallengeIDRejected: confirm with an ID the
// server never issued.
func TestChallenge_UnknownChallengeIDRejected(t *testing.T) {
	l, _ := enrollRig(t, false)
	_, err := l.ConfirmEnrollment("deadbeef", []byte{0}, nil)
	if err == nil {
		t.Fatal("ConfirmEnrollment with unknown ID should fail")
	}
	if !strings.Contains(err.Error(), "unknown or expired") {
		t.Fatalf("error should mention unknown, got: %v", err)
	}
}

// TestChallenge_ReplayRejected: a successful confirm consumes the
// pending state. A second confirm with the same challenge_id +
// signature must fail.
func TestChallenge_ReplayRejected(t *testing.T) {
	l, prod := enrollRig(t, false)
	begin, _ := l.BeginEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
	})
	sig, _, _ := prod.SignChallenge(begin.ChallengeBytes)

	if _, err := l.ConfirmEnrollment(begin.ChallengeID, sig, nil); err != nil {
		t.Fatalf("first confirm should succeed: %v", err)
	}
	if _, err := l.ConfirmEnrollment(begin.ChallengeID, sig, nil); err == nil {
		t.Fatal("second confirm with same challenge_id should be refused (single-use)")
	}
}

// TestChallenge_ExpiredRejected: the pending state has a deadline.
// We force-expire it and verify confirm fails.
func TestChallenge_ExpiredRejected(t *testing.T) {
	l, prod := enrollRig(t, false)
	begin, _ := l.BeginEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
	})
	// Force-expire by reaching into the map and rewinding expiresAt.
	l.pendingMu.Lock()
	l.pending[begin.ChallengeID].expiresAt = time.Now().Add(-1 * time.Second)
	l.pendingMu.Unlock()

	sig, _, _ := prod.SignChallenge(begin.ChallengeBytes)
	_, err := l.ConfirmEnrollment(begin.ChallengeID, sig, nil)
	if err == nil {
		t.Fatal("expired challenge should be refused")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error should mention expiry, got: %v", err)
	}
}

// TestChallenge_HybridRequiresQuantumSig: producer registered with a
// QuantumPublicKey but submits only a classical signature. Reject —
// otherwise this is a downgrade attack at enrollment time.
func TestChallenge_HybridRequiresQuantumSig(t *testing.T) {
	l, _ := enrollRig(t, false)
	hyb, err := attest.NewHybridSoftwareAttestor("hyb-prod")
	if err != nil {
		t.Fatal(err)
	}
	begin, err := l.BeginEnrollment(EnrollmentRequest{
		ID:               "hyb-prod",
		PublicKey:        hyb.PublicKey(),
		QuantumPublicKey: hyb.QuantumPublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	classical, _, _ := hyb.SignChallenge(begin.ChallengeBytes)
	// Pass nil for the quantum sig.
	_, err = l.ConfirmEnrollment(begin.ChallengeID, classical, nil)
	if err == nil {
		t.Fatal("hybrid producer should require quantum signature")
	}
	if !strings.Contains(err.Error(), "quantum") {
		t.Fatalf("error should mention quantum, got: %v", err)
	}
}

// TestChallenge_HybridHappyPath: hybrid producer signs with both
// keys; Confirm succeeds and the record carries both challenge sigs.
func TestChallenge_HybridHappyPath(t *testing.T) {
	l, _ := enrollRig(t, false)
	hyb, err := attest.NewHybridSoftwareAttestor("hyb-prod")
	if err != nil {
		t.Fatal(err)
	}
	begin, _ := l.BeginEnrollment(EnrollmentRequest{
		ID:               "hyb-prod",
		PublicKey:        hyb.PublicKey(),
		QuantumPublicKey: hyb.QuantumPublicKey(),
	})
	classical, qSig, err := hyb.SignChallenge(begin.ChallengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(qSig) == 0 {
		t.Fatal("hybrid attestor should produce a quantum sig")
	}
	rec, err := l.ConfirmEnrollment(begin.ChallengeID, classical, qSig)
	if err != nil {
		t.Fatalf("hybrid Confirm: %v", err)
	}
	if len(rec.QuantumChallengeSignature) == 0 {
		t.Fatal("rec must carry quantum challenge sig")
	}
	if err := rec.VerifyConsent(); err != nil {
		t.Fatalf("VerifyConsent hybrid: %v", err)
	}
}

// TestChallenge_AppendWorksAfterChallengeEnrollment: end-to-end, the
// stronger flow still satisfies RequireEnrollment-mode Append.
func TestChallenge_AppendWorksAfterChallengeEnrollment(t *testing.T) {
	l, prod := enrollRig(t, true) // require-enrollment ON
	begin, _ := l.BeginEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
		Validity:  1 * time.Hour,
	})
	sig, _, _ := prod.SignChallenge(begin.ChallengeBytes)
	if _, err := l.ConfirmEnrollment(begin.ChallengeID, sig, nil); err != nil {
		t.Fatal(err)
	}
	env, err := prod.Sign("src", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(env, false); err != nil {
		t.Fatalf("Append after challenge-response enrollment: %v", err)
	}
}

// silence "unused storage" when only some tests need it
var _ = storage.Producer{}