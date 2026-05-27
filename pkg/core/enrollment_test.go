package core

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/storage"
)

// enrollRig builds a Log with the supplied RequireEnrollment flag.
// Returns the Log and a SoftwareAttestor whose keys the tests use to
// mint envelopes.
func enrollRig(t *testing.T, require bool) (*Log, *attest.SoftwareAttestor) {
	t.Helper()
	dir := t.TempDir()
	st, err := storage.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fws, err := fwdsec.NewSigner("enroll.local/log", filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	sink, err := anchor.NewFileSink(filepath.Join(dir, "anchor.log"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(context.Background(), Options{
		Store:             st,
		Signer:            checkpoint.NewSigner(fws),
		Sinks:             []anchor.Sink{sink},
		RequireEnrollment: require,
	})
	if err != nil {
		t.Fatal(err)
	}
	prod, err := attest.NewSoftwareAttestor("prod-1")
	if err != nil {
		t.Fatal(err)
	}
	return l, prod
}

// TestIssueEnrollment_ProducesValidSignature confirms that the signed
// Producer record verifies against the operator chain's pubkey.
func TestIssueEnrollment_ProducesValidSignature(t *testing.T) {
	l, prod := enrollRig(t, false)
	rec, err := l.IssueEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
		Scope:     "logs:audit",
		Validity:  1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueEnrollment: %v", err)
	}
	if !rec.HasEnrollment() {
		t.Fatal("issued producer should report HasEnrollment() true")
	}
	if rec.IsExpired(time.Now()) {
		t.Fatal("freshly-issued enrollment must not be expired")
	}
	chain := l.signer.Chain()
	if err := rec.VerifyEnrollment(chain.PublicKeyAt, chain.QuantumPublicKeyAt); err != nil {
		t.Fatalf("verify enrollment: %v", err)
	}
}

// TestIssueEnrollment_TamperBreaksSignature confirms that mutating any
// enrollment-relevant field after issuance invalidates the signature.
func TestIssueEnrollment_TamperBreaksSignature(t *testing.T) {
	l, prod := enrollRig(t, false)
	rec, err := l.IssueEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
		Scope:     "logs:audit",
	})
	if err != nil {
		t.Fatal(err)
	}
	chain := l.signer.Chain()

	// Mutate Scope post-signing.
	rec.Scope = "logs:admin"
	err = rec.VerifyEnrollment(chain.PublicKeyAt, chain.QuantumPublicKeyAt)
	if err == nil {
		t.Fatal("verify accepted tampered Scope")
	}
}

// TestRequireEnrollment_RefusesAppendForLegacyProducer: with
// RequireEnrollment on, a legacy RegisterProducer record (no
// Signature) must be refused by Append.
func TestRequireEnrollment_RefusesAppendForLegacyProducer(t *testing.T) {
	l, prod := enrollRig(t, true)
	// Use the legacy path — no enrollment signature.
	if err := l.RegisterProducer(&storage.Producer{
		ID:              "prod-1",
		PublicKey:       prod.PublicKey(),
		AttestationType: string(attest.TypeSoftware),
	}); err != nil {
		t.Fatal(err)
	}
	env, err := prod.Sign("src", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.Append(env, false)
	if err == nil {
		t.Fatal("Append should have refused: legacy producer in enrollment-required mode")
	}
	if !strings.Contains(err.Error(), "no enrollment") {
		t.Fatalf("error should mention missing enrollment, got: %v", err)
	}
}

// TestRequireEnrollment_AcceptsAppendForEnrolledProducer: with
// RequireEnrollment on, a producer issued via IssueEnrollment must be
// accepted for Append.
func TestRequireEnrollment_AcceptsAppendForEnrolledProducer(t *testing.T) {
	l, prod := enrollRig(t, true)
	if _, err := l.IssueEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
		Scope:     "logs:audit",
		Validity:  1 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	env, err := prod.Sign("src", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := l.Append(env, false)
	if err != nil {
		t.Fatalf("Append should have succeeded for enrolled producer: %v", err)
	}
	if entry.Index != 0 {
		t.Fatalf("expected first append at index 0, got %d", entry.Index)
	}
}

// TestRequireEnrollment_ExpiredEnrollmentRefused: when an enrollment's
// ExpiresAt is in the past, Append refuses.
func TestRequireEnrollment_ExpiredEnrollmentRefused(t *testing.T) {
	l, prod := enrollRig(t, true)
	rec, err := l.IssueEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
		Validity:  1 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Force-expire by writing the record back with ExpiresAt in the
	// past. Real-world this happens via clock advancing past
	// ExpiresAt; we fake it by mutating the stored record. The
	// signature is over the canonical fields including ExpiresAt, so
	// a real attacker can't do this without breaking the sig — this
	// test only checks that the time check fires, not that the time
	// check is the only barrier.
	rec.ExpiresAt = time.Now().Add(-1 * time.Hour).UnixNano()
	if err := l.store.RegisterProducer(rec); err != nil {
		t.Fatal(err)
	}
	env, err := prod.Sign("src", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.Append(env, false)
	if err == nil {
		t.Fatal("Append should refuse expired enrollment")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error should mention expiry, got: %v", err)
	}
}

// TestRequireEnrollment_TamperedEnrollmentRefused: an attacker mutates
// the stored Producer's Scope post-signing. Verify fails; Append refuses.
func TestRequireEnrollment_TamperedEnrollmentRefused(t *testing.T) {
	l, prod := enrollRig(t, true)
	rec, err := l.IssueEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
		Scope:     "logs:audit",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec.Scope = "logs:admin" // post-signing tamper
	if err := l.store.RegisterProducer(rec); err != nil {
		t.Fatal(err)
	}
	env, err := prod.Sign("src", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.Append(env, false)
	if err == nil {
		t.Fatal("Append should refuse tampered enrollment")
	}
	if !strings.Contains(err.Error(), "enrollment invalid") {
		t.Fatalf("error should mention invalid enrollment, got: %v", err)
	}
}

// TestRequireEnrollment_RevokedProducerRefused: revoked producers are
// refused regardless of enrollment validity. (Already covered by
// non-enrollment-mode tests too; here we make sure the order of
// checks doesn't accidentally accept a revoked-but-signed record.)
func TestRequireEnrollment_RevokedProducerRefused(t *testing.T) {
	l, prod := enrollRig(t, true)
	if _, err := l.IssueEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.RevokeProducer("prod-1", "key compromised"); err != nil {
		t.Fatal(err)
	}
	env, err := prod.Sign("src", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.Append(env, false)
	if err == nil {
		t.Fatal("Append should refuse revoked producer")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("error should mention revocation, got: %v", err)
	}
}

// TestLegacyModeStillWorks: without RequireEnrollment, the old
// RegisterProducer path is unaffected. Important for backwards
// compatibility during migration.
func TestLegacyModeStillWorks(t *testing.T) {
	l, prod := enrollRig(t, false)
	if err := l.RegisterProducer(&storage.Producer{
		ID:              "prod-1",
		PublicKey:       prod.PublicKey(),
		AttestationType: string(attest.TypeSoftware),
	}); err != nil {
		t.Fatal(err)
	}
	env, err := prod.Sign("src", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(env, false); err != nil {
		t.Fatalf("legacy mode Append: %v", err)
	}
}

// TestEnrollmentEpochBindingRejectsForeignChain: a Producer record
// claiming to be signed by epoch 0 of operator A is presented to
// operator B (different chain). Verify must fail because the pubkey
// at B's epoch 0 is different.
func TestEnrollmentEpochBindingRejectsForeignChain(t *testing.T) {
	lA, prod := enrollRig(t, false)
	recA, err := lA.IssueEnrollment(EnrollmentRequest{
		ID:        "prod-1",
		PublicKey: prod.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// New, totally-independent operator B.
	lB, _ := enrollRig(t, false)
	chainB := lB.signer.Chain()
	if err := recA.VerifyEnrollment(chainB.PublicKeyAt, chainB.QuantumPublicKeyAt); err == nil {
		t.Fatal("verify should reject enrollment signed by a different operator chain")
	}
}
