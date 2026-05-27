package keyguard

import (
	"errors"
	"runtime"
	"testing"
)

// TestLockUnlockRoundtrip exercises the happy path on unix; on other
// OSes the call is expected to return ErrUnsupported and we accept
// that as a pass (the no-op is the contract).
func TestLockUnlockRoundtrip(t *testing.T) {
	buf := make([]byte, 4096) // page-aligned-ish; mlock works at page granularity
	err := Lock(buf)
	switch {
	case err == nil:
		// Locked. Confirm Unlock is happy.
		if err := Unlock(buf); err != nil {
			t.Fatalf("Unlock after Lock failed: %v", err)
		}
	case errors.Is(err, ErrUnsupported):
		if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
			t.Fatalf("Lock unexpectedly returned ErrUnsupported on %s", runtime.GOOS)
		}
	default:
		// EPERM is common in containers without CAP_IPC_LOCK + low
		// ulimit -l. Don't fail the test for that — Lock did its
		// best.
		t.Logf("Lock returned non-fatal error on %s: %v (likely ulimit -l)", runtime.GOOS, err)
	}
}

// TestUnlockIdempotent confirms Unlock on a never-locked buffer is
// silent — important so callers can defer Unlock unconditionally
// without checking whether Lock succeeded.
func TestUnlockIdempotent(t *testing.T) {
	buf := make([]byte, 32)
	if err := Unlock(buf); err != nil {
		t.Fatalf("Unlock on never-locked buffer should be silent: %v", err)
	}
	if err := Unlock(buf); err != nil {
		t.Fatalf("second Unlock should remain silent: %v", err)
	}
}

func TestLockEmptyBuffer(t *testing.T) {
	if err := Lock(nil); err != nil {
		t.Fatalf("Lock(nil) should be a no-op: %v", err)
	}
	if err := Lock([]byte{}); err != nil {
		t.Fatalf("Lock([]byte{}) should be a no-op: %v", err)
	}
}

func TestMarkNoCoreDump(t *testing.T) {
	buf := make([]byte, 4096)
	// Should not error on Linux/Darwin; ErrUnsupported on others.
	err := MarkNoCoreDump(buf)
	if err != nil && !errors.Is(err, ErrUnsupported) {
		// On Linux this would be a real failure (madvise rarely
		// errors on a valid buffer); on Darwin it's always nil.
		if runtime.GOOS == "linux" {
			t.Fatalf("MarkNoCoreDump on linux returned: %v", err)
		}
	}
}
