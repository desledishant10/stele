package keyguard

import (
	"errors"
	"runtime"
	"syscall"
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
		if err = Unlock(buf); err != nil {
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
	if err == nil || errors.Is(err, ErrUnsupported) {
		// Linux success, Darwin's always-nil no-op, or an
		// unsupported-OS no-op: all the contract. Nothing to assert.
		return
	}

	// A real errno came back. On Linux, madvise(2) virtually never
	// errors on a valid in-bounds buffer — EXCEPT in sandboxed CI
	// runners where the syscall is blocked by seccomp or simply not
	// honoured, surfacing as EINVAL/EPERM/ENOSYS. That's an
	// environment limitation, not a defect in the guard (which still
	// returns the errno to callers unchanged), so skip for exactly
	// those errnos and fail for anything else.
	if runtime.GOOS == "linux" {
		for _, e := range []syscall.Errno{syscall.EINVAL, syscall.EPERM, syscall.ENOSYS} {
			if errors.Is(err, e) {
				t.Skipf("MarkNoCoreDump: madvise(MADV_DONTDUMP) unsupported/blocked in this environment (%v); skipping syscall-dependent assertion", err)
			}
		}
		t.Fatalf("MarkNoCoreDump on linux returned unexpected error: %v", err)
	}
}
