//go:build linux || darwin

package keyguard

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Lock pins the pages backing b in RAM via mlock(2). Returns
// ErrUnsupported on unsupported OSes (handled in keyguard_other.go),
// or a wrapped errno (commonly EPERM when ulimit -l is too low).
//
// b must have len(b) > 0. Zero-length slices are accepted as a no-op
// (no pages to lock).
func Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if err := unix.Mlock(b); err != nil {
		return fmt.Errorf("keyguard: mlock: %w", err)
	}
	return nil
}

// Unlock reverses Lock. Idempotent — a buffer that was never locked
// (or already unlocked) is accepted silently.
func Unlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if err := unix.Munlock(b); err != nil {
		// Common case: the slice was never locked, or the kernel
		// already reclaimed it. Don't propagate as an error; the
		// goal is "memory is no longer locked", which is now true.
		return nil
	}
	return nil
}
