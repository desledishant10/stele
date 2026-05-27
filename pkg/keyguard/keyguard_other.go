//go:build !linux && !darwin

package keyguard

// Lock is a no-op on platforms without mlock support (e.g. Windows).
// Returns ErrUnsupported so callers can log "best-effort skipped" but
// continue startup.
func Lock(b []byte) error { return ErrUnsupported }

// Unlock is the matching no-op.
func Unlock(b []byte) error { return nil }

// MarkNoCoreDump is a no-op on platforms without an equivalent
// advisory.
func MarkNoCoreDump(b []byte) error { return ErrUnsupported }
