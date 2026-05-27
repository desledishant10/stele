//go:build darwin

package keyguard

// MarkNoCoreDump is a no-op on Darwin: macOS has no per-buffer
// "don't include in core" advisory the way Linux's MADV_DONTDUMP
// works. The standard mitigation on macOS is to disable core dumps
// globally (`ulimit -c 0`) for the operator process — operational,
// not code.
//
// Returns nil so callers don't have to special-case Darwin vs Linux.
func MarkNoCoreDump(b []byte) error {
	return nil
}
