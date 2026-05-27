//go:build linux

package keyguard

import "golang.org/x/sys/unix"

// MarkNoCoreDump asks the kernel to exclude b's pages from any core
// dump via madvise(MADV_DONTDUMP). On Linux this is honoured by the
// kernel's coredump writer.
//
// Best-effort: failures are returned so the caller can log them, but
// callers should NOT fail-closed on this — the worst case is "key
// might appear in a core dump", same as the pre-keyguard baseline.
func MarkNoCoreDump(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Madvise(b, unix.MADV_DONTDUMP)
}
