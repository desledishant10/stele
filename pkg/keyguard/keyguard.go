// Package keyguard provides best-effort OS-level protection for
// sensitive byte buffers (private signing keys, in particular):
//
//   - Lock(b) pins the buffer's pages in RAM so they can't be paged
//     to disk-backed swap. Implementation: mlock(2) on Linux/Darwin.
//
//   - MarkNoCoreDump(b) asks the kernel to exclude the buffer's pages
//     from any core dump the process produces. Implementation:
//     madvise(MADV_DONTDUMP) on Linux; best-effort no-op on Darwin
//     (which lacks an equivalent — only the per-process coredump
//     filter via setrlimit works there).
//
//   - Unlock(b) reverses Lock; safe to call multiple times.
//
// Caveats and honest framing:
//
//   1. Go's GC does not currently relocate heap-allocated slice
//      backing arrays, so the address mlock pins remains the address
//      the slice points at for the slice's lifetime. If Go ever ships
//      a moving GC, this approach silently degrades to "we locked the
//      old address". That risk is documented in fwdsec.
//
//   2. ulimit -l (max locked memory) must be high enough for the
//      process. The Linux default is 64 KiB which is plenty for a
//      handful of keys; CI / containers should raise it (or run as
//      root, or grant CAP_IPC_LOCK).
//
//   3. None of this defends against an attacker who already has
//      root + ptrace on the same host. The goal is to close the
//      paged-out-then-snapshotted-disk and core-dump-leaked-via-tooling
//      vectors. Stronger protection requires an HSM (pkg/hsm).
package keyguard

import "errors"

// ErrUnsupported is returned on platforms where neither mlock nor
// MADV_DONTDUMP is available. Callers should treat this as "best
// effort; continue without".
var ErrUnsupported = errors.New("keyguard: not supported on this OS")
