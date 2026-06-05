// Package memlimit auto-configures Go's runtime memory limit
// (GOMEMLIMIT) based on the detected host RAM. This is the main
// preventative measure against burst-OOM under sustained load,
// per the v0.1.4 soak finding (issue #8).
//
// Why this exists: Go's GC defaults to a 100% growth target between
// collections (GOGC=100). Under bursty allocation that means the
// heap can momentarily reach 2x steady-state before the next GC,
// which on a moderately-sized host is enough to cross the OS OOM
// threshold even when the leak-style fixes from v0.1.4 work.
// Setting GOMEMLIMIT forces the GC to pace itself against a hard
// ceiling well below the OS limit, smoothing the bursts.
//
// The package does nothing if the operator has set GOMEMLIMIT
// out-of-band (via env var) or passed a non-zero override; we
// never override an explicit choice.
package memlimit

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// Detect reads the host's physical memory in bytes. On Linux this
// uses /proc/meminfo's MemTotal field. On macOS and BSD it falls
// back to runtime detection (which is sufficient for tests but
// returns 0 on the production targets, so callers should treat 0
// as "could not detect").
func Detect() (uint64, error) {
	if v, err := detectLinux(); err == nil {
		return v, nil
	}
	return 0, errors.New("memlimit: could not detect host memory; pass --mem-limit-bytes manually")
}

// detectLinux reads /proc/meminfo and returns MemTotal in bytes.
func detectLinux() (uint64, error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return 0, fmt.Errorf("memlimit: unexpected MemTotal line: %q", line)
		}
		kib, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("memlimit: parsing MemTotal: %w", err)
		}
		// /proc/meminfo's MemTotal is in KiB.
		return kib * 1024, nil
	}
	return 0, errors.New("memlimit: MemTotal not found in /proc/meminfo")
}

// Apply sets Go's runtime memory limit to fraction * detected host
// memory, but only when:
//   - The GOMEMLIMIT environment variable is unset (operator hasn't
//     set one explicitly), AND
//   - fraction > 0 (caller wants auto-config), AND
//   - Detection succeeded (we know the host RAM)
//
// Returns the limit actually applied in bytes (0 if no action was
// taken) and a human-readable explanation suitable for logging.
//
// Typical call from steled startup:
//
//	limit, msg := memlimit.Apply(0.70)
//	log.Info("memory limit configured", "msg", msg, "bytes", limit)
func Apply(fraction float64) (uint64, string) {
	if v := os.Getenv("GOMEMLIMIT"); v != "" {
		return 0, fmt.Sprintf("GOMEMLIMIT already set to %q; not overriding", v)
	}
	if fraction <= 0 {
		return 0, "fraction <= 0; not setting memory limit"
	}
	if fraction > 1 {
		return 0, fmt.Sprintf("fraction %.2f > 1; refusing", fraction)
	}
	host, err := Detect()
	if err != nil {
		return 0, fmt.Sprintf("host RAM detection failed: %v; not setting limit", err)
	}
	if host == 0 {
		return 0, "host RAM detected as 0; not setting limit"
	}
	limit := int64(float64(host) * fraction)
	if limit <= 0 {
		return 0, "computed limit was non-positive; not setting"
	}
	prev := debug.SetMemoryLimit(limit)
	return uint64(limit), fmt.Sprintf(
		"GOMEMLIMIT auto-set to %d MiB (%.0f%% of detected %d MiB host RAM; previous limit %d)",
		limit/(1<<20), fraction*100, host/(1<<20), prev,
	)
}

// ApplyExact sets the memory limit to an exact byte value, ignoring
// host detection and the GOMEMLIMIT env var. Use when the operator
// has passed --mem-limit-bytes explicitly.
func ApplyExact(bytes uint64) string {
	if bytes == 0 {
		return "0 bytes; not setting memory limit"
	}
	prev := debug.SetMemoryLimit(int64(bytes))
	return fmt.Sprintf(
		"GOMEMLIMIT set to %d MiB (explicit; previous %d)",
		bytes/(1<<20), prev,
	)
}
