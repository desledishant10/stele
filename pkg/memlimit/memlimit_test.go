package memlimit

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestApply_RespectsExistingEnvVar(t *testing.T) {
	prev := os.Getenv("GOMEMLIMIT")
	if err := os.Setenv("GOMEMLIMIT", "1GiB"); err != nil {
		t.Fatal(err)
	}
	defer os.Setenv("GOMEMLIMIT", prev)

	limit, msg := Apply(0.70)
	if limit != 0 {
		t.Errorf("expected limit=0 when GOMEMLIMIT already set, got %d", limit)
	}
	if !strings.Contains(msg, "already set") {
		t.Errorf("expected message to mention env var; got %q", msg)
	}
}

func TestApply_RejectsBadFractions(t *testing.T) {
	// Clear env var for this test.
	prev := os.Getenv("GOMEMLIMIT")
	os.Unsetenv("GOMEMLIMIT")
	defer os.Setenv("GOMEMLIMIT", prev)

	cases := []float64{0, -1, 1.5, 100}
	for _, f := range cases {
		limit, msg := Apply(f)
		if limit != 0 {
			t.Errorf("fraction %g: expected limit=0, got %d (msg=%q)", f, limit, msg)
		}
	}
}

func TestApply_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only: /proc/meminfo not available")
	}
	prev := os.Getenv("GOMEMLIMIT")
	os.Unsetenv("GOMEMLIMIT")
	defer os.Setenv("GOMEMLIMIT", prev)

	limit, msg := Apply(0.50)
	if limit == 0 {
		t.Fatalf("expected positive limit on Linux; got 0 (msg=%q)", msg)
	}
	if !strings.Contains(msg, "auto-set") {
		t.Errorf("expected 'auto-set' message; got %q", msg)
	}
	// Restore something sane so we don't leak the constraint.
	ApplyExact(uint64(1) << 40)
}

func TestApplyExact_ZeroIsNoop(t *testing.T) {
	msg := ApplyExact(0)
	if !strings.Contains(msg, "not setting") {
		t.Errorf("expected explicit no-op message; got %q", msg)
	}
}

func TestApplyExact_Positive(t *testing.T) {
	msg := ApplyExact(uint64(1) << 30) // 1 GiB
	if !strings.Contains(msg, "1024 MiB") {
		t.Errorf("expected 1024 MiB in message; got %q", msg)
	}
	// Restore to no-limit so subsequent tests aren't constrained.
	ApplyExact(uint64(1) << 40)
}
