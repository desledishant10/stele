package storage

import (
	"testing"
	"time"
)

// TestDefaultOptions confirms the small-host-safe defaults we ship in v0.1.4.
// If anyone changes these we want the test to fail loudly so the README's
// sizing guidance can be updated alongside.
func TestDefaultOptions(t *testing.T) {
	cfg := defaultConfig()
	if cfg.blockCacheBytes != 64<<20 {
		t.Errorf("blockCacheBytes default changed: got %d, expected 64 MiB", cfg.blockCacheBytes)
	}
	if cfg.indexCacheBytes != 32<<20 {
		t.Errorf("indexCacheBytes default changed: got %d, expected 32 MiB", cfg.indexCacheBytes)
	}
	if cfg.numMemtables != 2 {
		t.Errorf("numMemtables default changed: got %d, expected 2", cfg.numMemtables)
	}
	if cfg.replayTTL != 0 {
		t.Errorf("replayTTL default changed: got %v, expected 0 (off)", cfg.replayTTL)
	}
}

// TestOptionsApply confirms each option setter takes effect.
func TestOptionsApply(t *testing.T) {
	cfg := defaultConfig()
	WithBlockCacheBytes(128 << 20)(&cfg)
	WithIndexCacheBytes(48 << 20)(&cfg)
	WithNumMemtables(4)(&cfg)
	WithReplayTTL(15 * time.Minute)(&cfg)

	if cfg.blockCacheBytes != 128<<20 {
		t.Errorf("WithBlockCacheBytes did not apply: %d", cfg.blockCacheBytes)
	}
	if cfg.indexCacheBytes != 48<<20 {
		t.Errorf("WithIndexCacheBytes did not apply: %d", cfg.indexCacheBytes)
	}
	if cfg.numMemtables != 4 {
		t.Errorf("WithNumMemtables did not apply: %d", cfg.numMemtables)
	}
	if cfg.replayTTL != 15*time.Minute {
		t.Errorf("WithReplayTTL did not apply: %v", cfg.replayTTL)
	}
}

// TestOptionsRejectZero confirms that 0 / no-op values do not clobber the
// existing field. This lets a CLI pass --replay-ttl 0 to mean "leave default".
func TestOptionsRejectZero(t *testing.T) {
	cfg := defaultConfig()
	cfg.blockCacheBytes = 999
	cfg.replayTTL = 5 * time.Second

	WithBlockCacheBytes(0)(&cfg)
	WithReplayTTL(0)(&cfg)

	if cfg.blockCacheBytes != 999 {
		t.Errorf("WithBlockCacheBytes(0) clobbered: got %d", cfg.blockCacheBytes)
	}
	if cfg.replayTTL != 5*time.Second {
		t.Errorf("WithReplayTTL(0) clobbered: got %v", cfg.replayTTL)
	}
}

// TestOpen_WithReplayTTL confirms the Store actually records the
// configured TTL and that CheckAndRecordEnvelope still works under it.
func TestOpen_WithReplayTTL(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir,
		WithBlockCacheBytes(16<<20),
		WithIndexCacheBytes(8<<20),
		WithNumMemtables(2),
		WithReplayTTL(1*time.Hour),
	)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	if st.replayTTL != time.Hour {
		t.Errorf("store.replayTTL not set: %v", st.replayTTL)
	}

	// Submit + re-submit should give a replay error on the second try.
	hash := []byte("0123456789abcdef0123456789abcdef")
	if err := st.CheckAndRecordEnvelope(hash, 1); err != nil {
		t.Fatalf("first CheckAndRecordEnvelope: %v", err)
	}
	if err := st.CheckAndRecordEnvelope(hash, 2); err == nil {
		t.Fatalf("second CheckAndRecordEnvelope should have failed (replay)")
	}
}
