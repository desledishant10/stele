package watchdog

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// mockRotator counts how many times Rotate was called.
type mockRotator struct {
	calls atomic.Int64
}

func (m *mockRotator) Rotate() error {
	m.calls.Add(1)
	return nil
}

func TestScheduledRotation(t *testing.T) {
	m := &mockRotator{}
	wd, err := Start(context.Background(), m, Config{
		Interval:    50 * time.Millisecond,
		MinDebounce: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wd.Stop()

	time.Sleep(180 * time.Millisecond)
	calls := m.calls.Load()
	if calls < 2 {
		t.Fatalf("expected >= 2 scheduled rotations, got %d", calls)
	}
}

func TestKeyDirTamperRotation(t *testing.T) {
	dir := t.TempDir()
	// Create the file before the watcher starts so the watcher sees a
	// real Write event when we touch it later.
	path := filepath.Join(dir, "chain.json")
	if err := os.WriteFile(path, []byte("initial"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := &mockRotator{}
	wd, err := Start(context.Background(), m, Config{
		KeyDir:      dir,
		MinDebounce: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wd.Stop()

	// Give the fsnotify goroutine time to subscribe.
	time.Sleep(80 * time.Millisecond)

	// The startup "skip 2" eats the first two writes; do three writes
	// total so the last one definitely fires.
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(path, []byte("changed"), 0o644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	if m.calls.Load() < 1 {
		t.Fatal("expected at least 1 rotation from key-dir tamper")
	}
}

func TestDebounce(t *testing.T) {
	m := &mockRotator{}
	wd, err := Start(context.Background(), m, Config{
		Interval:    10 * time.Millisecond,
		MinDebounce: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wd.Stop()

	// Many timer ticks but the debounce should clamp the rotations.
	time.Sleep(700 * time.Millisecond)
	calls := m.calls.Load()
	if calls > 5 {
		t.Fatalf("debounce should limit rotations; got %d in 700ms with 200ms debounce", calls)
	}
}

func TestRateSurgeTriggersRotation(t *testing.T) {
	m := &mockRotator{}
	wd, err := Start(context.Background(), m, Config{
		EnableRateMonitor: true,
		RateWindow:        300 * time.Millisecond, // 10ms buckets
		MinDebounce:       1 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wd.Stop()

	// Set a low baseline.
	for i := 0; i < 5; i++ {
		wd.ObserveAppend()
		time.Sleep(30 * time.Millisecond)
	}

	// Wait through warmup.
	time.Sleep(350 * time.Millisecond)

	// Now slam it.
	for i := 0; i < 500; i++ {
		wd.ObserveAppend()
	}
	time.Sleep(50 * time.Millisecond)

	// rateMonitor checks every bucketDur; give it some chances.
	for tries := 0; tries < 30 && m.calls.Load() == 0; tries++ {
		time.Sleep(20 * time.Millisecond)
	}
	if m.calls.Load() == 0 {
		t.Fatal("expected rate surge to trigger rotation")
	}
}
