// Package watchdog drives event-driven and time-driven operator key
// rotation. It exists to shrink the "stolen key, undetected forgery"
// window from "until manual rotation" to "until the next watchdog tick
// or trigger" — usually seconds.
//
// Triggers supported in v1:
//
//  1. Scheduled rotation — fires every Interval (e.g. 1 hour).
//
//  2. KeyDir tamper — any modification to files under the operator's
//     keys directory (chain.json, root.pub, on-disk key files in
//     FileKeyStore mode) immediately rotates. If an attacker is
//     poking at our key material, the act of poking destroys their
//     opportunity to use what they stole.
//
//  3. Append-rate anomaly — sudden 10x surge or 0.1x drop relative to
//     a rolling baseline. Defensive against silent-suppression and
//     burst-injection attacks.
//
// A rotation triggered by the watchdog calls log.Rotate() and emits a
// structured event so operators can correlate with their incident
// tooling.
package watchdog

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/desledishant10/stele/pkg/obs"
	"github.com/fsnotify/fsnotify"
)

// Reason describes why a rotation fired.
type Reason string

const (
	ReasonScheduled  Reason = "scheduled"
	ReasonKeyTamper  Reason = "key_dir_modified"
	ReasonRateSurge  Reason = "append_rate_surge"
	ReasonRateDrop   Reason = "append_rate_drop"
	ReasonManual     Reason = "manual"
)

// Event is what the watchdog emits when it fires a rotation.
type Event struct {
	At      time.Time `json:"at"`
	Reason  Reason    `json:"reason"`
	Detail  string    `json:"detail,omitempty"`
	Success bool      `json:"success"`
	Err     string    `json:"err,omitempty"`
}

// Rotator is the subset of core.Log that the watchdog needs. Defined as
// an interface for testing.
type Rotator interface {
	Rotate() error
}

// Config configures a Watchdog.
type Config struct {
	// Interval, if > 0, schedules a rotation every Interval. The first
	// rotation does not fire immediately on Start — wait one Interval.
	Interval time.Duration

	// KeyDir, if non-empty, is watched via fsnotify. Any change to any
	// file in the directory (or files newly created) triggers a
	// rotation.
	KeyDir string

	// MinDebounce is the minimum time between two watchdog-triggered
	// rotations. Prevents trigger storms (rapid fsnotify events,
	// pathological rate spikes). Default 30s.
	MinDebounce time.Duration

	// EnableRateMonitor turns on append-rate anomaly detection.
	EnableRateMonitor bool

	// RateWindow is the rolling window over which the rate baseline is
	// computed. Default 5 minutes.
	RateWindow time.Duration

	// EventSink, if set, receives every Event the watchdog emits.
	EventSink func(Event)
}

// Watchdog is the running watchdog instance.
type Watchdog struct {
	cfg     Config
	rot     Rotator
	mu      sync.Mutex
	lastRot time.Time

	// rate tracking
	rateMu      sync.Mutex
	rateBuckets []rateBucket
	bucketDur   time.Duration

	// state for shutdown
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type rateBucket struct {
	end   time.Time
	count uint64
}

// Start launches the watchdog. Call Stop on shutdown.
func Start(ctx context.Context, r Rotator, cfg Config) (*Watchdog, error) {
	if r == nil {
		return nil, errors.New("watchdog: nil Rotator")
	}
	if cfg.MinDebounce == 0 {
		cfg.MinDebounce = 30 * time.Second
	}
	if cfg.RateWindow == 0 {
		cfg.RateWindow = 5 * time.Minute
	}

	ctx2, cancel := context.WithCancel(ctx)
	w := &Watchdog{cfg: cfg, rot: r, cancel: cancel}

	// Initialise rate buckets: 30 buckets across the window so each
	// bucket holds RateWindow/30 seconds of counts.
	const nbuckets = 30
	w.bucketDur = cfg.RateWindow / nbuckets
	w.rateBuckets = make([]rateBucket, nbuckets)

	if cfg.Interval > 0 {
		w.wg.Add(1)
		go w.scheduler(ctx2)
	}
	if cfg.KeyDir != "" {
		w.wg.Add(1)
		if err := w.startFSWatcher(ctx2); err != nil {
			cancel()
			w.wg.Done()
			return nil, err
		}
	}
	if cfg.EnableRateMonitor {
		w.wg.Add(1)
		go w.rateMonitor(ctx2)
	}
	return w, nil
}

// Stop shuts the watchdog down.
func (w *Watchdog) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
}

// ObserveAppend bumps the append-rate counter. Call from the ingest
// path on every successful Append.
func (w *Watchdog) ObserveAppend() {
	if w == nil || !w.cfg.EnableRateMonitor {
		return
	}
	w.rateMu.Lock()
	defer w.rateMu.Unlock()
	now := time.Now()
	// Find or create the current bucket.
	if len(w.rateBuckets) == 0 || w.rateBuckets[len(w.rateBuckets)-1].end.Before(now) {
		// Roll the oldest bucket forward.
		copy(w.rateBuckets, w.rateBuckets[1:])
		w.rateBuckets[len(w.rateBuckets)-1] = rateBucket{end: now.Add(w.bucketDur), count: 1}
		return
	}
	w.rateBuckets[len(w.rateBuckets)-1].count++
}

// trigger fires a rotation if debounce allows. Thread-safe.
func (w *Watchdog) trigger(reason Reason, detail string) {
	w.mu.Lock()
	if time.Since(w.lastRot) < w.cfg.MinDebounce {
		w.mu.Unlock()
		return
	}
	w.lastRot = time.Now()
	w.mu.Unlock()

	err := w.rot.Rotate()
	ev := Event{
		At:      time.Now(),
		Reason:  reason,
		Detail:  detail,
		Success: err == nil,
	}
	outcome := "ok"
	if err != nil {
		outcome = "error"
		ev.Err = err.Error()
		obs.Error("watchdog rotation failed", "reason", string(reason), "err", err)
	} else {
		obs.Info("watchdog rotation succeeded", "reason", string(reason), "detail", detail)
	}
	obs.WatchdogRotationsTotal.WithLabelValues(string(reason), outcome).Inc()
	if w.cfg.EventSink != nil {
		w.cfg.EventSink(ev)
	}
}

// scheduler is the time-driven trigger.
func (w *Watchdog) scheduler(ctx context.Context) {
	defer w.wg.Done()
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.trigger(ReasonScheduled, fmt.Sprintf("interval=%s", w.cfg.Interval))
		}
	}
}

// startFSWatcher launches the fsnotify-based key directory watcher.
func (w *Watchdog) startFSWatcher(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watchdog: fsnotify: %w", err)
	}
	if err := watcher.Add(w.cfg.KeyDir); err != nil {
		watcher.Close()
		return fmt.Errorf("watchdog: watch %s: %w", w.cfg.KeyDir, err)
	}
	go func() {
		defer w.wg.Done()
		defer watcher.Close()
		// Counter so we can ignore the very first event burst, which is
		// just our own writes during startup.
		var ignored atomic.Int32
		ignored.Store(2) // skip up to 2 startup writes

		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Ignore CHMOD-only events (metadata changes only).
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
					continue
				}
				if ignored.Load() > 0 {
					ignored.Add(-1)
					continue
				}
				w.trigger(ReasonKeyTamper, fmt.Sprintf("event=%s path=%s", ev.Op, ev.Name))
			case err := <-watcher.Errors:
				if err != nil {
					obs.Warn("watchdog fsnotify error", "err", err)
				}
			}
		}
	}()
	return nil
}

// rateMonitor periodically inspects the bucket history and looks for
// statistical anomalies relative to the rolling baseline.
func (w *Watchdog) rateMonitor(ctx context.Context) {
	defer w.wg.Done()
	// Check every bucketDur after warmup.
	warmup := w.cfg.RateWindow
	startedAt := time.Now()
	t := time.NewTicker(w.bucketDur)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if time.Since(startedAt) < warmup {
				continue
			}
			if reason, detail, ok := w.detectRateAnomaly(); ok {
				w.trigger(reason, detail)
			}
		}
	}
}

// detectRateAnomaly compares the most-recent bucket's rate against the
// baseline of the rest of the window. Returns (reason, detail, true) if
// an anomaly is detected.
func (w *Watchdog) detectRateAnomaly() (Reason, string, bool) {
	w.rateMu.Lock()
	defer w.rateMu.Unlock()
	if len(w.rateBuckets) < 2 {
		return "", "", false
	}
	last := w.rateBuckets[len(w.rateBuckets)-1].count
	var baseline uint64
	for _, b := range w.rateBuckets[:len(w.rateBuckets)-1] {
		baseline += b.count
	}
	baselineRate := float64(baseline) / float64(len(w.rateBuckets)-1)
	lastRate := float64(last)

	// 10x surge.
	if baselineRate > 0 && lastRate > baselineRate*10 {
		return ReasonRateSurge, fmt.Sprintf("last=%d baseline_avg=%.2f", last, baselineRate), true
	}
	// 0.1x drop after we've actually seen activity (avoid firing on
	// quiet logs that have always been quiet).
	if baselineRate > 5 && lastRate < baselineRate*0.1 {
		return ReasonRateDrop, fmt.Sprintf("last=%d baseline_avg=%.2f", last, baselineRate), true
	}
	_ = math.IsNaN // keep math import alive if removed
	return "", "", false
}
