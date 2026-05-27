package obs

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Registry is the dedicated registry that /metrics exposes. We use a
// non-default registry so test binaries and library code can register
// metrics deterministically without colliding with stdlib defaults.
var Registry = prometheus.NewRegistry()

// promauto.With registers each metric on our Registry the moment the
// package initialises. Names follow the Prometheus naming convention:
// stele_<subsystem>_<unit>.

// AppendsTotal counts every Log.Append result. `outcome` is "ok",
// "duplicate", "rejected", or "error".
var AppendsTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
	Name: "stele_appends_total",
	Help: "Total number of Log.Append calls, partitioned by outcome.",
}, []string{"outcome"})

// AppendDurationSeconds is the end-to-end Append latency histogram.
// Buckets cover sub-millisecond to multi-second so a graph reveals
// both the fast path and pathological slow appends.
var AppendDurationSeconds = promauto.With(Registry).NewHistogram(prometheus.HistogramOpts{
	Name:    "stele_append_duration_seconds",
	Help:    "End-to-end Log.Append latency.",
	Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
})

// RotationsTotal counts forward-secure key rotations. `outcome` is
// "ok" or "error".
var RotationsTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
	Name: "stele_rotations_total",
	Help: "Forward-secure key rotations.",
}, []string{"outcome"})

// CheckpointsTotal counts published checkpoints.
var CheckpointsTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
	Name: "stele_checkpoints_total",
	Help: "Checkpoints published.",
}, []string{"outcome"})

// WitnessCosignTotal counts witness co-signature attempts.
// `witness` is the witness ID; `outcome` is "ok", "timeout", "rejected".
var WitnessCosignTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
	Name: "stele_witness_cosign_total",
	Help: "Witness co-signature attempts.",
}, []string{"witness", "outcome"})

// WitnessCosignDurationSeconds is the per-witness round-trip latency
// for collecting a co-signature.
var WitnessCosignDurationSeconds = promauto.With(Registry).NewHistogramVec(prometheus.HistogramOpts{
	Name:    "stele_witness_cosign_duration_seconds",
	Help:    "Time to gather a witness co-signature, end to end.",
	Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10, 30},
}, []string{"witness"})

// AnchorWritesTotal counts external-anchor writes. `sink` is "file",
// "rekor", etc.; `outcome` is "ok" or "error".
var AnchorWritesTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
	Name: "stele_anchor_writes_total",
	Help: "External anchor writes.",
}, []string{"sink", "outcome"})

// HoneypotsTotal counts honeylog canary alerts emitted.
var HoneypotsTotal = promauto.With(Registry).NewCounter(prometheus.CounterOpts{
	Name: "stele_honeypots_total",
	Help: "Honeylog canary alerts emitted.",
})

// WatchdogRotationsTotal counts watchdog-triggered rotations by reason
// ("schedule", "keydir", "rate-anomaly").
var WatchdogRotationsTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
	Name: "stele_watchdog_rotations_total",
	Help: "Watchdog-triggered key rotations.",
}, []string{"reason", "outcome"})

// ActiveEpoch and TreeSize are gauges set via callback functions in
// the operator. They surface the chain's current epoch and the log's
// current leaf count.
var ActiveEpoch = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
	Name: "stele_active_epoch",
	Help: "Current active fwdsec epoch.",
})

var TreeSize = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
	Name: "stele_tree_size",
	Help: "Current Merkle tree size (number of entries).",
})

var LastAnchorAgeSeconds = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
	Name: "stele_last_anchor_age_seconds",
	Help: "Seconds since the most recent external anchor write.",
})

var WitnessQuorumHealthy = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
	Name: "stele_witness_quorum_healthy",
	Help: "1 if the witness quorum threshold is reachable, 0 otherwise.",
})

// BuildInfo is a one-shot gauge surfacing the binary's build identity.
// Set once at startup with a constant value of 1, labelled with
// component/version/commit so PromQL can join other metrics against it.
var BuildInfo = promauto.With(Registry).NewGaugeVec(prometheus.GaugeOpts{
	Name: "stele_build_info",
	Help: "Build identity: value is always 1; labels carry the metadata.",
}, []string{"component", "version", "commit"})

// SetBuildInfo records the binary's identity. Call once from main().
func SetBuildInfo(version, commit string) {
	BuildInfo.WithLabelValues(component, version, commit).Set(1)
}

// TripwireRunsTotal counts continuous-integrity-check passes by
// outcome: "ok" / "tamper" / "error" / "skipped" (empty log).
var TripwireRunsTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
	Name: "stele_tripwire_runs_total",
	Help: "Continuous-integrity-check passes by outcome.",
}, []string{"outcome"})

// IngestRejectsTotal counts requests rejected at the ingest layer
// before reaching application logic. `reason` is one of:
//   - "body_too_large"  — exceeded http.MaxBytesReader cap
//   - "rate_limit"      — per-producer rate limiter triggered
//   - "concurrency"     — server-wide append semaphore saturated
//   - "shutting_down"   — graceful shutdown in progress
//
// `endpoint` is a low-cardinality label like "append", "producers".
var IngestRejectsTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
	Name: "stele_ingest_rejects_total",
	Help: "Requests rejected at the ingest layer (before application logic).",
}, []string{"endpoint", "reason"})

// AppendInFlight is a gauge of currently-running Append handlers. Use
// alongside the concurrency cap to see how close we are to saturation.
var AppendInFlight = promauto.With(Registry).NewGauge(prometheus.GaugeOpts{
	Name: "stele_append_in_flight",
	Help: "Number of Append handlers currently executing.",
})

// AdminActionsTotal counts admin-level mutations. Each one also goes
// into the on-disk admin audit log (pkg/adminlog). Useful for
// alerting on unexpected sequences (e.g. burst of producer-revocations).
//
// `action` examples: "rotate", "producer_register", "producer_revoke",
// "witness_add", "witness_remove", "threshold_group_set".
// `outcome` is "ok" or "error".
var AdminActionsTotal = promauto.With(Registry).NewCounterVec(prometheus.CounterOpts{
	Name: "stele_admin_actions_total",
	Help: "Admin-level mutations recorded into the admin audit log.",
}, []string{"action", "outcome"})

// lastAnchorAt holds the nanosecond timestamp of the last successful
// anchor write. Zero means "no anchor written yet" — in that case the
// gauge is left at 0 rather than reporting an unbounded large age.
var lastAnchorAt atomic.Int64

// MarkAnchorWrite records "now" as the most recent successful anchor.
// Call this whenever an anchor sink reports OK. A background ticker
// reads the timestamp and updates LastAnchorAgeSeconds.
func MarkAnchorWrite() {
	lastAnchorAt.Store(time.Now().UnixNano())
}

// StartAnchorAgeTicker starts a goroutine that updates the
// LastAnchorAgeSeconds gauge every 5 seconds. The goroutine exits when
// ctx is done. Idempotent isn't enforced — call once per process.
func StartAnchorAgeTicker(ctx context.Context) {
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ns := lastAnchorAt.Load()
				if ns == 0 {
					continue // never anchored — leave gauge at 0
				}
				LastAnchorAgeSeconds.Set(time.Since(time.Unix(0, ns)).Seconds())
			}
		}
	}()
}
