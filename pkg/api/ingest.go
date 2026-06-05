package api

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/desledishant10/stele/pkg/obs"
	"golang.org/x/time/rate"
)

// IngestPolicy configures the ingest-path guard rails: server-wide
// concurrency, per-producer rate limiting on /append, and per-actor
// rate limiting on the admin mutation endpoints.
//
// Each guard is optional — a zero/empty value disables it. Production
// should set all of them. Admin actions are intrinsically rare
// (rotations, enrollments, witness changes), so the admin limit is
// much tighter than the producer limit; the goal is to catch
// credential-stuffing or accidental loops against the admin trail.
type IngestPolicy struct {
	// MaxConcurrentAppends is the server-wide cap on simultaneous
	// /append handlers. A semaphore enforces it; saturation returns
	// 503 with a Retry-After header set from RetryAfter.
	// Zero or negative disables the cap.
	MaxConcurrentAppends int

	// PerProducerRPS is the steady-state rate (in requests/second)
	// allowed per producer ID on /append. Zero disables.
	PerProducerRPS float64

	// PerProducerBurst is the burst budget per producer. Should be at
	// least 1 — Go's x/time/rate caps burst at this value.
	PerProducerBurst int

	// PerAdminRPS is the steady-state rate per admin actor on the
	// admin mutation endpoints (rotate, producer-register,
	// producer-revoke, witness-add, enrollment-issue, checkpoint,
	// anchor). Actor identity is the mTLS client cert CN if present,
	// else the X-Stele-Admin header, else the source IP. Zero
	// disables.
	PerAdminRPS float64

	// PerAdminBurst is the burst budget per admin actor.
	PerAdminBurst int

	// RetryAfter is the Retry-After value (in seconds) returned with
	// 429s and 503s. Conservative: 1 second.
	RetryAfter int
}

// DefaultIngestPolicy is production-ready: CPU-aware concurrency,
// per-producer rate at 100 RPS with a 200-burst, per-admin rate at 5
// RPS with a 10-burst, 1-second Retry-After.
//
// Concurrency note (v0.1.5, per issue #8): MaxConcurrentAppends is
// now derived from runtime.NumCPU() via defaultConcurrency() rather
// than a fixed 256. On a 4-vCPU host that's 16; on a 32-vCPU host
// that's 128. The v0.1.4 soak found that the previous fixed 256
// produced burst-allocation spikes the GC could not keep up with on
// 4-8 GB hosts. CPU-scaled concurrency naturally tracks host size.
// Override via --max-concurrent-appends if you have an unusual ratio.
//
// Admin RPS is tight on purpose — a legitimate operator runs maybe a
// few rotations per day, dozens of enrollments per month. 5 RPS still
// leaves room for an emergency-revocation script processing a list of
// compromised keys.
var DefaultIngestPolicy = IngestPolicy{
	MaxConcurrentAppends: defaultConcurrency(),
	PerProducerRPS:       100,
	PerProducerBurst:     200,
	PerAdminRPS:          5,
	PerAdminBurst:        10,
	RetryAfter:           1,
}

// defaultConcurrency returns the v0.1.5 default for
// MaxConcurrentAppends: NumCPU * 4, clamped to [16, 256]. The cap is
// preserved so a very large host doesn't degrade GC pressure
// indefinitely, and the floor keeps very small hosts (2-vCPU) from
// undershooting.
func defaultConcurrency() int {
	n := runtime.NumCPU() * 4
	if n < 16 {
		n = 16
	}
	if n > 256 {
		n = 256
	}
	return n
}

// ingestGate is the runtime guard. It owns:
//   - A bounded semaphore for global concurrency.
//   - A map of per-producer token-bucket limiters with idle eviction.
//
// Single instance per Server. Constructed via newIngestGate.
type ingestGate struct {
	policy IngestPolicy
	sem    chan struct{} // nil if MaxConcurrentAppends <= 0

	mu             sync.Mutex
	producerLimits map[string]*bucketEntry
	adminLimits    map[string]*bucketEntry
}

// bucketEntry is a per-key token bucket plus the wall-clock time it
// was last used (for janitor eviction). The same shape works for
// producers and admin actors so we share the type.
type bucketEntry struct {
	lim      *rate.Limiter
	lastUsed time.Time
}

func newIngestGate(p IngestPolicy) *ingestGate {
	g := &ingestGate{
		policy:         p,
		producerLimits: make(map[string]*bucketEntry),
		adminLimits:    make(map[string]*bucketEntry),
	}
	if p.MaxConcurrentAppends > 0 {
		g.sem = make(chan struct{}, p.MaxConcurrentAppends)
	}
	return g
}

// acquire reserves one global concurrency slot. Returns true on
// success, false if the semaphore is saturated. nil sem (no cap)
// always succeeds.
func (g *ingestGate) acquire() bool {
	if g.sem == nil {
		return true
	}
	select {
	case g.sem <- struct{}{}:
		obs.AppendInFlight.Inc()
		return true
	default:
		return false
	}
}

// release returns the slot. Must be paired with a successful acquire.
func (g *ingestGate) release() {
	if g.sem == nil {
		return
	}
	<-g.sem
	obs.AppendInFlight.Dec()
}

// allowProducer consumes one token from the producer's bucket. Returns
// true if allowed, false if the producer is over its rate limit. A
// disabled limit (rate <= 0) always allows.
func (g *ingestGate) allowProducer(id string) bool {
	return g.allow(g.policy.PerProducerRPS, g.policy.PerProducerBurst, &g.producerLimits, id)
}

// allowAdmin consumes one token from the admin actor's bucket. Returns
// true if allowed. A disabled limit (rate <= 0) always allows.
//
// `actor` should be the result of callerIdentity(r): the mTLS client
// cert CN if present, else the X-Stele-Admin header, else the source
// IP. Same precedence as the admin audit log uses.
func (g *ingestGate) allowAdmin(actor string) bool {
	return g.allow(g.policy.PerAdminRPS, g.policy.PerAdminBurst, &g.adminLimits, actor)
}

// allow is the shared token-bucket implementation used by both the
// producer and admin limiters. Callers supply the rate, burst, and
// the map the bucket lives in.
func (g *ingestGate) allow(rps float64, burst int, table *map[string]*bucketEntry, key string) bool {
	if rps <= 0 {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := (*table)[key]
	if !ok {
		if burst <= 0 {
			burst = 1
		}
		entry = &bucketEntry{
			lim: rate.NewLimiter(rate.Limit(rps), burst),
		}
		(*table)[key] = entry
	}
	entry.lastUsed = time.Now()
	return entry.lim.Allow()
}

// evictIdle drops limiters that haven't been touched for `older` in
// EITHER the producer or admin maps. Call from a periodic janitor to
// keep memory bounded under churn. Returns the total count removed.
func (g *ingestGate) evictIdle(older time.Duration) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	cutoff := time.Now().Add(-older)
	n := 0
	for _, table := range []*map[string]*bucketEntry{&g.producerLimits, &g.adminLimits} {
		for id, e := range *table {
			if e.lastUsed.Before(cutoff) {
				delete(*table, id)
				n++
			}
		}
	}
	return n
}

// StartJanitor runs a background goroutine that evicts idle rate
// limiters (producer + admin) every `interval`. Limiters older than
// `idleAfter` are dropped. Cancel ctx to stop. No-op if both rate
// limits are disabled.
func (s *Server) StartJanitor(ctx context.Context, interval, idleAfter time.Duration) {
	if s.gate == nil ||
		(s.gate.policy.PerProducerRPS <= 0 && s.gate.policy.PerAdminRPS <= 0) {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if idleAfter <= 0 {
		idleAfter = 1 * time.Hour
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n := s.gate.evictIdle(idleAfter); n > 0 {
					obs.Debug("rate-limiter janitor evicted idle buckets", "count", n)
				}
			}
		}
	}()
}

// retryAfterSeconds returns the value for the Retry-After header. At
// least 1 — never zero, which clients sometimes interpret as "retry
// immediately".
func (g *ingestGate) retryAfterSeconds() int {
	if g.policy.RetryAfter <= 0 {
		return 1
	}
	return g.policy.RetryAfter
}

// writeRetryAfter sets Retry-After and writes a JSON error response.
// Used for both 429 (rate limit) and 503 (concurrency).
func writeRetryAfter(w http.ResponseWriter, status int, retryAfter int, msg string) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeErr(w, status, fmt.Errorf("%s; retry after %ds", msg, retryAfter))
}
