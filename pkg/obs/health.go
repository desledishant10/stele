package obs

import (
	"context"
	"sync"
	"time"
)

// Probe is a named readiness check. Returning nil means healthy; any
// error means the probe is unhappy and /readyz will return 503.
type Probe func(context.Context) error

// Health is a thread-safe registry of readiness probes. Each component
// (storage, chain, witness mesh) registers a probe; /readyz runs them
// all on every request.
//
// Liveness is intentionally separate: /healthz reflects only "is the
// process responsive", not "is the workload behaving." That distinction
// matters for orchestrators — restarting a pod that has degraded
// dependencies (e.g. a witness gone dark) is usually wrong.
type Health struct {
	mu     sync.RWMutex
	probes map[string]Probe
}

// DefaultHealth is the registry used by the package-level helpers. Each
// binary's main() should populate it.
var DefaultHealth = &Health{probes: map[string]Probe{}}

// Register adds a probe under `name`. Re-registering replaces the prior
// probe.
func (h *Health) Register(name string, p Probe) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.probes[name] = p
}

// Unregister removes a probe. No-op if name is not registered.
func (h *Health) Unregister(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.probes, name)
}

// Snapshot is the per-probe result of a Check run.
type Snapshot struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Err  string `json:"err,omitempty"`
}

// Check runs every registered probe with the supplied context (a 2s
// deadline is a sensible default for /readyz). Returns one snapshot per
// probe and a boolean indicating whether all passed.
func (h *Health) Check(ctx context.Context) ([]Snapshot, bool) {
	h.mu.RLock()
	probes := make(map[string]Probe, len(h.probes))
	for k, v := range h.probes {
		probes[k] = v
	}
	h.mu.RUnlock()

	out := make([]Snapshot, 0, len(probes))
	allOK := true
	for name, p := range probes {
		err := p(ctx)
		s := Snapshot{Name: name, OK: err == nil}
		if err != nil {
			s.Err = err.Error()
			allOK = false
		}
		out = append(out, s)
	}
	return out, allOK
}

// RegisterProbe is the package-level shortcut against DefaultHealth.
func RegisterProbe(name string, p Probe) { DefaultHealth.Register(name, p) }

// CheckHealth runs every probe in DefaultHealth with a 2s deadline.
func CheckHealth() ([]Snapshot, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return DefaultHealth.Check(ctx)
}
