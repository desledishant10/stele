package obs

import (
	"encoding/json"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Mount registers /metrics, /healthz, and /readyz on the given mux.
// Every stele binary should call this on its primary HTTP mux.
//
//   - /healthz returns 200 + "ok" as long as the process is responding.
//     Use this as the orchestrator's liveness probe.
//
//   - /readyz runs every registered probe in DefaultHealth and returns
//     200 + a JSON snapshot when all pass, 503 + the same snapshot
//     otherwise. Use this as the orchestrator's readiness probe and
//     for load-balancer traffic-routing decisions.
//
//   - /metrics serves Prometheus-format metrics from obs.Registry.
func Mount(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", handleLive)
	mux.HandleFunc("/readyz", handleReady)
	mux.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{
		Registry: Registry,
	}))
}

func handleLive(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func handleReady(w http.ResponseWriter, r *http.Request) {
	snaps, allOK := DefaultHealth.Check(r.Context())
	w.Header().Set("Content-Type", "application/json")
	if !allOK {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":     allOK,
		"probes": snaps,
	})
}
