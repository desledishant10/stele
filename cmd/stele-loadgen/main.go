// stele-loadgen exercises a running steled with synthetic producer
// traffic so operators can verify capacity, latency tails, and the
// hardening guards under realistic load.
//
// It does what a real producer cohort would do, sped up:
//
//   1. Mint N fresh Ed25519 producer keypairs in memory.
//   2. POST each producer's public key to /api/v0/producers (so
//      subsequent appends pass the registry check).
//   3. Run for --duration with --rps target. Each producer goroutine
//      paces its own appends; the aggregate rate is `producers * rps`
//      if --per-producer-rps is set, otherwise `--rps` is the
//      aggregate target shared across producers.
//   4. Every Append response is classified into one of:
//        - 200 success
//        - 413 body-too-large (size-cap)
//        - 429 rate-limit  (per-producer-rps quota)
//        - 503 concurrency (server-wide semaphore)
//        - other 4xx (typically envelope validation)
//        - 5xx (genuine server error)
//        - network (TCP / TLS / timeout)
//   5. Latencies are recorded into a histogram per outcome class so
//      the report can show "successful appends were fast, but the
//      429 path was also fast" (a healthy backpressure signature).
//
// Output is a text summary by default; --json or --csv emit machine-
// readable runs for plotting or CI comparison.
//
// stele-loadgen is intentionally not a fuzzer — it submits VALID
// envelopes. To test parser robustness see pkg/*/fuzz_test.go.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/desledishant10/stele/pkg/api"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/storage"
)

// Set via `-ldflags "-X main.version=... -X main.commit=..."`.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	obs.Init("loadgen", nil)
	obs.SetBuildInfo(version, commit)
	if err := run(); err != nil {
		obs.Fatal("loadgen failed", "err", err)
	}
}

func run() error {
	var (
		server         = flag.String("server", "http://localhost:8080", "stele operator URL")
		producers      = flag.Int("producers", 8, "number of synthetic producers")
		rps            = flag.Float64("rps", 100, "aggregate target requests/sec (split across producers)")
		duration       = flag.Duration("duration", 30*time.Second, "total run duration")
		warmup         = flag.Duration("warmup", 2*time.Second, "warmup before recording latencies (still hits the server)")
		payloadBytes   = flag.Int("payload", 64, "envelope.data payload size in bytes")
		producerPrefix = flag.String("id-prefix", "loadgen", "producer ID prefix")
		concurrency    = flag.Int("concurrency", 32, "max in-flight HTTP requests across all producers")
		jsonOut        = flag.String("json", "", "if set, write machine-readable run summary to this path")
		csvOut         = flag.String("csv", "", "if set, write a CSV row of per-outcome latency percentiles")
		insecure       = flag.Bool("insecure-skip-verify", false, "(DEV ONLY) skip server TLS verification")
	)
	flag.Parse()

	if *producers < 1 {
		return errors.New("--producers must be >= 1")
	}
	if *rps <= 0 {
		return errors.New("--rps must be > 0")
	}

	rig, err := buildRig(*server, *producers, *producerPrefix, *insecure)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeoutCancel := context.WithTimeout(ctx, *duration+*warmup)
	defer timeoutCancel()

	obs.Info("loadgen starting",
		"server", *server,
		"producers", *producers,
		"target_rps", *rps,
		"duration", duration.String(),
		"warmup", warmup.String(),
		"payload_bytes", *payloadBytes,
		"concurrency", *concurrency)

	stats := newStats()
	gate := make(chan struct{}, *concurrency)

	// Per-producer pacing: each producer's slice of the aggregate RPS.
	perProducerRPS := *rps / float64(*producers)
	tickInterval := time.Duration(float64(time.Second) / perProducerRPS)
	if tickInterval < 1*time.Millisecond {
		tickInterval = 1 * time.Millisecond
	}

	startRecording := time.Now().Add(*warmup)
	var wg sync.WaitGroup
	for _, p := range rig.producers {
		wg.Add(1)
		go func(p *producer) {
			defer wg.Done()
			runProducer(ctx, p, rig.client, *server, *payloadBytes,
				tickInterval, gate, stats, startRecording)
		}(p)
	}
	wg.Wait()

	stats.finalise()
	stats.summary(os.Stdout, *server, *rps, *duration)

	if *jsonOut != "" {
		if err := stats.writeJSON(*jsonOut, *server, *rps, *duration, *producers, *payloadBytes); err != nil {
			return fmt.Errorf("write json: %w", err)
		}
	}
	if *csvOut != "" {
		if err := stats.writeCSV(*csvOut, *server, *rps, *duration, *producers, *payloadBytes); err != nil {
			return fmt.Errorf("write csv: %w", err)
		}
	}
	return nil
}

// ---- rig setup ----

type producer struct {
	id       string
	attestor *attest.SoftwareAttestor
}

type rig struct {
	producers []*producer
	client    *http.Client
}

func buildRig(server string, n int, prefix string, insecure bool) (*rig, error) {
	r := &rig{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        1024,
				MaxIdleConnsPerHost: 1024,
				MaxConnsPerHost:     0,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
	if insecure {
		// Skip TLS verification for tests. Never use against prod.
		r.client.Transport.(*http.Transport).TLSClientConfig = nil
		obs.Warn("TLS verification disabled (--insecure-skip-verify)")
	}
	// Mint producers + register each one.
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano()%1_000_000, i)
		a, err := attest.NewSoftwareAttestor(id)
		if err != nil {
			return nil, fmt.Errorf("attestor %d: %w", i, err)
		}
		p := &producer{id: id, attestor: a}
		if err := registerProducer(r.client, server, p); err != nil {
			return nil, fmt.Errorf("register %s: %w", id, err)
		}
		r.producers = append(r.producers, p)
	}
	return r, nil
}

func registerProducer(c *http.Client, server string, p *producer) error {
	body := api.RegisterProducerRequest{Producer: &storage.Producer{
		ID:              p.id,
		PublicKey:       p.attestor.PublicKey(),
		AttestationType: string(attest.TypeSoftware),
	}}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, server+"/api/v0/producers", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// ---- producer loop ----

func runProducer(
	ctx context.Context,
	p *producer,
	client *http.Client,
	server string,
	payloadBytes int,
	tick time.Duration,
	gate chan struct{},
	stats *stats,
	startRecording time.Time,
) {
	payload := make([]byte, payloadBytes)
	if _, err := rand.Read(payload); err != nil {
		obs.Error("rand.Read for payload failed", "err", err)
		return
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// Vary the payload per-call so envelope hashes differ (replay
		// protection refuses duplicate hashes).
		// Replace only a small prefix so payload size remains constant.
		_, _ = rand.Read(payload[:8])
		select {
		case gate <- struct{}{}:
		case <-ctx.Done():
			return
		}
		go func(payload []byte) {
			defer func() { <-gate }()
			outcome, dur := submitOne(ctx, client, server, p, payload)
			if time.Now().After(startRecording) {
				stats.record(outcome, dur)
			}
		}(append([]byte(nil), payload...))
	}
}

func submitOne(ctx context.Context, client *http.Client, server string, p *producer, payload []byte) (outcome string, d time.Duration) {
	env, err := p.attestor.Sign("loadgen", payload)
	if err != nil {
		return "client-sign-error", 0
	}
	body, err := json.Marshal(api.AppendRequest{Envelope: env})
	if err != nil {
		return "client-marshal-error", 0
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v0/append", bytes.NewReader(body))
	if err != nil {
		return "client-req-error", 0
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := client.Do(req)
	d = time.Since(start)
	if err != nil {
		return classifyNetErr(err), d
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return classifyHTTP(resp.StatusCode), d
}

func classifyHTTP(status int) string {
	switch status {
	case 200, 201:
		return "ok"
	case 413:
		return "body_too_large"
	case 429:
		return "rate_limit"
	case 503:
		return "concurrency"
	case 400, 401, 403, 404, 405, 409, 422:
		return "client_4xx"
	}
	if status >= 500 {
		return "server_5xx"
	}
	return "other"
}

func classifyNetErr(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	return "network"
}

// ---- stats + reporting ----

type stats struct {
	mu       sync.Mutex
	counts   map[string]int
	latencies map[string][]time.Duration
	totalReqs int64
}

func newStats() *stats {
	return &stats{
		counts:    make(map[string]int),
		latencies: make(map[string][]time.Duration),
	}
}

func (s *stats) record(outcome string, d time.Duration) {
	atomic.AddInt64(&s.totalReqs, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[outcome]++
	if d > 0 {
		s.latencies[outcome] = append(s.latencies[outcome], d)
	}
}

func (s *stats) finalise() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.latencies {
		sort.Slice(s.latencies[k], func(i, j int) bool {
			return s.latencies[k][i] < s.latencies[k][j]
		})
	}
}

func (s *stats) summary(w io.Writer, server string, rps float64, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := int64(0)
	for _, n := range s.counts {
		total += int64(n)
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "==========================================================")
	fmt.Fprintf(w, "Stele load-test summary  (server=%s)\n", server)
	fmt.Fprintln(w, "==========================================================")
	fmt.Fprintf(w, "Target RPS    : %.1f\n", rps)
	fmt.Fprintf(w, "Duration      : %s\n", duration)
	fmt.Fprintf(w, "Total requests: %d\n", total)
	if total > 0 {
		fmt.Fprintf(w, "Achieved RPS  : %.1f\n", float64(total)/duration.Seconds())
	}
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "%-18s %10s %12s %12s %12s %12s\n",
		"outcome", "count", "p50", "p95", "p99", "p99.9")
	fmt.Fprintln(w, "----------------------------------------------------------------------------------")
	// Stable ordering for readability + machine diff.
	for _, k := range []string{
		"ok", "rate_limit", "concurrency", "body_too_large",
		"client_4xx", "server_5xx", "timeout", "network", "other",
	} {
		n, ok := s.counts[k]
		if !ok {
			continue
		}
		ls := s.latencies[k]
		fmt.Fprintf(w, "%-18s %10d %12s %12s %12s %12s\n",
			k, n, fmtP(ls, 0.50), fmtP(ls, 0.95), fmtP(ls, 0.99), fmtP(ls, 0.999))
	}
	fmt.Fprintln(w, "==========================================================")
}

func (s *stats) writeJSON(path, server string, rps float64, duration time.Duration, producers, payload int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	type outcomeStat struct {
		Count int           `json:"count"`
		P50   time.Duration `json:"p50_ns"`
		P95   time.Duration `json:"p95_ns"`
		P99   time.Duration `json:"p99_ns"`
		P999  time.Duration `json:"p999_ns"`
		Min   time.Duration `json:"min_ns"`
		Max   time.Duration `json:"max_ns"`
	}
	doc := map[string]any{
		"server":         server,
		"target_rps":     rps,
		"duration_ns":    duration,
		"producers":      producers,
		"payload_bytes":  payload,
		"version":        version,
		"commit":         commit,
		"run_started_at": time.Now().UTC().Format(time.RFC3339),
	}
	outcomes := map[string]outcomeStat{}
	for k, n := range s.counts {
		ls := s.latencies[k]
		var min, max time.Duration
		if len(ls) > 0 {
			min, max = ls[0], ls[len(ls)-1]
		}
		outcomes[k] = outcomeStat{
			Count: n,
			P50:   percentile(ls, 0.50),
			P95:   percentile(ls, 0.95),
			P99:   percentile(ls, 0.99),
			P999:  percentile(ls, 0.999),
			Min:   min,
			Max:   max,
		}
	}
	doc["outcomes"] = outcomes
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o644)
}

func (s *stats) writeCSV(path, server string, rps float64, duration time.Duration, producers, payload int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	cw := csv.NewWriter(f)
	defer cw.Flush()
	_ = cw.Write([]string{"server", "target_rps", "duration_s", "producers", "payload_bytes",
		"outcome", "count", "p50_us", "p95_us", "p99_us", "p999_us"})
	for k, n := range s.counts {
		ls := s.latencies[k]
		_ = cw.Write([]string{
			server,
			strconv.FormatFloat(rps, 'f', 1, 64),
			strconv.FormatFloat(duration.Seconds(), 'f', 1, 64),
			strconv.Itoa(producers),
			strconv.Itoa(payload),
			k,
			strconv.Itoa(n),
			usStr(percentile(ls, 0.50)),
			usStr(percentile(ls, 0.95)),
			usStr(percentile(ls, 0.99)),
			usStr(percentile(ls, 0.999)),
		})
	}
	return nil
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func fmtP(sorted []time.Duration, p float64) string {
	v := percentile(sorted, p)
	if v == 0 {
		return "-"
	}
	switch {
	case v >= time.Second:
		return v.Round(time.Millisecond).String()
	case v >= time.Millisecond:
		return v.Round(10 * time.Microsecond).String()
	default:
		return v.Round(time.Microsecond).String()
	}
}

func usStr(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Microsecond), 'f', 1, 64)
}
