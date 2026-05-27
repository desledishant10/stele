// steled is the provenance-log daemon. It serves the HTTP API on a single
// port and persists everything under --dir.
//
// Quickstart:
//
//	steled --dir ./data --origin example.com/my-log --init
//
// On --init it generates a new Ed25519 keypair under <dir>/keys/. Drop --init
// for subsequent runs.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/desledishant10/stele/pkg/adminlog"
	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/api"
	"github.com/desledishant10/stele/pkg/beacon"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/core"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/honeylog"
	"github.com/desledishant10/stele/pkg/hsm"
	"github.com/desledishant10/stele/pkg/httpx"
	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/readlog"
	"github.com/desledishant10/stele/pkg/storage"
	"github.com/desledishant10/stele/pkg/threshold"
	"github.com/desledishant10/stele/pkg/tripwire"
	"github.com/desledishant10/stele/pkg/watchdog"
)

// Set via `-ldflags "-X main.version=... -X main.commit=..."`.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	obs.Init("steled", nil)
	obs.SetBuildInfo(version, commit)
	if err := run(); err != nil {
		obs.Fatal("steled startup failed", "err", err)
	}
}

func run() error {
	var (
		addr        = flag.String("addr", ":8080", "HTTP listen address")
		dir         = flag.String("dir", "", "data directory (required)")
		origin      = flag.String("origin", "stele.local/default", "log origin label")
		anchorPath  = flag.String("anchor", "", "path to the append-only anchor file (defaults to <dir>/anchors/anchor.log)")
		initialise  = flag.Bool("init", false, "generate keys and create dir if missing")
		ckptEvery   = flag.Duration("checkpoint-every", 30*time.Second, "auto-checkpoint interval (0 to disable)")
		anchorEvery = flag.Duration("anchor-every", 30*time.Second, "auto-anchor interval (0 to disable)")
		beaconURL   = flag.String("beacon", beacon.DefaultEndpoint, "drand endpoint for time anchoring (empty = disable)")
		honeyURL    = flag.String("honey-webhook", "", "webhook URL to POST honeypot alerts (empty = stderr only)")
		rekorURL    = flag.String("rekor", "", "Sigstore Rekor endpoint for external anchoring (empty = disable)")
		hsmModule   = flag.String("hsm-module", "", "PKCS#11 module path (e.g. libsofthsm2.so); empty uses on-disk key files")
		hsmSlot     = flag.Uint("hsm-slot", 0, "PKCS#11 slot ID")
		hsmPIN      = flag.String("hsm-pin", "", "PKCS#11 user PIN (consider STELE_HSM_PIN env var instead)")
		hsmPINEnv   = flag.String("hsm-pin-env", "STELE_HSM_PIN", "env var to read the HSM PIN from (used if --hsm-pin is empty)")
		hsmPrefix   = flag.String("hsm-key-prefix", "stele", "label prefix used for HSM key objects")
		rotateEvery   = flag.Duration("rotate-every", 0, "auto-rotate the operator key every N (0 disables scheduled rotation)")
		watchKeyDir   = flag.Bool("watch-keys", true, "rotate immediately if anything modifies <dir>/keys/")
		watchRate     = flag.Bool("watch-rate", false, "rotate on anomalous append-rate surges or drops")
		watchDebounce = flag.Duration("watch-debounce", 30*time.Second, "minimum interval between watchdog-triggered rotations")
		tlsCert       = flag.String("tls-cert", "", "server certificate (PEM) — enables HTTPS")
		tlsKey        = flag.String("tls-key", "", "server private key (PEM)")
		clientCA      = flag.String("client-ca", "", "PEM file of CA(s) that sign producer client certs — enables mTLS")
		tlsRequireCN  = flag.Bool("tls-require-cn-match", true, "with mTLS, require client cert CN == envelope.ProducerID")
		thresholdPath = flag.String("threshold-group", "", "path to group.json — enables t-of-N threshold checkpoint signing via cosigners")
		thresholdTag  = flag.String("threshold-caller-tag", "", "X-Stele-Caller token sent to each cosigner (matched against cosigner --trusted-caller list)")
		readLog       = flag.Bool("read-log", true, "append every served read into a tamper-evident journal at <dir>/read-log/")
		pqMode        = flag.String("pq-mode", "classical", "post-quantum mode: 'classical' (Ed25519 only) or 'hybrid' (Ed25519 + Dilithium3)")
		otlpEndpoint  = flag.String("otlp-endpoint", "", "OpenTelemetry OTLP/HTTP traces endpoint, e.g. http://otelcol:4318 (empty = disable; also honors OTEL_EXPORTER_OTLP_*_ENDPOINT)")
		tripwireEvery = flag.Duration("tripwire-every", 1*time.Hour, "continuous integrity check interval; re-derives Merkle root from disk and compares to last checkpoint (0 disables)")
		requireEnrollment = flag.Bool("require-enrollment", false, "refuse Append for any producer without a verifiable signed enrollment from the operator chain (use /enrollments to mint)")
		// ---- ingest hardening ----
		maxConcurrentAppends = flag.Int("max-concurrent-appends", api.DefaultIngestPolicy.MaxConcurrentAppends,
			"server-wide cap on in-flight /append handlers; saturation returns 503 (0 disables)")
		perProducerRPS = flag.Float64("per-producer-rps", api.DefaultIngestPolicy.PerProducerRPS,
			"steady-state requests/sec per producer ID; excess returns 429 (0 disables)")
		perProducerBurst = flag.Int("per-producer-burst", api.DefaultIngestPolicy.PerProducerBurst,
			"per-producer token-bucket burst budget")
		perAdminRPS = flag.Float64("per-admin-rps", api.DefaultIngestPolicy.PerAdminRPS,
			"steady-state requests/sec per admin actor on rotate/enroll/revoke/witnesses/producers/checkpoint/anchor; excess returns 429 (0 disables)")
		perAdminBurst = flag.Int("per-admin-burst", api.DefaultIngestPolicy.PerAdminBurst,
			"per-admin token-bucket burst budget")
		appendBodyMax = flag.Int64("append-body-max", api.DefaultLimits.AppendBodyBytes,
			"max bytes per /append request body (HTTP 413 on excess)")
		adminBodyMax = flag.Int64("admin-body-max", api.DefaultLimits.AdminBodyBytes,
			"max bytes per admin endpoint request body")
		retryAfter = flag.Int("retry-after-secs", api.DefaultIngestPolicy.RetryAfter,
			"Retry-After header value sent with 429/503 responses")
	)
	flag.Parse()
	if *dir == "" {
		return errors.New("--dir is required")
	}

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}

	keyDir := filepath.Join(*dir, "keys")
	if *pqMode != "classical" && *pqMode != "hybrid" {
		return fmt.Errorf("invalid --pq-mode %q (expected classical|hybrid)", *pqMode)
	}
	if *pqMode == "hybrid" && *hsmModule != "" {
		return errors.New("--pq-mode hybrid is incompatible with --hsm-module in v1 (no PKCS#11 Dilithium yet)")
	}
	signer, signerCloser, err := loadOrInitSigner(*origin, keyDir, *initialise, *pqMode == "hybrid", hsmFlags{
		Module:    *hsmModule,
		Slot:      *hsmSlot,
		PIN:       resolveHSMPIN(*hsmPIN, *hsmPINEnv),
		KeyPrefix: *hsmPrefix,
	})
	if err != nil {
		return err
	}
	if signerCloser != nil {
		defer signerCloser()
	}

	// If a threshold-group config was supplied, swap the single-sig
	// checkpoint signer for a threshold one that fans out to cosigners.
	if *thresholdPath != "" {
		group, err := loadThresholdGroup(*thresholdPath, *origin)
		if err != nil {
			return err
		}
		coord := threshold.NewCoordinator(group)
		coord.CallerTag = *thresholdTag
		// We need a checkpoint.Signer that knows about both. Replace
		// the one returned by loadOrInitSigner — preserve the fwdsec
		// signer (used for KeyID + epoch metadata) but adopt
		// threshold mode for actual signing.
		threshSigner, err := checkpoint.NewThresholdSigner(signer.UnsafeFWS(), group, coord)
		if err != nil {
			return err
		}
		signer = threshSigner
		// ALSO use the same coordinator for rotation-cert signing so
		// the rotation key itself doesn't become a single point of
		// failure. After this hook, every Rotate() produces a
		// threshold-signed cert that requires t-of-N cosigners.
		signer.UnsafeFWS().UseThresholdRotation(&thresholdRotatorShim{coord: coord})
		obs.Info("threshold signing enabled",
			"origin", group.Origin,
			"group_digest", group.DigestHex()[:16],
			"threshold", group.Threshold,
			"members", len(group.Members),
			"covers", "rotation+checkpoint")
	}

	storeDir := filepath.Join(*dir, "db")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		return err
	}
	st, err := storage.Open(storeDir)
	if err != nil {
		return err
	}
	defer st.Close()

	if *anchorPath == "" {
		*anchorPath = filepath.Join(*dir, "anchors", "anchor.log")
	}
	fsink, err := anchor.NewFileSink(*anchorPath)
	if err != nil {
		return err
	}
	sinks := []anchor.Sink{fsink}
	if *rekorURL != "" {
		rekor := anchor.NewRekorSink(*rekorURL, filepath.Join(*dir, "anchors", "rekor-fallback.log"))
		sinks = append(sinks, rekor)
		obs.Info("rekor anchor enabled", "url", *rekorURL)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	traceShutdown, err := obs.InitTracing(ctx, *otlpEndpoint, version, commit)
	if err != nil {
		return fmt.Errorf("tracing: %w", err)
	}
	defer func() {
		shutCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = traceShutdown(shutCtx)
	}()
	if *otlpEndpoint != "" {
		obs.Info("OpenTelemetry tracing enabled", "endpoint", *otlpEndpoint)
	}

	var beaconFetcher core.CheckpointBeaconFetcher
	if *beaconURL != "" {
		bc := beacon.New()
		bc.Endpoint = *beaconURL
		beaconFetcher = bc.FetcherFor(ctx)
		obs.Info("drand beacon enabled", "endpoint", bc.Endpoint, "chain_hash", bc.ChainHash[:16])
	}

	logInst, err := core.New(ctx, core.Options{
		Store:             st,
		Signer:            signer,
		Sinks:             sinks,
		BeaconFetcher:     beaconFetcher,
		RequireEnrollment: *requireEnrollment,
	})
	if err != nil {
		return err
	}
	if *requireEnrollment {
		obs.Info("enrollment-required mode active",
			"hint", "every producer must be issued via POST /api/v0/enrollments before Append succeeds")
	}

	// Schedule background checkpoint + anchor.
	if *ckptEvery > 0 {
		go schedule(ctx, *ckptEvery, "checkpoint", func() error {
			_, err := logInst.Checkpoint()
			return err
		})
	}
	if *anchorEvery > 0 {
		go schedule(ctx, *anchorEvery, "anchor", func() error {
			_, err := logInst.Anchor()
			return err
		})
	}

	var honeySink honeylog.Sink = &honeylog.StderrSink{}
	if *honeyURL != "" {
		honeySink = &honeylog.MultiSink{Sinks: []honeylog.Sink{
			&honeylog.StderrSink{},
			honeylog.NewWebhookSink(*honeyURL),
		}}
		obs.Info("honey webhook enabled", "url", *honeyURL)
	}

	apiServer := &api.Server{
		Log:       logInst,
		HoneySink: honeySink,
		Limits: api.Limits{
			AppendBodyBytes: *appendBodyMax,
			AdminBodyBytes:  *adminBodyMax,
		},
		IngestPolicy: api.IngestPolicy{
			MaxConcurrentAppends: *maxConcurrentAppends,
			PerProducerRPS:       *perProducerRPS,
			PerProducerBurst:     *perProducerBurst,
			PerAdminRPS:          *perAdminRPS,
			PerAdminBurst:        *perAdminBurst,
			RetryAfter:           *retryAfter,
		},
	}

	if *readLog {
		var rl *readlog.Journal
		var err error
		if *pqMode == "hybrid" {
			rl, err = readlog.OpenHybrid(filepath.Join(*dir, "read-log"))
		} else {
			rl, err = readlog.Open(filepath.Join(*dir, "read-log"))
		}
		if err != nil {
			return fmt.Errorf("read log: %w", err)
		}
		apiServer.ReadLog = rl
		mode := "classical"
		if rl.IsHybrid() {
			mode = "hybrid"
		}
		obs.Info("read log enabled", "events_at_startup", rl.Size(), "mode", mode)
	}

	// Admin audit log is always on — it records the rules-mutating
	// actions (rotate / producer / witness / threshold) on a separate
	// hash-chained signed journal. If anyone disables it via a CLI
	// flag in the future, the journal CAN replay forward but cannot
	// retroactively cover the gap.
	var alJournal *adminlog.Journal
	{
		var err error
		if *pqMode == "hybrid" {
			alJournal, err = adminlog.OpenHybrid(filepath.Join(*dir, "admin-log"))
		} else {
			alJournal, err = adminlog.Open(filepath.Join(*dir, "admin-log"))
		}
		if err != nil {
			return fmt.Errorf("admin log: %w", err)
		}
		apiServer.AdminLog = alJournal
		mode := "classical"
		if alJournal.IsHybrid() {
			mode = "hybrid"
		}
		obs.Info("admin log enabled", "events_at_startup", alJournal.Size(), "mode", mode)
	}

	var wd *watchdog.Watchdog
	if *rotateEvery > 0 || *watchKeyDir || *watchRate {
		wdCfg := watchdog.Config{
			Interval:          *rotateEvery,
			MinDebounce:       *watchDebounce,
			EnableRateMonitor: *watchRate,
			EventSink: func(ev watchdog.Event) {
				attrs := []any{
					"reason", string(ev.Reason),
					"success", ev.Success,
				}
				if ev.Detail != "" {
					attrs = append(attrs, "detail", ev.Detail)
				}
				if ev.Err != "" {
					attrs = append(attrs, "err", ev.Err)
				}
				obs.Info("watchdog event", attrs...)
			},
		}
		if *watchKeyDir {
			wdCfg.KeyDir = keyDir
		}
		var err error
		wd, err = watchdog.Start(ctx, logInst, wdCfg)
		if err != nil {
			return fmt.Errorf("watchdog start: %w", err)
		}
		obs.Info("watchdog enabled",
			"rotate_every", rotateEvery.String(),
			"watch_keys", *watchKeyDir,
			"watch_rate", *watchRate)
		if *watchRate {
			apiServer.AppendObserver = wd.ObserveAppend
		}
	}

	// TLS configuration.
	tlsCfg, useTLS, err := buildTLSConfig(*tlsCert, *tlsKey, *clientCA)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	if useTLS && *clientCA != "" {
		apiServer.RequireClientCertCN = *tlsRequireCN
		obs.Info("mTLS enabled", "client_ca", *clientCA)
	} else if useTLS {
		obs.Info("TLS enabled (no client cert verification)")
	}

	mux := api.NewMux(apiServer)
	obs.Mount(mux)
	apiServer.StartJanitor(ctx, 5*time.Minute, 1*time.Hour)
	logInst.StartEnrollmentJanitor(ctx, 1*time.Minute)

	// Readiness probes: chain loaded, store responsive, witness quorum
	// reachable (if witnesses are registered). /readyz returns 503 until
	// these pass — orchestrators should withhold traffic until then.
	obs.RegisterProbe("chain", func(_ context.Context) error {
		if logInst == nil || signer == nil || signer.Chain() == nil {
			return errors.New("chain not initialised")
		}
		return nil
	})
	obs.RegisterProbe("store", func(_ context.Context) error {
		if st == nil {
			return errors.New("store not initialised")
		}
		return nil
	})

	// Surface chain identity to gauges so /metrics reflects state at scrape time.
	obs.ActiveEpoch.Set(float64(signer.Chain().ActiveEpoch()))
	obs.TreeSize.Set(float64(logInst.Size()))
	// Background ticker that advances LastAnchorAgeSeconds between writes.
	obs.StartAnchorAgeTicker(ctx)
	// Continuous integrity check (tripwire). On detected tamper this
	// fires the alert path; the operator should follow RECOVERY.md §4.
	if *tripwireEvery > 0 {
		tripwire.Start(ctx, st, logInst, tripwire.Config{
			Interval: *tripwireEvery,
			OnTamper: func(r *tripwire.Result) {
				obs.Error("TRIPWIRE FIRED — refusing to consider log integrity intact",
					"size", r.Size,
					"first_failure_index", r.FirstFailureIndex,
					"expected_root", fmt.Sprintf("%x", r.ExpectedRoot),
					"derived_root", fmt.Sprintf("%x", r.DerivedRoot),
					"runbook", "see RECOVERY.md §4 (Detected tampering)")
			},
		})
		obs.Info("tripwire enabled", "interval", tripwireEvery.String())
	}

	srv := httpx.NewServer(*addr, mux, httpx.DefaultTimeouts)
	srv.TLSConfig = tlsCfg

	obs.Info("steled ready",
		"origin", signer.Origin(),
		"dir", *dir,
		"addr", *addr,
		"tree_size", logInst.Size(),
		"epoch", signer.Chain().ActiveEpoch(),
		"key_id", fwdsec.KeyID(signer.Public()),
		"anchor_file", *anchorPath)

	// Graceful shutdown coordinator. Three phases on SIGTERM:
	//   1. Flip the "draining" flag → /readyz starts failing → load
	//      balancers stop routing new traffic to us.
	//   2. Sleep `lbDrain` so the LB observes the failure on its next
	//      health-check tick.
	//   3. srv.Shutdown waits for in-flight handlers to finish (up to
	//      `httpDrain`), then closes the listener.
	//
	// Storage close (Badger fsync) is handled by the deferred st.Close
	// up the stack; the watchdog is stopped last so its rotations
	// can't race the close.
	var draining atomic.Bool
	obs.RegisterProbe("not_draining", func(_ context.Context) error {
		if draining.Load() {
			return errors.New("draining for shutdown")
		}
		return nil
	})
	const (
		lbDrain   = 2 * time.Second  // give LBs one health-check cycle
		httpDrain = 30 * time.Second // max wait for in-flight Appends
	)
	go func() {
		<-ctx.Done()
		obs.Info("shutdown initiated; failing /readyz to drain load balancer", "lb_drain", lbDrain.String())
		draining.Store(true)
		time.Sleep(lbDrain)
		obs.Info("closing listener; waiting for in-flight handlers", "http_drain", httpDrain.String())
		shutdownCtx, c := context.WithTimeout(context.Background(), httpDrain)
		defer c()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			obs.Warn("http server shutdown reported error", "err", err)
		}
		if wd != nil {
			wd.Stop()
		}
	}()

	var serveErr error
	if tlsCfg != nil {
		serveErr = srv.ListenAndServeTLS("", "") // cert/key already in TLSConfig
	} else {
		serveErr = srv.ListenAndServe()
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	obs.Info("steled shutdown complete")
	return nil
}

// buildTLSConfig assembles a *tls.Config from steled's flags. Returns
// (nil, false, nil) if no TLS flags are set.
func buildTLSConfig(certPath, keyPath, clientCAPath string) (*tls.Config, bool, error) {
	if certPath == "" && keyPath == "" && clientCAPath == "" {
		return nil, false, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, false, errors.New("--tls-cert and --tls-key must both be set")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, false, fmt.Errorf("load TLS keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // TLS 1.3 only; older versions allow downgrade
	}
	if clientCAPath != "" {
		caPEM, err := os.ReadFile(clientCAPath)
		if err != nil {
			return nil, false, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, false, errors.New("client CA PEM contained no usable certs")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, true, nil
}

// thresholdRotatorShim adapts a *threshold.Coordinator to the
// fwdsec.ThresholdRotator interface (the Coordinator exposes Group as
// a field rather than a method).
type thresholdRotatorShim struct {
	coord *threshold.Coordinator
}

func (s *thresholdRotatorShim) Sign(ctx context.Context, msg []byte, label string) ([]*threshold.MemberSig, error) {
	return s.coord.Sign(ctx, msg, label)
}

func (s *thresholdRotatorShim) Group() *threshold.Group { return s.coord.Group }

// loadThresholdGroup reads a group.json from disk, validates it, and
// ensures Origin matches the operator's --origin flag (so a typo
// can't accidentally bind the wrong group).
func loadThresholdGroup(path, origin string) (*threshold.Group, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read threshold group: %w", err)
	}
	g, err := threshold.Unmarshal(buf)
	if err != nil {
		return nil, fmt.Errorf("parse threshold group: %w", err)
	}
	if g.Origin != origin {
		return nil, fmt.Errorf("threshold group origin %q does not match operator --origin %q", g.Origin, origin)
	}
	return g, nil
}

// hsmFlags bundles the HSM-related command-line flags so loadOrInitSigner
// keeps a tight signature.
type hsmFlags struct {
	Module    string
	Slot      uint
	PIN       string
	KeyPrefix string
}

func (h hsmFlags) enabled() bool { return h.Module != "" }

// resolveHSMPIN prefers the explicit --hsm-pin flag; otherwise falls back
// to the environment variable named by --hsm-pin-env. Empty value means
// "no PIN" and is fine for HSMs configured with public-token semantics.
func resolveHSMPIN(flagVal, envVar string) string {
	if flagVal != "" {
		return flagVal
	}
	if envVar != "" {
		return os.Getenv(envVar)
	}
	return ""
}

// loadOrInitSigner opens the forward-secure signer at keyDir, creating
// the genesis epoch on first run if --init is supplied. If hsmFlags
// indicate an HSM module, signing keys live inside the HSM and never
// touch disk; only chain.json (with public keys + active locator) is
// persisted under keyDir. If hybrid is true, the key store also
// generates Dilithium3 keys per epoch for post-quantum-protected
// signatures.
//
// Returns a *checkpoint.Signer and an optional closer that releases the
// HSM session (nil for the file-backed signer).
func loadOrInitSigner(origin, keyDir string, initialise, hybrid bool, flags hsmFlags) (*checkpoint.Signer, func(), error) {
	chainPath := filepath.Join(keyDir, "chain.json")
	if _, err := os.Stat(chainPath); errors.Is(err, os.ErrNotExist) {
		if !initialise {
			return nil, nil, fmt.Errorf("no key chain at %s (use --init to generate one)", chainPath)
		}
	}

	var (
		fws    *fwdsec.Signer
		closer func()
	)
	if flags.enabled() {
		store, err := hsm.Open(hsm.Config{
			Module:    flags.Module,
			SlotID:    flags.Slot,
			PIN:       flags.PIN,
			KeyPrefix: flags.KeyPrefix,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("open HSM: %w", err)
		}
		fws, err = fwdsec.NewSignerWithStore(origin, keyDir, store)
		if err != nil {
			_ = store.Close()
			return nil, nil, err
		}
		closer = func() { _ = store.Close() }
		obs.Info("signing keys backed by HSM", "module", flags.Module, "slot", flags.Slot)
	} else {
		var store *fwdsec.FileKeyStore
		var err error
		if hybrid {
			store, err = fwdsec.NewFileKeyStoreHybrid(keyDir)
		} else {
			store, err = fwdsec.NewFileKeyStore(keyDir)
		}
		if err != nil {
			return nil, nil, err
		}
		fws, err = fwdsec.NewSignerWithStore(origin, keyDir, store)
		if err != nil {
			return nil, nil, err
		}
		if hybrid {
			obs.Info("signing keys on disk (hybrid)", "scheme", "Ed25519+Dilithium3")
		} else {
			obs.Info("signing keys on disk (classical)", "hint", "consider --hsm-module for production")
		}
	}

	// (Re-)write the root public key file so it stays available next to
	// the daemon directory regardless of where the private bytes live.
	rootPath := filepath.Join(keyDir, "root.pub")
	enc := base64.StdEncoding.EncodeToString(fws.RootPublicKey())
	if err := os.WriteFile(rootPath, []byte(enc+"\n"), 0o644); err != nil {
		if closer != nil {
			closer()
		}
		return nil, nil, err
	}
	return checkpoint.NewSigner(fws), closer, nil
}

func schedule(ctx context.Context, every time.Duration, label string, fn func() error) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := fn(); err != nil {
				obs.Error("scheduled task failed", "task", label, "err", err)
			}
		}
	}
}
