// stele-cosigner is a tiny daemon that holds one threshold-group
// member's Ed25519 signing key and serves SIGN requests over HTTP.
//
// Run one cosigner per group member, on independent infrastructure.
// The operator's stele daemon coordinates the t-of-N collection.
//
// Quickstart:
//
//	stele-cosigner --dir ./cosigner-alice --id alice --addr :9101
//
// Inspect the public key:
//
//	curl http://localhost:9101/cosigner/v0/identity
//
// For production, run behind mTLS terminating in front of this daemon
// (the operator authenticates with a client cert) and set
// --trusted-caller to the expected token for defence in depth.
package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/desledishant10/stele/pkg/httpx"
	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/threshold"
)

// Set via `-ldflags "-X main.version=... -X main.commit=..."`.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	obs.Init("cosigner", nil)
	obs.SetBuildInfo(version, commit)

	addr := flag.String("addr", ":9101", "HTTP listen address")
	dir := flag.String("dir", "", "data directory (required)")
	id := flag.String("id", "", "member ID (must match the group entry; required)")
	callers := flag.String("trusted-caller", "", "comma-separated X-Stele-Caller tokens to accept; empty = allow all (DEV ONLY)")
	pqMode := flag.String("pq-mode", "classical", "post-quantum mode: 'classical' or 'hybrid' (Ed25519 + Dilithium3)")
	flag.Parse()
	if *dir == "" || *id == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *pqMode != "classical" && *pqMode != "hybrid" {
		obs.Fatal("invalid --pq-mode", "value", *pqMode, "expected", "classical|hybrid")
	}

	var trusted []string
	if *callers != "" {
		for _, t := range strings.Split(*callers, ",") {
			if s := strings.TrimSpace(t); s != "" {
				trusted = append(trusted, s)
			}
		}
	}

	var c *threshold.Cosigner
	var err error
	if *pqMode == "hybrid" {
		c, err = threshold.NewHybridCosigner(*id, *dir, trusted)
	} else {
		c, err = threshold.NewCosigner(*id, *dir, trusted)
	}
	if err != nil {
		obs.Fatal("stele-cosigner startup failed", "err", err)
	}
	if c.IsHybrid() {
		obs.Info("hybrid mode active", "scheme", "Ed25519+Dilithium3")
	}

	mux := threshold.NewMux(c)
	obs.Mount(mux)
	srv := httpx.NewServer(*addr, mux, httpx.DefaultTimeouts)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancelShut := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShut()
		_ = srv.Shutdown(shutdownCtx)
	}()

	obs.Info("stele-cosigner ready",
		"id", c.ID(),
		"addr", *addr,
		"key_id", c.KeyID(),
		"trusted_callers", len(trusted))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		obs.Fatal("cosigner serve failed", "err", err)
	}
	obs.Info("stele-cosigner shutdown complete")
}
