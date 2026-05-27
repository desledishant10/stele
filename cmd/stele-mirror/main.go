// stele-mirror is the read-only replica daemon. Point it at a stele
// operator's upstream URL and it will pull every entry, verify the
// producer signature + chain integrity, persist to a local BadgerDB,
// and serve a strict subset of the same API (entries, size,
// mirror-status).
//
// Run multiple mirrors on independent infrastructure for the strongest
// selective-disclosure resistance.
//
// Quickstart:
//
//	stele-mirror --dir ./mirror-data \
//	    --upstream https://stele.example.com:8443 \
//	    --addr :8444
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/desledishant10/stele/pkg/httpx"
	"github.com/desledishant10/stele/pkg/mirror"
	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/storage"
)

// Set via `-ldflags "-X main.version=... -X main.commit=..."`.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	obs.Init("mirror", nil)
	obs.SetBuildInfo(version, commit)
	if err := run(); err != nil {
		obs.Fatal("stele-mirror startup failed", "err", err)
	}
}

func run() error {
	addr := flag.String("addr", ":8444", "HTTP listen address")
	dir := flag.String("dir", "", "data directory (required)")
	upstream := flag.String("upstream", "", "operator base URL (required)")
	poll := flag.Duration("poll", 30*time.Second, "how often to pull new entries upstream")
	chunk := flag.Uint64("chunk", 256, "entries per upstream HTTP call")
	tlsCA := flag.String("tls-ca", "", "PEM file of CAs to trust for upstream (optional)")
	skipVerify := flag.Bool("tls-skip-verify", false, "skip upstream cert verification (DEV ONLY)")
	flag.Parse()
	if *dir == "" || *upstream == "" {
		flag.Usage()
		os.Exit(2)
	}

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	storeDir := filepath.Join(*dir, "db")
	st, err := storage.Open(storeDir)
	if err != nil {
		return err
	}
	defer st.Close()

	httpClient, err := buildClient(*tlsCA, *skipVerify)
	if err != nil {
		return err
	}

	m, err := mirror.New(mirror.Config{
		Upstream:  *upstream,
		HTTP:      httpClient,
		PollEvery: *poll,
		ChunkSize: *chunk,
	}, st)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	m.Start(ctx)

	mux := mirror.NewMux(m)
	obs.Mount(mux)
	srv := httpx.NewServer(*addr, mux, httpx.DefaultTimeouts)
	go func() {
		<-ctx.Done()
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
	}()

	obs.Info("stele-mirror ready",
		"upstream", *upstream,
		"dir", *dir,
		"addr", *addr,
		"mirrored_size", m.Size())
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	obs.Info("stele-mirror shutdown complete")
	return nil
}

func buildClient(caPath string, skipVerify bool) (*http.Client, error) {
	if caPath == "" && !skipVerify {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: skipVerify, //nolint:gosec
	}
	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("CA file contained no certs")
		}
		cfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg},
	}, nil
}
