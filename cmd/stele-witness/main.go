// stele-witness is a tiny daemon that countersigns checkpoints from one or
// more stele operators. Run it on infrastructure independent from any
// operator you watch.
//
// With --gossip-every set, the witness also pulls every peer witness's
// seen map periodically and refuses to keep cosigning for an operator
// that has produced contradictory checkpoints — closing the
// "split-brain operator" attack.
package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/desledishant10/stele/pkg/httpx"
	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/witness"
)

// Set via `-ldflags "-X main.version=... -X main.commit=..."`.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	obs.Init("witness", nil)
	obs.SetBuildInfo(version, commit)

	addr := flag.String("addr", ":9090", "HTTP listen address")
	dir := flag.String("dir", "", "data directory (required)")
	id := flag.String("id", "", "human label for this witness (required)")
	gossipEvery := flag.Duration("gossip-every", 0, "how often to pull peer witnesses for fork detection (0 disables)")
	pqMode := flag.String("pq-mode", "classical", "post-quantum mode: 'classical' or 'hybrid' (Ed25519 + Dilithium3)")
	flag.Parse()
	if *dir == "" || *id == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *pqMode != "classical" && *pqMode != "hybrid" {
		obs.Fatal("invalid --pq-mode", "value", *pqMode, "expected", "classical|hybrid")
	}

	var w *witness.Server
	var err error
	if *pqMode == "hybrid" {
		w, err = witness.NewHybridServer(*id, *dir)
	} else {
		w, err = witness.NewServer(*id, *dir)
	}
	if err != nil {
		obs.Fatal("witness startup failed", "err", err)
	}
	if w.IsHybrid() {
		obs.Info("hybrid mode active", "scheme", "Ed25519+Dilithium3")
	}

	mux := witness.NewMux(w)
	obs.Mount(mux)

	srv := httpx.NewServer(*addr, mux, httpx.DefaultTimeouts)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *gossipEvery > 0 {
		w.StartGossip(ctx, witness.GossipConfig{
			Interval: *gossipEvery,
			EventSink: func(ev *witness.ForkEvidence) {
				obs.Error("fork detected",
					"origin", ev.Origin,
					"size", ev.Size,
					"peer", ev.TheirPeerID)
			},
		})
		obs.Info("gossip enabled", "interval", gossipEvery.String())
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
	}()

	obs.Info("stele-witness ready",
		"id", w.ID(),
		"addr", *addr,
		"key_id", w.KeyID(),
		"watching", len(w.ListOperators()),
		"peers", len(w.ListPeers()))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		obs.Fatal("witness serve failed", "err", err)
	}
	obs.Info("stele-witness shutdown complete")
}
