// stele-watcher is the independent cross-checker. It fetches the
// latest checkpoint from a stele operator + every named witness's
// signed view of that operator's log, and reports any disagreement.
//
// Use cases:
//
//   - Scheduled CI job, e.g. nightly: run with --once and exit code 1
//     on divergence; the CI alert path becomes the page-on-fork
//     signal.
//   - Sidecar daemon (--interval 10m): same checks on a tight loop;
//     emits stele_watcher_* Prometheus metrics so an alert manager
//     can fan out.
//
// stele-watcher is INTENTIONALLY independent from both the operator
// and the witness mesh — it relies on neither for its evidence and
// can run on infrastructure neither controls. That's the point: if
// every operator and every witness colluded, the watcher would
// still detect divergence at the next public-anchor cycle (and
// the operator's view in particular).
//
// Exit codes:
//
//	0  all sources reported the same root at the operator-claimed size
//	1  divergence detected — a real fork
//	2  one or more sources unreachable; no fork claim made
//	3  bad arguments / startup error
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/watcher"
)

// Set via `-ldflags "-X main.version=... -X main.commit=..."`.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	obs.Init("watcher", nil)
	obs.SetBuildInfo(version, commit)
	if err := run(); err != nil {
		obs.Fatal("stele-watcher failed", "err", err)
	}
}

func run() error {
	var (
		origin   = flag.String("origin", "", "operator log origin (required)")
		operator = flag.String("operator", "", "operator base URL (required)")
		witnesses = flag.String("witnesses", "", "comma-separated witness base URLs (required for meaningful cross-check)")
		once     = flag.Bool("once", true, "run a single pass and exit (CI mode); set --once=false + --interval for daemon mode")
		interval = flag.Duration("interval", 10*time.Minute, "with --once=false, time between passes")
		timeout  = flag.Duration("timeout", 10*time.Second, "per-HTTP-call timeout")
		jsonOut  = flag.Bool("json", false, "emit each report as JSON on stdout (machine-readable)")
	)
	flag.Parse()

	if *origin == "" || *operator == "" {
		return errors.New("stele-watcher: --origin and --operator are required")
	}

	var urls []string
	for _, u := range strings.Split(*witnesses, ",") {
		if u = strings.TrimSpace(u); u != "" {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		obs.Warn("no witnesses configured; watcher will only confirm the operator is reachable",
			"hint", "pass --witnesses w1,w2,w3 for a real cross-check")
	}

	cfg := watcher.Config{
		Origin:      *origin,
		OperatorURL: *operator,
		WitnessURLs: urls,
		Timeout:     *timeout,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *once {
		_, code := runOnceAndPrint(ctx, cfg, *jsonOut)
		os.Exit(code)
	}

	obs.Info("stele-watcher daemon mode", "interval", interval.String())
	t := time.NewTicker(*interval)
	defer t.Stop()
	// One pass immediately, then on the ticker.
	runOnceAndPrint(ctx, cfg, *jsonOut)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			runOnceAndPrint(ctx, cfg, *jsonOut)
		}
	}
}

func runOnceAndPrint(ctx context.Context, cfg watcher.Config, asJSON bool) (*watcher.Report, int) {
	rep, outcome, err := watcher.Run(ctx, cfg)
	if err != nil {
		obs.Error("watcher pass aborted before any check", "err", err)
		return nil, 3
	}

	if asJSON {
		body, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(body))
	} else {
		printHuman(rep, outcome)
	}

	switch outcome {
	case watcher.OutcomeConsistent:
		obs.Info("watcher: all sources agree",
			"size", rep.OperatorView.Size,
			"root", rep.OperatorView.RootHex)
		return rep, 0
	case watcher.OutcomeDiverged:
		obs.Error("watcher: FORK DETECTED",
			"divergences", len(rep.Divergences),
			"size", rep.OperatorView.Size)
		return rep, 1
	case watcher.OutcomeErrored:
		obs.Warn("watcher: sources unreachable, no consistency claim possible")
		return rep, 2
	}
	return rep, 2
}

func printHuman(rep *watcher.Report, outcome watcher.Outcome) {
	fmt.Println("============================================================")
	fmt.Printf("Stele watcher report — %s\n", rep.At.Format(time.RFC3339))
	fmt.Printf("origin       : %s\n", rep.Origin)
	fmt.Printf("outcome      : %s\n", outcome)
	fmt.Println("------------------------------------------------------------")
	if rep.OperatorView != nil {
		if rep.OperatorView.Reachable {
			fmt.Printf("OPERATOR: size=%d root=%s\n", rep.OperatorView.Size, short(rep.OperatorView.RootHex))
		} else {
			fmt.Printf("OPERATOR: UNREACHABLE (%s)\n", rep.OperatorView.ErrMessage)
		}
	}
	for _, w := range rep.WitnessViews {
		switch {
		case !w.Reachable:
			fmt.Printf("  %s: UNREACHABLE (%s)\n", w.Name, w.ErrMessage)
		case w.RootHex == "":
			fmt.Printf("  %s: behind (no view at size %d)\n", w.Name, w.Size)
		default:
			fmt.Printf("  %s: size=%d root=%s\n", w.Name, w.Size, short(w.RootHex))
		}
	}
	if len(rep.Divergences) > 0 {
		fmt.Println("------------------------------------------------------------")
		fmt.Println("!!! FORK !!!")
		for _, d := range rep.Divergences {
			fmt.Printf("  source=%s size=%d\n", d.Source, d.Size)
			fmt.Printf("    operator root: %s\n", short(d.OperatorRoot))
			fmt.Printf("    source   root: %s\n", short(d.SourceRoot))
		}
	}
	fmt.Println("============================================================")
}

func short(s string) string {
	if len(s) > 24 {
		return s[:24] + "..."
	}
	return s
}
