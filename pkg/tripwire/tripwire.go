// Package tripwire continuously re-derives the Merkle root from
// BadgerDB and compares it to the operator's most-recent stored
// checkpoint. If anyone modifies a stored entry out of band (an
// attacker with disk access, a buggy ops script, a misconfigured
// backup-restore), the derived root no longer matches the committed
// root, and tripwire fires.
//
// This complements the anchor — the anchor proves to the *outside
// world* that the log is consistent, but only at anchor cadence.
// Tripwire proves consistency to the *operator themselves* at a much
// tighter cadence, so an internal incident does not have to wait for
// the next public anchor to be detected.
//
// Cost: each run streams every entry from `0..size` through SHA-256.
// On a 1M-entry log this is sub-second on modern hardware; on a 1B
// entry log this should be re-architected with a Merkle-tree cache or
// run incrementally. For v1, the simple full scan is fine.
package tripwire

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/logentry"
	"github.com/desledishant10/stele/pkg/merkle"
	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/storage"
)

// Result captures one tripwire run.
type Result struct {
	At                time.Time
	Size              uint64
	ExpectedRoot      []byte
	DerivedRoot       []byte
	Tamper            bool
	FirstFailureIndex int64 // -1 if no per-entry hash chain break
	Err               error
}

// CheckpointSource is the small surface tripwire needs to know "what's
// the latest signed root we committed?" — implemented by core.Log.
type CheckpointSource interface {
	LatestCheckpoint() (*checkpoint.Checkpoint, error)
}

// Run performs ONE consistency pass: re-derive the Merkle root from
// stored entries `[0, size)` and compare against `expectedRoot`. Also
// re-verifies every entry's hash-chain link (PrevHash + EntryHash) so a
// modification that re-hashes the leaf but breaks the chain is still
// caught. Returns (result, nil) on success — a (result, nil) where
// result.Tamper == true is the alarm condition.
func Run(ctx context.Context, store *storage.Store, size uint64, expectedRoot []byte) (*Result, error) {
	res := &Result{At: time.Now(), Size: size, ExpectedRoot: expectedRoot, FirstFailureIndex: -1}
	if size == 0 {
		// Empty log has the RFC 6962 empty root.
		res.DerivedRoot = merkle.Hasher.EmptyRoot()
		res.Tamper = !bytesEqual(res.DerivedRoot, expectedRoot)
		return res, nil
	}

	tree := merkle.NewTree()
	var prev *logentry.Entry
	err := store.IterateEntries(ctx, 0, func(e *logentry.Entry) error {
		if e.Index >= size {
			return errStopIter
		}
		// 1. Per-entry self-consistency: EntryHash and LeafHash must
		//    re-derive from the canonical bytes on the entry. Catches
		//    "attacker modified Envelope.Data but didn't recompute
		//    hashes" (a tamper-via-replace).
		if err := e.Verify(); err != nil {
			res.Tamper = true
			res.FirstFailureIndex = int64(e.Index)
			return errStopIter
		}
		// 2. Per-entry chain link: PrevHash must equal the previous
		//    entry's EntryHash. Catches "attacker rewrote two entries
		//    so each self-verifies but the chain is broken."
		if err := e.VerifyChain(prev); err != nil {
			res.Tamper = true
			res.FirstFailureIndex = int64(e.Index)
			return errStopIter
		}
		tree.AppendLeafHash(e.LeafHash)
		prev = e
		return nil
	})
	if err != nil && !errors.Is(err, errStopIter) {
		res.Err = err
		return res, err
	}

	if res.Tamper {
		// Don't bother computing root once a per-entry break is known —
		// the chain is broken and reporting "root differs" is redundant.
		return res, nil
	}
	if tree.Size() != size {
		res.Err = fmt.Errorf("tripwire: iterated %d entries, expected %d", tree.Size(), size)
		return res, res.Err
	}
	res.DerivedRoot = tree.Root()
	res.Tamper = !bytesEqual(res.DerivedRoot, expectedRoot)
	return res, nil
}

// errStopIter is an internal sentinel to stop IterateEntries early
// without it being treated as a real error by callers.
var errStopIter = errors.New("tripwire: stop iteration")

// Config controls the background runner.
type Config struct {
	// Interval between scheduled runs. Zero or negative disables the
	// scheduled runner; callers can still invoke Run directly.
	Interval time.Duration

	// OnTamper, if set, is called when tripwire detects a mismatch.
	// Implementations should at minimum: persist the Result to durable
	// storage and notify the operator out-of-band (PagerDuty, Slack,
	// email). The default behavior on nil is to log+metric only.
	OnTamper func(*Result)
}

// Start launches a goroutine that runs Run every cfg.Interval against
// store using the latest stored checkpoint's Size + Root. Returns
// nothing — the caller stops the loop by cancelling ctx.
//
// Each pass updates:
//   - obs.Logger (info on ok, error on tamper)
//   - the stele_tripwire_runs_total counter (registered in pkg/obs)
//
// If no checkpoint exists yet, the run is skipped (nothing to compare
// against). Same if the log is empty.
func Start(ctx context.Context, store *storage.Store, src CheckpointSource, cfg Config) {
	if cfg.Interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				runOnce(ctx, store, src, cfg)
			}
		}
	}()
}

func runOnce(ctx context.Context, store *storage.Store, src CheckpointSource, cfg Config) {
	c, err := src.LatestCheckpoint()
	if err != nil {
		obs.Error("tripwire: read latest checkpoint failed", "err", err)
		obs.TripwireRunsTotal.WithLabelValues("error").Inc()
		return
	}
	if c == nil {
		// No checkpoint yet — nothing to compare against.
		obs.TripwireRunsTotal.WithLabelValues("skipped").Inc()
		return
	}
	res, err := Run(ctx, store, c.Size, c.RootHash)
	if err != nil {
		obs.Error("tripwire: run failed", "err", err, "size", c.Size)
		obs.TripwireRunsTotal.WithLabelValues("error").Inc()
		return
	}
	if res.Tamper {
		obs.Error("TRIPWIRE: log integrity FAILURE — stored entries no longer match committed root",
			"size", c.Size,
			"first_failure_index", res.FirstFailureIndex,
			"expected_root", fmt.Sprintf("%x", res.ExpectedRoot),
			"derived_root", fmt.Sprintf("%x", res.DerivedRoot))
		obs.TripwireRunsTotal.WithLabelValues("tamper").Inc()
		if cfg.OnTamper != nil {
			cfg.OnTamper(res)
		}
		return
	}
	obs.Debug("tripwire ok", "size", c.Size)
	obs.TripwireRunsTotal.WithLabelValues("ok").Inc()
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
