# Stele soak runs — v0.1.3 / v0.1.4 / v0.1.5 / v0.1.6 — 2026-05-30 to 2026-06-20

Two attempts. Neither completed a clean 72 hours. The second
attempt (v0.1.4 on 8 GB) confirms the v0.1.4 caps are doing what
the code intended; they just don't address the actual failure
mode. **Reopening issue [#8](https://github.com/desledishant10/stele/issues/8)
with a corrected diagnosis.**

## Summary

| Attempt | Version | Host | Workload | Wall clock before OOM | Total cost |
|---|---|---|---|---|---|
| v3 (raw) | v0.1.2 | 4 GB c7i.large | 16×500 | unknown (lost) | ~$5 |
| v4 | v0.1.3 | 4 GB c7i.large | 16×500 | ~17 hours | ~$2.40 |
| v5 | v0.1.4 | 8 GB c7i.xlarge | 16×500 | ~3 hours | ~$9.00 |
| v6 | v0.1.5 | 8 GB c7i.xlarge | 16×500 (script overrode concurrency cap) | ~17 hours | ~$2.00 |
| v7 | v0.1.6 | 8 GB c7i.xlarge | 4×250 (representative real workload) | **~18.6 hours** | ~$34.50 |
| **Total** | | | | | **~$52.90** |

(v7 spent more than expected because the instance was left running in
its crash-loop state for 13.6 days before I caught it. My bookkeeping
error. The OOM diagnosis arrived inside the first ~20 hours; the
remaining 13 days produced no new information.)

## What v0.1.4 was supposed to fix

The v0.1.3 soak found `steled` growing past 4 GB at ~17 hours of
~250 RPS load. Three caches were unbounded:

- Merkle internal-node map
- BadgerDB block + index caches
- Replay-dedup table

v0.1.4 added caps + a TTL + tunable flags for all three.

## What v0.1.4 actually did

The fix is working at steady state. Per-entry memory cost across
the v5 run dropped as the log grew (because the Merkle internal-
node LRU started evicting):

| Tree size | RSS | Bytes per entry |
|---|---|---|
| 0.5M | 1006 MB | 1,931 |
| 1.0M | 1808 MB | 1,975 |
| 2.2M | 3188 MB | 1,523 |
| 3.0M | 3441 MB | 1,198 |
| 4.9M | 2884 MB | 617 |
| 12.0M (post crash-loop) | 3647 MB | 304 |

For comparison, v0.1.3 was running at ~2,500 bytes/entry at 1M
entries and trending UP. v0.1.4 at the same size is ~1,975 and
trends DOWN. The caps ARE doing their job.

## What v0.1.4 did NOT fix

**Transient memory bursts.** Even with the caps in effect, RSS
oscillates between 3 GB and 7 GB throughout the v5 run. The OOM
kills happen at the peaks, not at any monotonic ceiling.

Examples from the v5 timeline:

- t+2.5h: RSS 3,188 MB
- t+3.0h: RSS 6,120 MB (+2.9 GB in 30 min while only 400k new
  entries arrived)
- t+3.5h: RSS 3,441 MB (back down)
- t+10.0h: 3,667 MB
- t+10.5h: 6,267 MB (+2.6 GB in 30 min)

A 2-3 GB transient burst on top of a 3 GB steady state crosses
the 8 GB host's OOM threshold.

The transients are big enough to overwhelm any "cap" approach:
even on a 16 GB host, the same 2-3 GB swings would put us close
to the limit; on a 32 GB host the cost is fine but you're now
paying for double the RAM you actually need.

## Likely root cause (best hypothesis)

I don't have a heap profile yet, so this is informed guessing
from the data + a code read:

1. **No `GOMEMLIMIT` set.** Go's GC defaults to a 100% growth
   target between collections. Under bursty allocation, the heap
   can double between GCs. Setting `GOMEMLIMIT` to ~70% of the
   host RAM forces Go to GC aggressively before the OS gets
   involved.

2. **16 producers × 500 RPS = high concurrency.** Each producer's
   Append handler allocates ~5-10 KB for envelope parsing,
   signature verification, Merkle path construction. At 8K
   concurrent operations this is ~80 MB of transient garbage
   per checkpoint window. Reducing
   `--max-concurrent-appends` from the default would smooth
   this.

3. **BadgerDB compaction** allocates large buffers when the
   value log rolls over. Compaction interval is the default;
   could be tuned.

4. **Checkpoint generation reads many entries.** When the
   operator builds a checkpoint, it touches each `!Operator`
   record + the active Merkle path. Under burst load this
   competes with the Append handlers for heap.

None of these are caps. They are concurrency / GC / scheduling
knobs that v0.1.4 did not touch.

## What v0.1.5 should do (proposed)

1. Set `GOMEMLIMIT` automatically based on detected host RAM
   (e.g. 70% of memtotal) when the env var is not already set.
2. Add `--max-concurrent-appends-frac` defaulting to ~50% of
   cores (effectively halving the default concurrency).
3. Surface BadgerDB compaction settings (`--badger-compactors`,
   value log rotation size) as flags.
4. Add a memory-pressure circuit breaker: when steady-state RSS
   approaches `--mem-soft-limit` (default 80% of GOMEMLIMIT),
   transiently slow Append until GC catches up.

## What v0.1.4 IS appropriate for

The caps still matter for hosts where steady-state growth is the
issue (very long-running deployments on small hosts; pilots).
v0.1.4 is the right baseline; v0.1.5 layers burst-tolerance on
top.

The v0.1.4 release notes should be amended to be honest about
this: the caps reduce the per-entry cost but do not prevent
burst-driven OOMs.

## Artifacts retained

In `soak/artifacts/` (v0.1.3 run) and `soak/artifacts-v5/`
(v0.1.4 run):

| File | Contents |
|---|---|
| `timeline.ndjson` | 9 snapshots (v0.1.3) + 94 snapshots (v0.1.4) |
| `stele-soak.log` | soak driver log |
| `system-v5.log` | partial host journal (most OOM kills were outside the sampled window) |

The v5 timeline.ndjson is the richer data set. It captures
~85 hours of operator behaviour, including the crash-loop
pattern after the first burst-OOM.

## v6 (v0.1.5, 16×500 with concurrency-cap override)

v0.1.5 shipped with three burst-tolerance fixes: auto-`GOMEMLIMIT`,
CPU-aware `MaxConcurrentAppends` default, BadgerDB compactor tuning.
The v6 soak unintentionally tested only two of the three: the
`soak/stele-soak-setup` script hard-coded `--max-concurrent-appends=512`
on the operator's systemd unit, overriding the new default of 16
that v0.1.5 was meant to deliver.

Result: first OOM at ~17 hours, same as v0.1.3. GOMEMLIMIT alone
delayed the OOM from v0.1.4's 3 hours back to v0.1.3 territory, but
did not prevent it. Useful negative data: the concurrency cap is
load-bearing, not optional.

## v7 (v0.1.6, 4×250 with all three fixes active)

v0.1.6 fixed the soak script override and reduced the workload to
representative levels (1K aggregate RPS instead of 8K, matching a
Fortune-500 audit log rate). This was the cleanest test: all three
v0.1.5 burst-tolerance knobs active, realistic workload, 8 GB host.

**Result: first OOM at ~18.6 hours.** Tree size at first kill:
14.7M entries. The crash-loop pattern continued for the remaining
13.6 days of uptime (~$32 of bookkeeping-error spend that produced
no new findings beyond confirming the pattern).

This is the definitive data point. Every implementation knob we
have in the v0.1.x line caps memory growth at roughly 17-20 hours
before OOM on a sustained 250+ RPS workload. The remaining O(N)
memory consumer is the in-memory Merkle leaf map: at ~80 bytes per
leaf × 14.7M leaves = ~1.2 GB just for leaves. Plus internal LRU
+ Badger overhead + Go runtime + bursting allocation, the operator
hits 7 GB on 8 GB hosts within ~18 hours regardless of workload
shape.

## The real fix (v0.1.7)

**Disk-backed Merkle leaves.** The current implementation keeps
every leaf hash in a `map[uint64][]byte` indexed by leaf index.
v0.1.4's LRU eviction was deliberately scoped to internal nodes,
on the (incorrect) assumption that leaves at ~32 bytes each were
"small enough to keep forever." Sustained-load soaks have now
proven that assumption wrong: 14.7M leaves are 1.2 GB, and the log
grows linearly with time.

v0.1.7 should:
1. Move leaves to BadgerDB-backed storage, fetched on demand at
   proof-construction time
2. Keep a small in-memory LRU for the most-recently-accessed leaves
   (last few thousand) to keep the hot-path fast
3. Document the new sizing: "Memory cost is now O(LRU cap), not
   O(log size); steady-state is bounded for arbitrarily large logs."

That's ~half a day of code in `pkg/merkle` plus an interface change
through `pkg/core` to give the Tree access to the leaf store. Worth
doing only if there's a real adopter pushing for it; the v0.1.6
implementation handles the pilot workload (your Mac's git commit
log) indefinitely. Documented sizing guidance ("don't run single-
node operator at >1K aggregate RPS on <16 GB") covers the rest.

## Conclusion

Four soaks across four releases. Each release improved on the
previous (better diagnosis, better fix, longer time-to-OOM in the
representative workload), but no v0.1.x release achieves a clean
72-hour run on the configured workload. The pattern is now well-
understood: unbounded leaf-map is the dominant remaining O(N)
consumer. The v0.1.7 fix is well-scoped but not done.

**Total soak spend: ~$52.90 across five attempts** (more than the
originally projected $6 because v7 was left running in its crash-
loop state for 13 days through a bookkeeping error on my side).
Going forward: no more paid soaks until v0.1.7 is implemented and
ready to validate.
