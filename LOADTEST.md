# Stele Load + Chaos Testing

This doc covers two related testing surfaces:

- **Load**: synthetic producer traffic via `stele-loadgen`, to measure
  throughput, latency tails, and ingest-guard backpressure.
- **Chaos**: deliberate fault injection (byzantine witnesses, clock
  skew, disk tampering) to confirm the protocol's defences fire.

For correctness testing (unit, race, fuzz, property tests) see
[HARDENING.md](HARDENING.md).

---

## 1. `stele-loadgen` — synthetic producer traffic

A single binary in [cmd/stele-loadgen](cmd/stele-loadgen/main.go) that:

1. Mints N fresh Ed25519 producer keypairs in memory.
2. Registers each via `/api/v0/producers`.
3. Runs for `--duration` at `--rps` aggregate target rate.
4. Classifies every response into one of: `ok`, `rate_limit` (429),
   `concurrency` (503), `body_too_large` (413), `client_4xx`,
   `server_5xx`, `timeout`, `network`.
5. Reports per-class latency percentiles (p50/p95/p99/p99.9) at the
   end, optionally to CSV and JSON for plotting/CI diff.

### Quickstart

```sh
# Start steled separately on :8080, then:
make build               # builds bin/stele-loadgen
./bin/stele-loadgen \
    --server  http://localhost:8080 \
    --producers 16 \
    --rps 800 \
    --duration 30s \
    --payload  96 \
    --concurrency 64 \
    --json out/run.json \
    --csv  out/run.csv
```

### Reading the output

A healthy run shows the bulk of requests as `ok` with bounded tail
latency, and any limiter rejections (`rate_limit` / `concurrency`)
returning in **sub-millisecond p50**. That fast-reject path is the
sign that ingest hardening is working: under pressure, garbage exits
quickly rather than queuing.

Example burst run against a steled with `--max-concurrent-appends 64
--per-producer-rps 200 --per-producer-burst 400`:

```
outcome                 count          p50          p95          p99        p99.9
----------------------------------------------------------------------------------
ok                      50922       1.75ms       8.76ms      40.93ms      92.69ms
rate_limit              21148        202µs        373µs        850µs        4.6ms
concurrency              1662        763µs      15.52ms      41.35ms      49.52ms
```

- `ok` p99 ~40 ms under pressure is fine; that's Badger fsync tail.
- `rate_limit` p50 = 202 µs — the 429 path doesn't even touch storage.
- `concurrency` p50 = 763 µs — slightly slower because the semaphore
  is contested, but still does no work.

If `ok` p99 starts trending into seconds, the operator is at its
real capacity — drop `--max-concurrent-appends` to push more to the
limiter rather than queueing inside the handler.

### Make targets

| Target | Equivalent |
|---|---|
| `make load-quick` | 30s, 200 rps, 8 producers — sanity smoke |
| `make load-burst` | 60s, 2000 rps, 32 producers, 128 concurrency — limiter exercise |

---

## 2. Chaos tests — deliberate fault injection

Three classes, all runnable from `make chaos`.

### 2.a Byzantine witness ([pkg/witness/chaos_test.go](pkg/witness/chaos_test.go))

| Test | Attack | Defence |
|---|---|---|
| `TestChaos_PeerSignsWithWrongKey` | Peer returns SignedSeen signed by an attacker's key, not the registered pubkey | gossip.go rejects on `bytesEqualLocal(stmt.PublicKey, peer.PublicKey)` check |
| `TestChaos_PeerClaimsWrongWitnessID` | Peer returns SignedSeen claiming `witness_id` of someone else | gossip.go rejects on `stmt.WitnessID != peer.ID` check |
| `TestChaos_PeerBitFlipSignature` | Otherwise-valid SignedSeen with a tampered Signature byte | `stmt.Verify()` fails ed25519 verification |
| `TestChaos_PeerReturnsGarbage` | Peer returns HTTP 500 / non-JSON body | gossip layer logs + skips |

Already-covered cases (from [pkg/witness/witness_test.go](pkg/witness/witness_test.go)):
- `TestCosignAcceptsThenRejectsFork` — operator forks; single witness detects
- `TestGossipDetectsForkAcrossWitnesses` — two witnesses see different roots; gossip detects
- `TestDishonestPeerContradictionIsAuditable` — peer mutates its seen map between rounds; honest peer records both signed contradictions

### 2.b Clock skew ([pkg/core/chaos_test.go](pkg/core/chaos_test.go))

| Test | Scenario | Expected |
|---|---|---|
| `TestChaos_ClockSkew_RefusesCheckpoint/ahead_by_6m_rejects` | Operator clock 6 min ahead of drand round | Refuse to checkpoint with error mentioning "clock" |
| `TestChaos_ClockSkew_RefusesCheckpoint/behind_by_6m_rejects` | Operator clock 6 min behind drand round | Refuse |
| `TestChaos_ClockSkew_RefusesCheckpoint/ahead_by_4m_passes` | Within `DefaultMaxClockSkew` tolerance | Checkpoint succeeds |
| `TestChaos_NonDrandBeaconSkipsCheck` | Beacon source is not "drand" | Skip the math (we don't know the chain genesis) |
| `TestChaos_BeaconUnreachable` | Fetcher returns error | Best-effort: checkpoint succeeds without a beacon field |

### 2.c Disk tampering ([pkg/tripwire/tripwire_test.go](pkg/tripwire/tripwire_test.go))

| Test | Attack | Defence |
|---|---|---|
| `TestRun_DetectsLeafMutation` | Attacker mutates `Envelope.Data` of one entry in BadgerDB | Entry.Verify recomputes EntryHash + LeafHash and they don't match |
| `TestRun_DetectsLeafSwap` | Attacker swaps two entries' on-disk bytes | PrevHash chain link breaks |

### Running

```sh
make chaos            # all of the above
make chaos-byzantine  # just witness chaos
make chaos-clock      # just clock-skew chaos
make chaos-tamper     # just tripwire chaos
```

Every test asserts the **defence fired** — not that the system kept
running. A passing test means stele detected the fault and refused
to produce a bogus artifact.

---

## 3. Performance regression gate

The bench-comparison flow in [Makefile](Makefile):

```sh
make bench-baseline   # captures bench/baseline.txt (commit this)
# ...change code...
make bench-current    # captures bench/current.txt
make bench-compare    # benchstat output (informational)
make bench-compare-strict  # fail if any bench regressed > THRESHOLD_PCT (default 100 == 2x)
```

The strict mode is what CI uses (`bench` job in
[hardening.yml](.github/workflows/hardening.yml)). The threshold is
deliberately loose because GitHub runner hardware is noisy — we're
catching "accidentally O(N²)" class regressions, not 5% microbench
drift. Override with `THRESHOLD_PCT=50` if you want a tighter gate
for a specific PR.

The script that does the actual gating is
[scripts/check_bench_regression.sh](scripts/check_bench_regression.sh).

### Refreshing the baseline

When you intentionally regress a benchmark (e.g. you added required
validation that's correctly slower than before), re-capture the
baseline in the same PR:

```sh
make bench-baseline BENCHTIME=2s
git add bench/baseline.txt
git commit -m "bench: refresh baseline after add validation"
```

Justify the change in the PR description — reviewers will look at
the old vs new numbers.

---

## 4. What's deferred (and why)

These belong to the same testing surface but were not done in the
shippable code-and-CI session:

| Item | Why deferred | What to do |
|---|---|---|
| **72-hour soak test** | Needs 3 days of clock time and a target host. | Run on a staging host once per release. Log: throughput, RSS over time, append p99 over time, anchor freshness. Flag any monotonic memory growth. |
| **Network chaos with toxiproxy / `tc qdisc`** | Requires a test harness that can run two daemons + a man-in-the-middle proxy. | Stand up: operator + 3 witnesses behind toxiproxy. Inject 200ms latency, then 5% loss, then a full partition between operator and one witness. Confirm witness quorum drops gracefully, recovers cleanly, and that `stele_witness_cosign_total{outcome="error"}` rate ticks during the partition. |
| **Slow-disk chaos** | Requires `LD_PRELOAD` or filesystem injection layer. | Use `chaos-mesh` `iochaos` on a k8s deployment, OR `LD_PRELOAD` a libc shim that delays `pwrite`. Confirm Append p99 rises but no 5xx, and that backpressure surfaces as `concurrency` 503s rather than handler timeouts. |
| **Burst test to 50K RPS sustained** | Needs hardware (multiple loadgen hosts) to actually reach 50K against a single operator. | Run loadgen on a separate host from steled, ramp `--rps` until the limiter starts firing, record the achieved-RPS / p99 / reject-rate curve. |
| **Real-world admin-action chaos** | Need to coordinate cosigner outages + rotation under load. | Manually: trigger `/rotate` while loadgen is at 80% target RPS. Confirm 0 ok-appends are lost; epoch advances; admin log records the action. |

Each row is an **operational** test, not a code change. Run quarterly
or as part of a release readiness checklist; record the results
alongside the chaos runs in `make chaos`.
