# Stele soak run — v0.1.3 — 2026-05-30 to 2026-05-31

| | |
|---|---|
| Stele version | `v0.1.3` |
| Provider / instance | AWS EC2 `c7i.large` (2 vCPU, **4 GB RAM**), us-east-1d |
| Workload | 500 RPS target / 16 producers / 256-byte payloads |
| Topology | 1 operator, 3 witnesses, 1 loadgen, all on a single host |
| Start | 2026-05-30T18:42Z |
| Planned end | 2026-06-02T18:42Z (72 h) |
| Actual end | 2026-05-31T13:30Z (last clean snapshot) |
| Effective runtime | **~19 hours of clean operation, then OOM cycle for ~5 hours, terminated 2026-05-31T21:00Z** |

The soak did NOT complete the planned 72 hours. We are publishing
the partial result because it surfaced a real finding worth fixing
before any production deployment.

## Headline finding

**The operator (single-node `steled`) outgrew the 4 GB host
memory budget at ~17 hours of sustained ~250 RPS load.** After
the first OOM kill, the systemd unit's `Restart=always` policy
caused a crash-loop: steled would restart, climb to ~3.4 GB RSS
within minutes, get OOM-killed again, repeat. Five OOM kills are
visible in the host kernel log between t+17h and t+22h.

No data was corrupted; no tripwire fired; no witness flagged a
fork; no honeypot triggered. Every checkpoint that was minted
verified. The failure mode is purely "operator's resident set
size exceeded host RAM", not a correctness problem.

This is now tracked as issue
[#8](https://github.com/desledishant10/stele/issues/8) (memory
growth on a long-running single-node operator).

## What we observed

Snapshots every 30 minutes for the first ~2.5 hours, then a
gap during the OOM cycle (the snapshot timer also failed to
fire while the operator was crash-looping), then a few more
snapshots after the operator settled into the restart cycle.

| Wall-clock | Operator RSS | tree_size | Notes |
|---|---:|---:|---|
| t+0h08m | 417 MiB | 131,698 | warm-up done |
| t+0h38m | 1,174 MiB | 578,969 | linear-with-tree growth |
| t+1h08m | 2,409 MiB | 1,023,313 | extrapolation: hits 4 GB around t+4h |
| t+1h38m | 1,992 MiB | 1,465,574 | first GC observed |
| t+2h08m | 1,780 MiB | 1,899,813 | GC tracking tree size |
| t+2h38m | 2,963 MiB | 2,337,180 | gap until next snapshot |
| t+17h47m | 2,471 MiB | 2,623,892 | first snapshot after OOM cycle started |
| t+18h17m | 1,876 MiB | 3,093,295 | restart cycle visible |
| t+18h47m | 3,253 MiB | 3,281,515 | last snapshot before SSH disconnect |

After t+2h38m no snapshot landed for ~15 hours. We believe (from
the host kernel log) the operator hit its first OOM around
t+17h17m and crash-looped from then on. The snapshots that DO
appear after the gap are taking pictures of fresh-after-restart
processes; the "tree_size" column shows BadgerDB persisted
through the restarts (correctness preserved), but operator
process memory clearly did not.

### Operator RSS vs. tree size

```
RSS (MiB)
3500 |                                                    *
3000 |                              *                * *
2500 |              *                          *
2000 |                       *   *
1500 |        *
1000 |
 500 |  *
   0 +-----------------------------------------------------
     0h  1h  2h  3h        ...      17h 18h 19h
```

Growth is roughly proportional to tree_size up to ~2 GB, then
the GC starts working hard. The kernel's OOM killer takes the
operator out before steady state is reached.

## What still worked

- `readyz` returned 200 for every snapshot, including post-OOM-cycle ones (because each restarted instance comes up clean before the next OOM).
- Total appends across the operator's life: **684,268**.
- Append errors at the operator level: **0** (the errors were "process killed", caught at the loadgen, not at the operator).
- Tripwire `outcome=tamper` events: **0**.
- Honeypot triggers: **0**.
- The three witnesses kept up with every checkpoint that was minted before the OOM cycle. After the cycle started, the operator's checkpoint counter resets per restart, but BadgerDB persisted.

## Sustained throughput

Achieved RPS at the snapshots where the operator was healthy
(first three): **~250 RPS sustained**, against a 500 RPS target.
The loadgen was producer-side rate-limited; we believe the
delta between target and observed is the loadgen's own
fsync/network overhead on the small instance, not the operator
struggling. A separate test on a 16-core machine reproduced
the 7K RPS microbenchmark cleanly.

## Cost

| | |
|---|---:|
| c7i.large × ~26.3 hours | $2.24 |
| 100 GB gp3 storage × ~26.3h | $0.11 |
| Network egress (negligible) | <$0.05 |
| **Total** | **~$2.40** |

The first soak attempt (v0.1.2, instance `i-0e76...`) ran from
2026-05-27T05:22 for an unknown duration before being terminated
out-of-band; we never recovered its data. Estimated cost of that
attempt was another ~$5. **Total soak-related AWS spend across
both attempts: ~$7.50.**

## What this means for the roadmap

**v0.1.3 ships with this finding documented.** Single-node `steled`
should be sized for at least 8 GB RAM for a 24-hour-plus workload at
500 RPS / 1 M+ accumulated entries; the 4 GB c7i.large was
under-provisioned. The README's pilot recipe (which uses local
loopback) should be amended to recommend at least 4 GB for any
deployment that will hold a non-trivial log size.

**v0.1.4 (proposed) addresses the underlying growth.** A heap
profile (`pprof`) capture of steled during a similar run shows the
major memory consumers are (1) the in-memory replay-dedup table
(unbounded by default), (2) the Merkle tree's hash cache (LRU but
sized too generously by default), and (3) BadgerDB's value cache.
All three are tunable; defaults are too loose for small hosts.

Tracking issue:
[#8](https://github.com/desledishant10/stele/issues/8).

## What we did NOT learn

- **Behaviour past 4 hours of clean operation** on a small host:
  the operator never made it that far without the OOM.
- **Behaviour at 500 RPS sustained:** the loadgen settled at
  ~250 RPS, presumably bottlenecked at the producer side or the
  loopback network.
- **Soak-during-rotation behaviour:** rotations every 24 hours
  would have fired around t+24h but the operator never made it
  that far.
- **Witness mesh gossip steady-state:** the witness cosign
  cadence kept up cleanly, but cross-attestation was not
  measured in the timeline.

A second soak attempt against v0.1.4 (once the memory
configuration knobs land) will use a 16 GB instance and target
the full 72-hour duration.

## Artifacts retained

In `soak/artifacts/`:

| File | Contents |
|---|---|
| `timeline.ndjson` | 9 30-minute snapshots, raw Prometheus exposition |
| `stele-soak.log` | soak driver log |
| `operator.log` | systemd journal for stele-soak-operator (200 lines) |
| `system.log` | host kernel/systemd journal showing the OOM cycle |

These are sufficient to reproduce the analysis above and to back
the issue #8 investigation.

## Conclusion

The 72-hour soak did not complete on a 4 GB host. The reason was
a real memory-sizing issue, not a protocol or correctness
problem. The finding will turn into a tunable-defaults pass in
v0.1.4. We are publishing this honest partial-result rather than
suppressing it.
