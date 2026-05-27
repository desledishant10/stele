# Stele Chaos Rig

A self-contained docker-compose stack that brings up a realistic stele
deployment and lets you inject controlled network faults to verify the
protocol's defences fire under fire.

What's in the box:

- **operator** (`steled`): the log daemon, full ingest hardening on.
- **mirror** (`stele-mirror`): pulls + verifies entries from operator.
- **witness-{a,b,c}** (`stele-witness`): three independent witnesses.
- **toxiproxy**: man-in-the-middle every operator→witness call. Listens
  on `:8474` for HTTP control. Each witness gets a named proxy you can
  inject latency, timeouts, or full partitions on.
- **prometheus**: scrapes every component's `/metrics`.
- **grafana**: anonymous-admin, auto-provisioned with
  [deploy/grafana/stele-overview.json](../deploy/grafana/stele-overview.json).

---

## Quickstart

Prerequisites: `docker` + `docker compose` (Docker Desktop or
equivalent), and Docker daemon running.

```sh
cd chaos/

# Bring up the stack. First run builds the stele image (~30s).
docker compose up -d --build

# One-time setup: enrol a producer + register the three witnesses.
./run-chaos.sh setup

# Baseline: assert everyone's healthy, run a 30s loadgen, print metrics.
./run-chaos.sh baseline
```

Then point a browser at:

- Grafana: <http://localhost:13000> (anonymous, admin role)
- Prometheus: <http://localhost:19094>
- Operator: <http://localhost:18080>
- Toxiproxy admin: <http://localhost:18474>

---

## Scenarios

Each scenario is one command. Run them in any order; they're
self-cleaning when you call `heal`. The interesting metrics during
each scenario are listed.

### 1. Latency injection — degraded witness

Inject 500 ms of one-way latency on `witness-c`:

```sh
./run-chaos.sh latency witness-c 500
```

**What should happen:**

- `stele_witness_cosign_duration_seconds_bucket{witness="witness-c"}`
  shifts right — p99 climbs into the 500 ms+ range for that witness.
- `stele_witness_cosign_total{witness="witness-c",outcome="ok"}` still
  ticks (latency, not failure).
- Operator-side `stele_append_duration_seconds` p99 is mostly
  unaffected (witness gathering is best-effort + parallel).
- `stele_appends_total{outcome="ok"}` keeps climbing — log throughput
  is preserved.

Heal:
```sh
./run-chaos.sh heal witness-c
```

### 2. Connection-timeout chaos — flaky witness

Inject 30% connection timeouts on `witness-b`:

```sh
./run-chaos.sh loss witness-b 30
```

**What should happen:**

- `stele_witness_cosign_total{witness="witness-b",outcome="error"}`
  rate rises (~30% of calls). `outcome="ok"` rate drops correspondingly.
- The other two witnesses absorb the gap (quorum holds at 2/3).
- `stele_witness_quorum_healthy` stays at `1`.

Heal:
```sh
./run-chaos.sh heal witness-b
```

### 3. Full partition — one witness goes dark

```sh
./run-chaos.sh partition witness-c
```

**What should happen:**

- `stele_witness_cosign_total{witness="witness-c",outcome="error"}`
  starts ticking at every checkpoint attempt (connection refused).
- The other two witnesses continue; the operator should still produce
  checkpoints with `len(c.Witnesses) == 2`.
- `stele_appends_total{outcome="ok"}` unaffected.
- If you partition a SECOND witness (`./run-chaos.sh partition
  witness-b`) the operator drops below quorum:
  `stele_witness_quorum_healthy` flips to `0` (once that metric is
  populated by core; today it's left at startup default).

Heal both:
```sh
./run-chaos.sh heal witness-c
./run-chaos.sh heal witness-b
```

### 4. Recovery — partition heals

Right after a `heal`, gossip on the next interval re-syncs all
witnesses' `seen` maps. Watch
`stele_witness_cosign_total{witness="witness-c",outcome="ok"}` start
ticking again at ~roughly one increment per `--checkpoint-every` cycle.

---

## Inspecting what's going on

```sh
# Print current toxics on every witness proxy:
./run-chaos.sh show

# Pull stele metrics directly:
./run-chaos.sh metrics

# Tail the operator's structured log:
./run-chaos.sh logs operator

# Grafana dashboard:  http://localhost:13000  → Dashboards → stele
```

The Grafana dashboard is the one committed at
[deploy/grafana/stele-overview.json](../deploy/grafana/stele-overview.json) — same dashboard
you'd run in production. During a scenario you should watch the
"Witness cosign rate by witness" and "Witness cosign p99 latency"
panels in particular.

---

## Adding scenarios

`run-chaos.sh` is intentionally thin — every command is one toxiproxy
HTTP call. To add a scenario:

1. Look up the toxic type you want at
   <https://github.com/Shopify/toxiproxy#toxics> (bandwidth,
   slow_close, slicer, etc.).
2. Add a subcommand to `run-chaos.sh` that POSTs to
   `$TOXIPROXY_URL/proxies/<witness>/toxics`.
3. Document the expected metric signature in this README.

The compose file's networking is set up so `toxiproxy:19090`,
`toxiproxy:19091`, `toxiproxy:19092` always route to witness a/b/c —
no need to touch container DNS to add more scenarios.

---

## Tearing down

```sh
./run-chaos.sh down
```

Removes containers AND volumes (so the next `up -d` starts with a
fresh log).

---

## Self-verifying scenarios (PromQL auto-assertions)

Each scenario above has a matching `assert-*` subcommand that injects
the fault, queries Prometheus, and exits non-zero on any metric
that doesn't match expectations. Designed to run unattended (e.g. in
CI):

```sh
./run-chaos.sh assert-baseline          # only — confirms healthy baseline
./run-chaos.sh assert-latency witness-c 500
./run-chaos.sh assert-partition witness-c
./run-chaos.sh assert-all               # runs every scenario, fails on first
```

Sample output of `assert-all` (real run, against a freshly-set-up stack):

```
==> ASSERT baseline: stack is healthy and producing entries
  OK:   operator append rate > 50/s              value=55.17 GREATER 50
  OK:   witness-a has cosigned at least one ckpt value=6 GREATER 0
  OK:   witness-b has cosigned at least one ckpt value=6 GREATER 0
  OK:   witness-c has cosigned at least one ckpt value=6 GREATER 0
  OK:   operator append error rate is zero       (no samples, treated as 0)

==> ASSERT latency on witness-c = 500ms
  OK:   witness-c p99 cosign latency > 0.35s     value=0.985 GREATER 0.35
  OK:   witness-a p99 unaffected (< 0.35s)       value=0.0099 LESS 0.35
  OK:   witness-b p99 unaffected (< 0.35s)       value=0.0099 LESS 0.35
  OK:   operator append rate held > 50/s         value=71.45 GREATER 50

==> ASSERT partition on witness-c
  OK:   witness-c cosign error rate climbs       value=0.025 GREATER 0
  OK:   witness-a still cosigning (quorum)       value=0.091 GREATER 0
  OK:   witness-b still cosigning (quorum)       value=0.091 GREATER 0
  OK:   operator append rate held > 50/s         value=103.4 GREATER 50
  OK:   witness-c resumed cosigning after heal   value=1.2 GREATER 0

  ALL CHAOS ASSERTIONS PASSED
```

The PromQL the assertions ride on is the same set the Grafana
dashboard renders, so a passing assertion sweep is also a
de-facto smoke test of the metric pipeline (operator → Prometheus →
Grafana).

To add a new assertion: copy `cmd_assert_partition` in
[run-chaos.sh](run-chaos.sh) and modify the `promql_assert` lines.
The helper takes `<op> <threshold> <query> <label_match> <description>` —
`op` is `GREATER | LESS | EQUAL_TO_ZERO | NONZERO`, `label_match` is
optional and filters for a specific metric instance like
`witness="witness-c"`.

---

## Limitations

- **Single host.** Real multi-region chaos (cross-AZ latency, BGP
  flap) needs more than docker-compose. Use this rig to validate the
  protocol-level defences; use a multi-host environment for
  infrastructure validation.
- **Operator-side faults aren't injected** — toxiproxy only sits on
  the operator→witness path. For operator-side disk or CPU chaos use
  `chaos-mesh`, `stress-ng`, or `LD_PRELOAD` shims directly on the
  operator container.
- **Stateful retry on slow scrapes** — the `wait_for_scrape` defaults
  assume Prometheus's 5s scrape interval. On a slower host (or with
  a tighter `scrape_interval`), bump the `dur` argument in each
  `cmd_assert_*` body.
