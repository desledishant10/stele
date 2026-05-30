# Changelog

All notable changes to stele are recorded in this file. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/).

Each release is also published to the project's git tags and signed
via Sigstore Fulcio keyless (see [HARDENING.md](HARDENING.md) for the
verifier recipe).

## [Unreleased]

### Added
- (next-version entries go here)

## [0.1.3] - 2026-05-27

Formal-model overhaul. The Tamarin proof now machine-checks 2 of 3
core security lemmas (up from 0 of 3 in v0.1.2). No protocol or
wire-format changes; v0.1.0..v0.1.3 are runtime-compatible.

### Changed
- **`formal/stele.spthy`**: substantial rewrite.
  - Removed the `let producer_pk = pk(spk)` from `EnrollBegin` and
    the `let envelope_sig = sign(..., spk)` from `AppendEntry` —
    both leaked `spk` as adversary-controlled (the wellformedness
    warning). Now `producer_pk` is opaque from `In` in `EnrollBegin`,
    and `envelope_sig` is opaque from `In` in `AppendEntry`. Closes
    [#4](https://github.com/desledishant10/stele/issues/4).
  - Added a `Live(O, epoch, sk)` linear fact that `SignCheckpoint`
    consumes-and-re-emits and `RevealOperatorKey` consumes without
    re-emission. After a Reveal, no honest `SignCheckpoint` for that
    key can fire — the forward-secrecy structure now matches the
    real protocol's key-destruction semantics.
  - Added a `!OperatorPubkey(O, epoch, opk)` registry so witnesses
    verify checkpoints against a properly-bound key (replacing the
    free `pkOperator/2` function symbol the prior model declared
    but never gave semantics).
  - Added an `Equality` restriction and switched action labels
    from the noop `Verify(...)` to `Eq(verify(...), true)`, which
    combined with the signing builtin's equation actually enforces
    signature verification in the trace.
  - Added a `WitnessSizeUnique` restriction so a single witness
    cannot stamp two different roots at the same size. Closes
    [#6](https://github.com/desledishant10/stele/issues/6).
- **`formal/expected-output.txt`** now contains the measured
  per-lemma output captured against Tamarin 1.10.0.
- **`formal/README.md`** and **`AUDIT-KIT.md`** reflect the new
  2-of-3 verified state.

### Fixed
- `enrollment_required` lemma: still verified (3 steps, 0.82s).
- `no_witness_double_cosign` lemma: now verified (2 steps, 0.80s).
- `forward_secrecy` lemma: model is structurally sound (no
  counter-example at any bound tried, including 8); proof search
  doesn't converge under the default heuristic. Issue
  [#5](https://github.com/desledishant10/stele/issues/5) stays
  open for finding the right helper lemma or oracle.

## [0.1.2] - 2026-05-17

Second patch release in the v0.1.x line. Continues the v0.1.1
packaging fixes (which only landed for half the matrix) and corrects
overclaims in the formal-proof documentation discovered when we
actually ran `tamarin-prover` for the first time.

### Fixed
- **RPM `%{_unitdir}` undefined on Ubuntu CI runners.** That macro
  ships with `systemd-rpm-macros` (Fedora-only); we now declare a
  fallback in `deploy/rpm/stele.spec` so the build doesn't fail on
  "File must begin with /".
- **RPM cross-arch build:** `deploy/rpm/build-rpm.sh` now explicitly
  passes `--define '_target_cpu $ARCH'` in addition to `--target`,
  so `BuildArch: %{_target_cpu}` expands to aarch64 on amd64 hosts.

### Changed
- **Formal-model documentation: honesty pass.** Running
  `tamarin-prover --prove` against `formal/stele.spthy` for the
  first time revealed that 2 of 3 security lemmas currently
  *falsify* (forward_secrecy, no_witness_double_cosign) due to a
  wellformedness warning in the model that lets the adversary
  synthesise the producer signing-pubkey too freely. The remaining
  lemma (enrollment_required) verifies in 8 steps.
  - `formal/README.md` now reflects the actual prover state.
  - `formal/expected-output.txt` now contains the *measured* output,
    not the previously-aspirational "all verified".
  - `AUDIT-KIT.md` no longer claims Tamarin proofs for forward
    secrecy / fork detection; those rows now point only at the unit
    tests that genuinely cover those properties.
  - Issues [#4](https://github.com/desledishant10/stele/issues/4)
    and [#5](https://github.com/desledishant10/stele/issues/5)
    track the model fix.

## [0.1.1] - 2026-05-17

Patch release for three packaging / CI bugs that surfaced in the
v0.1.0 release pipeline. No protocol or wire-format changes; v0.1.0
and v0.1.1 are runtime-compatible.

### Fixed
- **RPM build:** `deploy/rpm/stele.spec` no longer depends on the
  Fedora-only `systemd-rpm-macros` package (broke .rpm production on
  Ubuntu CI runners). The `%systemd_*` macros are now guarded with
  `%{?...}` so they're a no-op when absent. Closes [#1].
- **RPM build:** `%changelog` header now uses a properly-formatted
  shell-expanded date instead of an undefined macro. Closes [#1].
- **RPM build:** `BuildArch` now tracks `%{_target_cpu}` so aarch64
  cross-builds succeed on amd64 runners. Closes [#1].
- **CI:** the `verify-reproducible` job now filters to `stele*`
  binaries before diffing hashes, so SBOM and combined-hashes file
  differences don't masquerade as reproducibility failures.
  Closes [#2].
- **Release workflow:** the container image is now also tagged
  `:0.1.1` (unprefixed) in addition to `:v0.1.1`, matching how
  docs and adopters naturally write image refs. Closes [#3].

### Changed
- `soak/cloud-init.yaml` and `soak/README.md` default to
  `STELE_VERSION=v0.1.1`.

[#1]: https://github.com/desledishant10/stele/issues/1
[#2]: https://github.com/desledishant10/stele/issues/2
[#3]: https://github.com/desledishant10/stele/issues/3

## [0.1.0] - 2026-05-17

Initial public release. Everything below is what landed across the
v0.x development line.

### Added — protocol & crypto
- RFC 6962 Merkle tree (CT- / Sigstore-compatible)
- Hash-chained append-only entries
- Forward-secure operator chain (Ed25519, rotated, prev-key destroyed)
- PKCS#11 HSM-backed operator keys (CGO build) — `pkg/hsm/`
- Hybrid post-quantum signatures (Ed25519 + Dilithium3 / ML-DSA Level 3) at every signature site — `pkg/hybrid/`
- Threshold operator signatures (t-of-N independent cosigners) — `pkg/threshold/`, `cmd/stele-cosigner`
- Witness mesh with signed seen-roots, peer gossip, cross-attestations, byzantine-peer detection — `pkg/witness/`
- Read-only mirror with independent entry verification — `cmd/stele-mirror`
- External anchoring: file sink, Sigstore Rekor, drand beacon — `pkg/anchor/`, `pkg/beacon/`
- Replay protection via envelope-hash dedup — `pkg/storage/replay.go`
- Clock-skew validation against the drand beacon — `pkg/core/log.go`
- Watchdog: scheduled + fsnotify + rate-anomaly rotation — `pkg/watchdog/`
- Read log (every served read recorded into a signed hash-chained journal) — `pkg/readlog/`
- Admin log (every rotate / enroll / revoke / witness-add / threshold-group change recorded) — `pkg/adminlog/`
- Honeypot canary entries with structured alerting — `pkg/honeylog/`
- Producer enrollment ceremony with proof-of-possession (challenge / response) — `pkg/storage/producers.go`, `pkg/core/log.go`
- `--require-enrollment` strict mode (refuses Append for un-enrolled producers)
- Tripwire: continuous re-derivation of the Merkle root from disk, fired on mismatch — `pkg/tripwire/`
- DNSSEC trust-anchor distribution + `stele dnssec-fetch` — `pkg/trustdns/`
- mlock + MADV_DONTDUMP best-effort key memory protection — `pkg/keyguard/`
- Standalone fork-detector daemon (`stele-watcher`) — `cmd/stele-watcher`, `pkg/watcher/`
- `stele audit --pdf <path>` produces a structured PDF compliance report — `pkg/audit/`, `pkg/auditpdf/`

### Added — ingest hardening
- HTTP server timeouts (Read/ReadHeader/Write/Idle) on every daemon — `pkg/httpx/`
- Per-endpoint request-body size caps via `http.MaxBytesReader`
- Bounded concurrency for `/append` (semaphore) with 503 + Retry-After
- Per-producer rate limiting (`x/time/rate` token bucket) with 429 + Retry-After
- Per-admin rate limiting on rotate / enroll / revoke / witness mutation endpoints
- Graceful shutdown: drain LB → /readyz returns 503 → drain in-flight → exit
- mTLS for producer authentication with CN-equals-ProducerID enforcement — `pkg/tlsutil/`

### Added — observability
- Structured logging via `log/slog` (JSON to stdout, configurable level)
- 18 Prometheus metrics covering appends, rotations, checkpoints, witness cosigns, anchors, watchdog, honeypots, tripwire, ingest rejects, admin actions, build identity
- OpenTelemetry tracing across Append → checkpoint → witness fan-out with W3C tracecontext propagation
- `/healthz`, `/readyz`, `/metrics` endpoints on every daemon — `pkg/obs/`
- Grafana dashboard — `deploy/grafana/stele-overview.json`
- Prometheus alert rules — `deploy/prometheus/alerts.yml`

### Added — supply chain
- SLSA Level 4 reproducible builds with second-pass byte-identical verification
- Sigstore Fulcio keyless cosign signing for every release binary + the multi-arch container image, anchored in Rekor
- CycloneDX SBOM published with every release
- govulncheck (reachable-call CVE detection) in CI — `.github/workflows/hardening.yml`
- gosec static analysis in CI
- shadow analyzer for `err` variable shadowing
- Dependabot weekly updates grouped by ecosystem — `.github/dependabot.yml`

### Added — durability
- `stele-backup` CLI: `snapshot` + `restore` using Badger's native incremental backup
- `stele-export-chain` CLI: paper + JSON export of the rotation chain trust anchor
- Tripwire continuous integrity check
- [RECOVERY.md](RECOVERY.md): 9-scenario runbook with concrete commands

### Added — quality / testing
- 11 fuzz targets across 7 packages
- 24 property-based tests using `pgregory.net/rapid`
- Byzantine-witness chaos tests (4 scenarios: wrong key, wrong witness_id, bit-flipped sig, garbage)
- Clock-skew chaos tests (6 scenarios)
- Disk-tamper chaos tests (4 scenarios via tripwire)
- Toxiproxy-based docker-compose chaos rig with PromQL auto-assertions — `chaos/`
- Race-detector CI gate on every PR
- benchstat regression gate against committed baseline
- `stele-loadgen` configurable synthetic-load generator

### Added — deployment
- Multi-stage distroless production OCI image — `deploy/Dockerfile`
- Multi-arch image (amd64 + arm64) build + push to `ghcr.io` in release workflow
- Helm chart with operator + mirror + 3 witnesses + optional cosigners + ServiceMonitor + NetworkPolicy + PodSecurityContext — `deploy/helm/stele/`
- Hardened systemd units with NoNewPrivileges, ProtectSystem=strict, MemoryDenyWriteExecute, CAP_IPC_LOCK for mlock — `deploy/systemd/`
- 15-minute deployment quickstart for Docker / Helm / systemd — `deploy/QUICKSTART.md`
- Cross-platform support: Linux + macOS + Windows + FreeBSD × amd64 + arm64 — `PLATFORMS.md`

### Added — governance
- `SECURITY.md` — vulnerability disclosure policy
- `CONTRIBUTING.md` — contributor workflow
- `CODEOWNERS` + GitHub issue / PR templates
- Apache 2.0 license
- `THREATMODEL.md` — STRIDE-per-component, scope/out-of-scope, trust roots
- `HARDENING.md` — test surface map + extension guide
- `LOADTEST.md` — load + chaos surface

### Notes for the curious
- Total Go: 28 packages, ~22,000 LoC (incl. tests)
- 9 binaries (`steled`, `stele`, `stele-witness`, `stele-mirror`, `stele-cosigner`, `stele-backup`, `stele-export-chain`, `stele-watcher`, `stele-loadgen`) plus the `stele-tamper` demo
- 0 reachable CVEs per `govulncheck` at the time of release
- The wire format and CLI flags freeze as compat surface at v0.1.0; minor versions add fields, never remove them

[Unreleased]: https://github.com/desledishant10/stele/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/desledishant10/stele/releases/tag/v0.1.0
