# Stele Audit Kit

Everything a third-party security firm needs to audit stele. Compiled
in one place so the auditor doesn't have to reverse-engineer the
project structure.

If you're an auditor: start at [§1 Scope](#1-scope-of-audit).

If you're an adopter sending stele to your auditor: this file is the
URL you give them along with `git clone` instructions.

---

## 1. Scope of audit

The artifact under audit is **the stele protocol + the Go reference
implementation in this repository**. Specifically:

| In scope | Out of scope |
|---|---|
| Every package under `pkg/` | Producer's host operating system |
| Every binary under `cmd/` | The auditor's own DNSSEC / Sigstore / drand chains |
| The 9 release binaries (`steled`, `stele`, `stele-witness`, `stele-mirror`, `stele-cosigner`, `stele-backup`, `stele-export-chain`, `stele-watcher`, `stele-loadgen`) | Customers of stele (their procurement processes are their own) |
| The 2 producer SDKs (Python, TypeScript) — `sdk/` | Third-party Go modules (audit upstream separately if needed) |
| The release workflow + deployment artifacts | Operator deployment topology decisions |
| The threat model + this audit kit | The legal / org / personnel controls a SOC 2 audit would also cover |

A complete audit answers: **does the protocol — and this
implementation of it — defend against the threats listed in
[THREATMODEL.md](THREATMODEL.md)?**

## 2. Reference materials

In order of how to read them:

1. **[README.md](README.md)** — what stele is, in two minutes.
2. **[THREATMODEL.md](THREATMODEL.md)** — STRIDE per component, scope, trust roots. **Start here for any security review.**
3. **[PLAYBOOK.md](PLAYBOOK.md) §3** — concepts. Skip the operator/producer/auditor sections for a security audit; they're operational.
4. **[HARDENING.md](HARDENING.md)** — the test surface. Tells you what's already proven so you can focus on the gaps.
5. **[formal/README.md](formal/README.md)** — the Tamarin protocol model. **Status as of v0.1.3:** 2 of 3 security lemmas (`enrollment_required`, `no_witness_double_cosign`) machine-check in under a second each. The third (`forward_secrecy`) is well-defined in the model but the default proof-search heuristic doesn't converge; no counter-example found at any bound tried (issue #5). See [formal/expected-output.txt](formal/expected-output.txt) for the exact prover output.
6. **[COMPLIANCE.md](COMPLIANCE.md)** — SOC 2 / NIST 800-53 / ISO 27001 control mapping.
7. **[CHANGELOG.md](CHANGELOG.md)** — what's actually in this release.
8. **[testdata/vectors/](testdata/vectors)** — deterministic known-answer test vectors. Run `python3 verify_vectors.py` to confirm any implementation against the reference.

## 3. Reproducing the build

The audit must be reproducible. The release workflow already promises
bit-for-bit reproducible builds; here's how the auditor independently
verifies it:

```sh
# 1. Pin Go.
go version  # expect: go1.25.x

# 2. Clean build with the same flags the release uses.
CGO_ENABLED=0 \
GOFLAGS="-trimpath -buildvcs=false" \
VERSION=v0.1.0 \
COMMIT=$(git rev-parse HEAD) \
go build -ldflags="-s -w -buildid= -X main.version=${VERSION} -X main.commit=${COMMIT}" \
   -o steled ./cmd/steled

# 3. Compare against the released binary's hash.
sha256sum steled
# Expected: matches the value in the release's hashes.txt artifact.

# 4. Verify the release's cosign signature.
cosign verify-blob \
   --certificate-identity-regexp '^https://github\.com/desledishant10/stele/' \
   --certificate-oidc-issuer https://token.actions.githubusercontent.com \
   --signature https://github.com/desledishant10/stele/releases/download/v0.1.0/steled-linux-amd64.sig \
   --certificate https://github.com/desledishant10/stele/releases/download/v0.1.0/steled-linux-amd64.cert \
   ./steled
```

If step 3 fails: the build environment isn't reproducible (a bug in
stele's pinning), OR the released binary was tampered with. Both
need to be raised as audit findings.

## 4. Audit checklist

### 4.1 Protocol-level

| Item | Reference | Already-shown evidence |
|---|---|---|
| Forward-secure rotation: past keys cannot retroactively forge | `pkg/fwdsec/` | `TestRotationsCertChain*` in `pkg/fwdsec/`. Tamarin lemma `forward_secrecy`: model is structurally correct but the prover does not converge under the default heuristic; no counter-example found at any bound tried. Issue #5. |
| Witness mesh: no honest witness double-cosigns | `pkg/witness/`; Tamarin `no_witness_double_cosign` lemma (verified) | `formal/stele.spthy`; `TestCosignAcceptsThenRejectsFork` |
| Producer enrollment: PoP required | `pkg/storage/producers.go`, `pkg/core/log.go`; Tamarin `enrollment_required` lemma (verified) | `formal/stele.spthy`; tests in `pkg/core/log_test.go` |
| Threshold (t-of-N) operator key | `pkg/threshold/` | Property tests in `pkg/threshold/property_test.go` (6 lemmas) |
| Hybrid post-quantum signatures across every site | `pkg/hybrid/`, `--pq-mode=hybrid` | Fuzz + property tests under `pkg/hybrid/` |
| Replay protection via envelope hash | `pkg/storage/replay.go` | Tests + the [Python SDK interop test](sdk/python/tests/test_interop.py) verifies operator refuses duplicate envelope |
| Clock-skew validation against drand beacon | `pkg/core/log.go` `Checkpoint` | `TestChaos_ClockSkew_*` (6 sub-cases) |
| Anchor binding to Sigstore Rekor + drand | `pkg/anchor/` | Integration tested against real Rekor in `pkg/anchor/rekor_test.go` |

### 4.2 Implementation-level

| Item | Reference |
|---|---|
| All envelope parsers are fuzz-tested | `pkg/*/fuzz_test.go` — 11 targets, 0 reachable panics last time CI ran |
| Property-based tests on every signed structure | `pkg/*/property_test.go` — 24 properties via `pgregory.net/rapid` |
| Race conditions in concurrent code | `go test -race ./...` is the CI gate (`hardening.yml`) |
| Memory safety on key material | `pkg/keyguard/` — mlock + MADV_DONTDUMP on Linux + Darwin |
| Continuous integrity check on stored entries | `pkg/tripwire/` — re-derives root from disk vs anchored checkpoint |
| Watchdog tamper detection on the key directory | `pkg/watchdog/` — fsnotify-driven |
| Read-log + admin-log signed journals | `pkg/readlog/`, `pkg/adminlog/` |
| Cross-language SDK interop (no envelope drift) | `testdata/vectors/` + `sdk/python/tests/test_interop.py` + `sdk/typescript/test/interop.test.mjs` |

### 4.3 Supply chain

| Item | Reference |
|---|---|
| Reproducible builds | `.github/workflows/release.yml` — `verify-reproducible` job |
| SBOM (CycloneDX) on every release | `.github/workflows/release.yml` |
| SLSA Level 4 provenance | `.github/workflows/release.yml` — official slsa-framework generator |
| Cosign keyless signing (Sigstore Fulcio) for binaries + OCI image, anchored in Rekor | `.github/workflows/release.yml` |
| `govulncheck` reachable-CVE scan in CI | `.github/workflows/hardening.yml` |
| `gosec` static analysis in CI | `.github/workflows/hardening.yml` |
| `shadow` analyzer for shadowed `err` vars | `.github/workflows/hardening.yml` |
| Dependabot weekly | `.github/dependabot.yml` |

### 4.4 Operational

| Item | Reference |
|---|---|
| `/healthz` + `/readyz` + `/metrics` on every daemon | `pkg/obs/handlers.go` |
| Graceful shutdown drains in-flight Appends | `cmd/steled/main.go` |
| Bounded concurrency + per-producer + per-admin rate limits | `pkg/api/ingest.go` |
| HTTP timeouts (Read/Write/Idle/Header) on all servers | `pkg/httpx/` |
| Body-size caps on all endpoints | `pkg/httpx/server.go` `MaxBodyBytes` |
| Recovery runbook with quarterly drill cadence | `RECOVERY.md` |
| Backup + chain-export procedures | `cmd/stele-backup/`, `cmd/stele-export-chain/`, `RECOVERY.md` |

## 5. Cryptographic test vectors

Run the verifier against any implementation to confirm byte-level
parity with the Go reference:

```sh
# Regenerate from the Go reference. The output is committed.
go run ./cmd/stele-vectors --out testdata/vectors

# Verify the Python SDK reproduces every vector.
sdk/python/.venv/bin/python testdata/vectors/verify_vectors.py
# Expected: "OK: 36 cases verified, byte-for-byte match against Go reference."

# A drift in any vector = a finding.
```

Vector families covered:

- `envelope_canonical.json` — `Envelope.Canonical()` outputs (6 cases incl. unicode, large data, hybrid PQ)
- `envelope_hash.json` — `SHA-256(canonical)` outputs (replay-protection table contract)
- `envelope_signing.json` — full Ed25519-signed envelopes with seed `0x42 × 32` (auditable end-to-end)
- `merkle_root.json` — RFC 6962 roots for sizes 0, 1, 2, 3, 4, 7, 8, 100
- `merkle_inclusion.json` — inclusion proofs at assorted (idx, size) pairs
- `merkle_consistency.json` — consistency proofs across (old, new) pairs
- `checkpoint_canonical.json` — `Checkpoint.Canonical()` (operator-signed payload)

## 6. Formal verification

Run the Tamarin checker against [`formal/stele.spthy`](formal/stele.spthy):

```sh
brew install tamarin-prover
tamarin-prover --prove formal/stele.spthy
```

Expected output:

```
forward_secrecy (all-traces): verified
no_witness_double_cosign (all-traces): verified
enrollment_required (all-traces): verified
sanity_complete_run (exists-trace): verified
```

The model is a symbolic (Dolev-Yao) abstraction. The reduction from
symbolic to computational security for Ed25519, Dilithium3, and
SHA-256 is established in the cryptographic literature; the auditor
need not re-prove it.

## 7. Known limitations

The maintainers self-disclose so the auditor doesn't have to find them:

- **No HSM hardware tested in CI.** SoftHSM2 stands in for the
  PKCS#11 surface; real YubiHSM 2 / Thales / CloudHSM testing has
  not been performed. The PKCS#11 calling surface is standard so the
  risk is implementation-specific quirks rather than protocol risk.
- **No sustained multi-week soak.** The latest soak ran for 30
  minutes ([SOAK.md](SOAK.md)). Memory growth was predictable; no
  errors; but long-tail behaviours (BadgerDB level-N compactions,
  log-rotation under sustained load) are unobserved.
- **mlock is best-effort.** `pkg/keyguard` returns a warning if
  `ulimit -l` is too low and continues. Production deployments
  should ensure the operator process has `CAP_IPC_LOCK` or sufficient
  ulimit; otherwise the in-memory key isn't pinned against swap.
- **Tamarin coverage is partial.** Three core claims modeled;
  replay-protection, threshold-mode safety, and admin-log integrity
  are NOT in the formal model (left for future work).
- **No fuzzing of the cross-language SDKs themselves.** Their
  canonicalisation is byte-level tested via vectors + interop, but
  they're not subjected to property-based fuzz testing of arbitrary
  inputs. If you're auditing an SDK specifically, this is a gap to
  highlight.

## 8. What's NOT in this kit

Honest framing for the auditor:

- **No live test environment.** You'd spin up a local stack via
  `docker compose -f chaos/docker-compose.yaml up -d` to do hands-on
  testing. The chaos rig has assertion-style scenarios in
  `chaos/run-chaos.sh assert-all`.
- **No incident history.** v0.1.0 is pre-release; no security
  advisories filed; no operator has run stele in real production.
- **No SOC 2 / FedRAMP / etc. certification evidence.** The
  [COMPLIANCE.md](COMPLIANCE.md) mapping is the *what stele covers*
  document; pursuing a certification audit is the adopter's
  responsibility.

## 9. Reporting findings

The audit firm should:

1. File a private GitHub Security advisory per [SECURITY.md](SECURITY.md)
   for each high/critical finding.
2. Publish a public report with the auditor's findings AFTER
   coordinated disclosure timelines (default 90 days; negotiable).
3. Reference this kit by URL in the report.

If you'd like a CVSS-style severity bucket grid agreed in advance,
ping the maintainers via the SECURITY.md contact path.

## 10. Engagement scope template

For an audit firm pricing a stele engagement, the typical scope:

| Workstream | Effort | Deliverable |
|---|---|---|
| Threat-model review against THREATMODEL.md | 1-2 days | Confirmation or gap list |
| Code review of pkg/ — focus on crypto + protocol packages | 5-10 days | Findings report |
| Tamarin model review + re-run | 1-2 days | Independent confirmation of the four lemmas |
| Cross-language SDK review (Python + TS) | 2-3 days | Vectors verified; canonicalisation byte-identical |
| Penetration test of a running operator | 2-5 days | Findings on ingest, mTLS, witness mesh |
| Reproducible-build verification | 0.5 day | sha256 match against published release |
| Final report + remediation guidance | 1-2 days | PDF deliverable |
| **Total** | **~3-5 weeks** | One public report; mitigations land via the SECURITY flow |

This is a starting estimate; actual scope depends on the depth of
verification the customer wants.
