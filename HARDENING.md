# Stele Hardening Notes

A reference for how stele's correctness, robustness, and crypto-safety
are demonstrated, and how to extend the test surface when adding new
signed types or proof formats.

This document is for stele maintainers and integrators. End-user
operations live in `PLAYBOOK.md`; the non-technical narrative is in
`EXPLAINED.md`.

---

## Test surface overview

| Layer | Mechanism | Where |
|---|---|---|
| Unit / integration | `go test ./...` | every package |
| Concurrency | `go test -race ./...` | every package |
| Fuzz (parser robustness) | `go test -fuzz=^Fuzz...$` | 11 targets across 7 packages |
| Property (invariants under randomised inputs) | `pgregory.net/rapid` | merkle, fwdsec, threshold |
| Performance regression sniff | `go test -bench=. -benchtime=1x` | merkle, core |
| CI orchestration | GitHub Actions | `.github/workflows/{test,hardening}.yml` |

There is no single test that "proves stele correct" — the strategy is
*defence in depth*: every untrusted parser is fuzzed, every signed
invariant is property-tested, every concurrency-sensitive component
runs under the race detector.

---

## 1. Fuzz harnesses

Every wire-format parser that consumes externally-supplied bytes has a
fuzz target. The contract is: **`json.Unmarshal -> Canonical -> Verify`
must never panic on any byte string.**

Targets (with `-fuzztime=30s` each in CI):

| Target | Package | Covers |
|---|---|---|
| `FuzzEnvelopeUnmarshal` | `pkg/attest` | producer attestation envelope |
| `FuzzCanonicalDeterminism` | `pkg/attest` | canonical output is byte-stable for the same parsed input |
| `FuzzCheckpointUnmarshal` | `pkg/checkpoint` | signed Merkle root statements |
| `FuzzRotationCertUnmarshal` | `pkg/fwdsec` | per-epoch rotation certs |
| `FuzzChainUnmarshal` | `pkg/fwdsec` | full forward-secure chain |
| `FuzzGroupUnmarshal` | `pkg/threshold` | t-of-N group descriptors |
| `FuzzMemberSigUnmarshal` | `pkg/threshold` | per-cosigner signatures |
| `FuzzSignedSeenUnmarshal` | `pkg/witness` | witness-signed seen-roots |
| `FuzzCrossAttestationUnmarshal` | `pkg/witness` | witness-to-witness attestations |
| `FuzzEventUnmarshal` | `pkg/readlog` | hash-chained read journal |
| `FuzzEntryUnmarshal` | `pkg/logentry` | the canonical log record itself |

**Run all of them locally:**

```sh
for t in FuzzEnvelopeUnmarshal FuzzCanonicalDeterminism FuzzCheckpointUnmarshal \
         FuzzRotationCertUnmarshal FuzzChainUnmarshal \
         FuzzGroupUnmarshal FuzzMemberSigUnmarshal \
         FuzzSignedSeenUnmarshal FuzzCrossAttestationUnmarshal \
         FuzzEventUnmarshal FuzzEntryUnmarshal; do
  pkg=$(grep -rl "^func $t(" pkg | head -1 | xargs dirname)
  go test "./$pkg" -run=^$ -fuzz="^${t}$" -fuzztime=30s
done
```

If fuzzing finds a crashing input, the bytes land in
`pkg/<x>/testdata/fuzz/<target>/`. **Check that file in.** It becomes
part of the seed corpus and prevents regression.

---

## 2. Property-based tests

Property tests use `pgregory.net/rapid` to generate randomised inputs
and assert algebraic invariants. They are the second layer of defence
after fuzz tests: fuzzers find "does it crash"; property tests find
"does it still mean what it says."

### `pkg/merkle/property_test.go`

| Property | Asserts |
|---|---|
| `TestProp_RootDeterministic` | Same leaves → same root, always |
| `TestProp_InclusionVerifies` | For any tree and any index, the proof verifies |
| `TestProp_InclusionRejectsTamper` | Flipping a bit in the leaf or root makes verification fail |
| `TestProp_ConsistencyVerifies` | For any oldSize ≤ newSize, the consistency proof verifies |
| `TestProp_ConsistencyRejectsRewrite` | Rewriting any prefix leaf breaks consistency |
| `TestProp_BadInputsDoNotPanic` | Out-of-bound indices return errors, not panics |

### `pkg/fwdsec/property_test.go`

| Property | Asserts |
|---|---|
| `TestProp_ChainVerifiesAfterAnyRotations` | After 0..6 rotations, VerifyChain passes |
| `TestProp_ChainKeysDistinct` | No epoch reuses a previous epoch's pubkey |
| `TestProp_ChainRejectsWrongRoot` | A 1-byte-different root fails VerifyChain |
| `TestProp_ChainRejectsTamperedSignature` | Flipping any byte of any cert signature fails |
| `TestProp_ChainRejectsTamperedPublicKey` | Flipping any byte of any cert pubkey fails |
| `TestProp_ChainRejectsReordering` | Swapping any two certs fails VerifyChain |

### `pkg/threshold/property_test.go`

| Property | Asserts |
|---|---|
| `TestProp_AnyQuorumVerifies` | Any t valid sigs from distinct members pass |
| `TestProp_BelowQuorumFails` | t-1 valid sigs always fail |
| `TestProp_DuplicateSigsCountOnce` | Submitting the same sig N times doesn't reach threshold |
| `TestProp_ForeignSignerRejected` | Signatures from outside the group never count |
| `TestProp_GarbageDoesNotPoisonValidQuorum` | nil/invalid sigs are skipped, valid quorum still passes |
| `TestProp_MessageTamperRejected` | Modifying msg between sign and verify fails |

**Run with extra checks locally:**

```sh
go test ./pkg/merkle/ ./pkg/fwdsec/ ./pkg/threshold/ \
  -run TestProp -rapid.checks=2000 -count=1
```

CI runs at `-rapid.checks=500`; for a release, run `2000-5000` locally.

---

## 3. Race detector

The race detector is on by default in CI (`test.yml` and `hardening.yml`
both pass `-race`). It catches concurrent map writes, unsynchronised
access to mutable state, and forgotten locks.

Stele's most race-sensitive surfaces:

- `pkg/core/log.go` — multi-goroutine Append on a shared Log
- `pkg/storage/storage.go` — Badger txn ordering
- `pkg/witness/gossip.go` — peer fan-out
- `pkg/fwdsec/fwdsec.go` — Signer's mu during Rotate while Sign is in flight
- `pkg/threshold/coordinator.go` — parallel cosigner fan-out

When adding new shared state, **always** add at least one race-sensitive
test: a goroutine that reads while another writes. The race detector
will not save you from missing tests.

---

## 4. Crypto audit hygiene

The "did we silently drop a crypto error" trap is a recurring source of
real-world vulnerabilities. We pre-empt it with a periodic grep.

**Audit command:**

```sh
grep -rn "_ =\|_, _ =" --include="*.go" \
  pkg/checkpoint pkg/attest pkg/threshold pkg/fwdsec pkg/hybrid \
  | grep -v _test.go
```

The known acceptable patterns are:

- `_ = active.Destroy()` in error-recovery paths where we've already
  decided to abort and the cleanup is best-effort.
- `_, _ = w.Write(...)` and `_ = enc.Encode(...)` against an HTTP
  ResponseWriter where the peer may have disconnected.

Everything else — especially `MarshalBinary()`, `Sign(...)`,
`Verify(...)`, `rand.Read(...)` — must propagate the error. If you
introduce a new `_ = ...` in those packages, also leave a comment
explaining why dropping the error is safe.

---

## 5. Benchmarks

Benchmarks live alongside their packages as `bench_test.go`. They are
not regression-gated (GitHub runners' performance varies too much), but
they:

- prove the bench paths still compile and run
- give a current-day baseline for capacity planning
- catch >2x regressions on a developer machine before merge

**Run locally:**

```sh
go test ./pkg/merkle/ -bench=. -benchtime=2s -run=^$
go test ./pkg/core/ -bench=. -benchtime=2s -run=^$
```

Reference numbers on Apple M3 Pro, single-threaded:

| Benchmark | Result |
|---|---|
| `BenchmarkAppendLeaf` (merkle only) | ~1.47M leaves/sec |
| `BenchmarkInclusionProof_10K` | ~560 ns / proof |
| `BenchmarkConsistencyProof_10K` | ~595 ns / proof |
| `BenchmarkRoot_10K` | ~380 ns |
| `BenchmarkLogAppend` (full pipeline: sign + Badger + Merkle) | ~6,800 entries/sec |
| `BenchmarkProducerSign` (Ed25519 + canonical envelope) | ~59K sigs/sec |

The end-to-end Append number is dominated by Badger fsyncs, not crypto.
A production deployment with grouped writes or WAL-batched appends
should comfortably reach 50K+ entries/sec.

---

## 6. CI workflows

- **`.github/workflows/test.yml`** — full `go test -race ./...` with
  SoftHSM2 set up so the PKCS#11 tests in `pkg/hsm` actually exercise
  real keypair generation against an HSM emulator.
- **`.github/workflows/hardening.yml`** — race + property tests on
  non-HSM packages, 30s of fuzzing per target, bench smoke tests, and
  supply-chain guard rails:
  - `govulncheck` — reachable-call CVE detection across all packages.
  - `gosec` — static analysis (weak crypto, hardcoded creds, unsafe
    tempfiles); findings fail the build, drift only via reviewed
    `// #nosec G... -- justification` annotations.
  - `shadow` — catches `err` shadowing in crypto paths.
- **`.github/workflows/release.yml`** — SLSA L4 reproducible builds,
  CycloneDX SBOM, Sigstore Fulcio keyless signing, Rekor anchoring, and
  a second-run reproducibility check (binaries must match byte-for-byte
  between two independent builds).
- **`.github/dependabot.yml`** — weekly Go module and GitHub Actions
  updates, grouped by ecosystem (crypto / observability / storage /
  transparency). No auto-merge; every bump runs the full CI gauntlet.

All run on every PR and every push to `main`. If a fuzz target finds a
new crashing input in CI, the offending bytes are uploaded as a
workflow artifact.

## 6b. Threat model

See [THREATMODEL.md](THREATMODEL.md) for the canonical STRIDE-per-
component breakdown, the explicit out-of-scope list, and the minimal
trust roots an auditor must accept. Every defence mentioned there is
named with the file path of the implementation, so the threat model and
the code stay in sync.

When you add a new feature, update `THREATMODEL.md` first: it forces
the question "what are we now defending against, and at what trust
cost?" before any code lands.

---

## 7. Extending the test surface

### When adding a new signed wire type

1. Write `Canonical() []byte` and `Verify(...) error`.
2. Add a fuzz target: `func FuzzXxxUnmarshal(f *testing.F)` with at
   least 3 seed inputs (empty `{}`, a valid-looking shape, an
   adversarial shape like `{"signature":"!!!"}`).
3. Add a `Marshal`/`Unmarshal` round-trip test.
4. If the type participates in an aggregate (chain, group, list), add
   a property test that builds N of them and asserts the aggregate's
   verification holds.

### When adding a new invariant

If the property is "for any X, Y holds":
- Write a property test in the package's `property_test.go`.
- Use `rapid.IntRange`, `rapid.SliceOfN`, `rapid.SliceOfNDistinct`,
  etc., to generate the X.
- Inside the test, draw exactly one X and assert Y. Rapid will
  re-run hundreds of times with different seeds.

If the property is "no input causes a panic":
- That's a fuzz target.

### When adding a new concurrent path

- Acquire/release the mutex in the obvious place.
- Add a test that spawns ≥2 goroutines hitting the shared state.
- Run with `-race`. If the race detector is silent, the test passes.

---

## 8. What's intentionally *not* tested

Honest framing matters more than test count.

- **HSM tests** — only run in CI under SoftHSM. A real YubiHSM /
  CloudHSM target would need a paid integration env. The PKCS#11
  surface is the same, so SoftHSM is a reasonable proxy.
- **End-to-end network tests across multiple physical machines** — the
  witness mesh, mirror, and cosigner protocols are exercised via
  `loopback` HTTP in single-process integration tests
  (`pkg/core/log_test.go`, `pkg/witness/*_test.go`). True multi-host
  failure modes (network partition, clock skew across regions, DNS
  poisoning of `_stele-root` TXT records) are not in the automated
  suite.
- **Cryptographic primitive correctness** — we rely on
  `crypto/ed25519` (Go stdlib) and `github.com/cloudflare/circl`
  (Dilithium3). We test our *use* of those primitives, not the
  primitives themselves.
- **Adversarial OS-level conditions** — disk-full during a rotation
  cert write, partial fsync on power loss, malicious filesystem racing
  the keystore. These belong in a chaos-engineering harness, not a unit
  test.

These gaps are deliberate. Anything in this list that turns out to be
load-bearing for a deployment is a candidate for the next hardening
pass.
