# Contributing to stele

Thanks for considering a contribution. Stele is a security tool, so
the contributor workflow is a bit stricter than for a typical Go
project — every change ships with tests, and every PR runs the full
hardening sweep before review.

## Quick start

```sh
git clone https://github.com/desledishant10/stele
cd stele

# Go 1.25 or later required (the OTel SDK enforces this floor).
go version

# Build everything.
go build ./...

# Run the tests (race detector on, fuzz + property tests).
make test
# Equivalent: go test -race -count=1 ./...
```

If you're new to the codebase, start with these in order:

1. [README.md](README.md) — what stele is
2. [PLAYBOOK.md](PLAYBOOK.md) §3 (Concepts)
3. [THREATMODEL.md](THREATMODEL.md) — frames what every change must preserve
4. [HARDENING.md](HARDENING.md) — the test surface and how it's extended

## Development workflow

| Step | Command |
|---|---|
| Build all binaries into `./bin/` | `make build` |
| Run full test suite | `make test` |
| Quick tests only (skip benchmarks) | `make test-short` |
| Static analysis | `make vet` |
| Reachable-CVE scan | `make vuln` |
| Chaos tests (byzantine + clock + tamper) | `make chaos` |
| Performance regression check | `make bench-compare-strict` |
| Build the chaos docker rig | `cd chaos && docker compose up -d --build` |
| Render the Helm chart | `helm lint deploy/helm/stele/` |

The Makefile is the canonical source of truth for "what CI runs."

## What every PR must include

| Class of change | Required artifacts |
|---|---|
| **New wire format (envelope, checkpoint, etc.)** | Fuzz target in `pkg/<x>/fuzz_test.go`. Property test if the type participates in an aggregate (chain, group, list). Update to the [Threat model](THREATMODEL.md) row that describes the threat the new shape addresses. |
| **New cryptographic primitive or signature site** | Tests covering: happy path, wrong-key rejection, bit-flipped-signature rejection, replay rejection (if applicable), hybrid mode if introduced. Update to [SECURITY.md](SECURITY.md) §"Primitives." |
| **New defence** (e.g. rate limit, validator, watchdog trigger) | A chaos test in `pkg/<x>/chaos_test.go` that injects the corresponding attack. The defence must assert it FIRED. |
| **New flag** | Help text + entry in [PLAYBOOK.md §8.2](PLAYBOOK.md). Default must be production-safe. |
| **New metric** | Entry in [PLAYBOOK.md §8.5](PLAYBOOK.md) AND a panel or alert rule in [deploy/](deploy/). |
| **Performance change** | Refresh `bench/baseline.txt` in the same PR if you've intentionally regressed a microbenchmark, with justification in the PR description. |
| **Anything else** | Just tests — the existing kind. We don't ship code without test coverage. |

## Commit style

- **One concern per commit.** A refactor commit and a feature commit
  should be separate even if they touch the same file. Reviewers
  read commits one at a time.
- **Imperative summary line, < 72 chars.** "Add per-admin rate
  limit" not "Added per-admin rate limit".
- **Explain WHY in the body when it isn't obvious.** Code review
  tools show the WHAT; the body is where future-you reconstructs
  intent.
- **Reference the issue.** `Refs #123` or `Fixes #456` so the
  history is searchable.

## Code style

- Standard Go formatting (`gofmt`). CI enforces.
- Avoid comments that restate the code. Add a comment only when the
  WHY is non-obvious. See `CLAUDE.md` if present, or read existing
  files for the established style.
- Don't add error handling for impossible cases (the rest of the
  codebase trusts internal invariants and validates at boundaries).
- Don't pre-emptively abstract. Three similar lines is better than
  a premature helper.
- Don't introduce backwards-compatibility shims when you can just
  change the code — except across the **wire format**, where stele
  commits to additive evolution within a major version (see
  [CHANGELOG.md](CHANGELOG.md)).

## Testing philosophy

Stele's invariants are mathematical, so the tests are mathematical
too:

- **Property tests** (`pgregory.net/rapid`) for any "for-all" claim.
  Examples: "for any sequence of N rotations the chain still verifies",
  "for any t-of-N quorum the multi-sig succeeds."
- **Fuzz tests** for every parser that consumes external bytes.
  Goal: zero panics on any input.
- **Chaos tests** for every defence. Goal: when the documented attack
  fires, the documented defence fires too.
- **Race tests** on every concurrent path.
- **Benchmarks** for the hot path (`Append`, Merkle proof generation,
  Ed25519 signing) with regression gating in CI.

The bar for adding NEW behaviour without ANY of these is: zero.

## How `pkg/obs` works

If your change emits log lines or metrics, use `pkg/obs`. Examples:

```go
obs.Info("witness added", "id", id, "url", url)
obs.IngestRejectsTotal.WithLabelValues("append", "rate_limit").Inc()
ctx, span := obs.StartSpan(ctx, "stele.my_operation")
defer span.End()
```

Do NOT use the stdlib `log` package directly. The migration completed
in a prior session; new uses regress us.

## How `pkg/keyguard` works

Anything that holds a private key in memory should call
`keyguard.Lock(b)` after loading it and `keyguard.Unlock(b)` before
zeroing. `MarkNoCoreDump(b)` is best-effort on Linux. Failures are
non-fatal — log and continue. See [pkg/fwdsec/keystore.go](pkg/fwdsec/keystore.go)
for the canonical pattern.

## Reviewing other people's PRs

Useful checks beyond "does it compile":

- Does it preserve every existing defence? Cross-reference the
  Threat model table.
- Does any new wire-format field have a fuzz target?
- Does any new HTTP endpoint have a size cap + (if mutating) admin
  rate limit?
- Did `make chaos` and `make bench-compare-strict` pass on the
  PR's CI run?

## Releases

- Tag a release with `git tag -s vX.Y.Z` (signed) and push the tag.
- The `release` workflow does the rest: builds 9 binaries × 7
  platform targets, generates SBOM, builds the OCI image, signs
  everything with cosign keyless, publishes to GitHub Releases +
  `ghcr.io/desledishant10/stele`.
- Update [CHANGELOG.md](CHANGELOG.md) in the same commit as the tag.

## Security

Do **not** report suspected vulnerabilities as public issues.
See [SECURITY.md](SECURITY.md) for the disclosure flow.

## License

By contributing, you agree your code is licensed under the project's
[LICENSE](LICENSE) (Apache 2.0).
