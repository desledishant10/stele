# Security Policy

## Reporting a vulnerability

**Do not file a public GitHub issue** for a suspected vulnerability in
stele. Use one of these private channels instead, in order of
preference:

1. **GitHub Security Advisory**: from the repository's "Security" tab
   → "Report a vulnerability." This routes a private advisory to the
   maintainers without disclosing the issue publicly. Preferred.
2. **Email**: `security@<the-domain-this-repo-is-published-under>`
   (replace with the actual maintainer-reachable address before
   making the repo public). PGP welcome but not required.

Include in your report:

- Affected component (`steled`, `stele-witness`, `pkg/...`, etc.)
- Stele version (`stele --version` or git commit)
- A reproducer (minimal commands, sample input, expected vs actual)
- Your assessment of impact (denial of service, integrity break,
  information disclosure, etc.)
- Whether you intend to publish your own writeup, and on what
  timeline

## What we'll do

| Step | Target |
|---|---|
| Initial acknowledgement | within 3 business days |
| Triage (severity + affected versions) | within 7 business days |
| Fix landed on `main` | depends on severity (see below) |
| Coordinated disclosure | 90 days after report, or sooner by agreement |

Severity guidelines:

- **Critical** (forgery of an entry, chain compromise, signature
  bypass, remote code execution): hotfix released within 7 days of
  triage; public advisory + CVE filed at release.
- **High** (privilege escalation, information disclosure of a
  producer key, DoS that survives ingest hardening): fix in the next
  minor release within 30 days; advisory at release.
- **Medium / Low**: fix in the regular release cadence; documented in
  CHANGELOG.

## Scope

**In scope** for security reports:

- Anything in this repository under `pkg/`, `cmd/`, `deploy/`,
  `chaos/`, `.github/workflows/`.
- A way to forge, modify, or hide an entry without the signed proof
  trail expected by [THREATMODEL.md](THREATMODEL.md).
- A way to bypass any of the protocol's documented defences
  (forward-secure rotation, witness mesh, threshold, hybrid PQ,
  enrollment, tripwire, anchor, watchdog).
- Memory-safety / panics on hostile input (the fuzz harnesses are
  meant to catch these; gaps are fair game).
- Supply-chain attacks on the release workflow.

**Out of scope** for security reports (these are documented design
choices, not vulnerabilities):

- DoS against the operator process itself. Stele is fail-safe: it
  refuses to append rather than produce a wrong entry. We bound DoS
  exposure via [pkg/api/ingest.go](pkg/api/ingest.go) but never
  promise availability against arbitrary attackers.
- Physical attacks on the operator host (RAM extraction, disk
  forensics, ptrace from another root process). The mitigation is
  HSM-backed keys + [keyguard mlock](pkg/keyguard/), not the
  operator-host trust boundary.
- Defects in third-party dependencies (`crypto/ed25519`,
  `cloudflare/circl`, `dgraph-io/badger`). Report those upstream;
  stele will pick up the fix via Dependabot.
- "I can decrypt entries someone published in cleartext" — stele
  doesn't encrypt entry payloads. Producers who care must encrypt
  before signing.
- Side-channel attacks on the HSM / Ed25519 / Dilithium3
  implementations. Vendor-level concerns.

## Cryptographic primitives currently relied on

If any of these are broken in academic literature or by published
vulnerabilities, the entire stele integrity claim weakens — we treat
that as a top-severity event regardless of whether anyone reports a
concrete exploit.

| Primitive | Where | Mitigation if broken |
|---|---|---|
| Ed25519 (RFC 8032) | Every classical signature site | Activate `--pq-mode=hybrid`; rotate to Dilithium3-only when available |
| Dilithium3 / ML-DSA Level 3 (NIST FIPS 204) | Every hybrid signature site | Migration to next NIST PQ winner |
| SHA-256 | Merkle tree, hash chain, envelope hash | Migration to SHA-384 / SHA-3 — centralised at [pkg/merkle/merkle.go](pkg/merkle/merkle.go) |
| RFC 6962 Merkle tree construction | The append-only proof structure | Use a transparency-log construction with explicit weak-leaf protection (RFC 9162) |

## Past advisories

(none — fresh project)

## Public-key cryptography for this disclosure flow

When the project's security inbox is set up, paste the PGP public key
fingerprint here. Stele's release workflow signs all binaries +
images with Sigstore Fulcio keyless, which is the recommended
verification path for releases. The PGP key here is solely for
encrypting inbound vulnerability reports.

```
(fingerprint goes here once the inbox is provisioned)
```
