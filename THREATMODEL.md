# Stele Threat Model

This document is the *security frame* for stele. It defines what the
system is trying to defend against, what it explicitly is not, and how
each defence in the codebase maps onto a named threat. Read this
before touching any cryptographic code or changing any wire format.

For implementation details of the test surface, see
[HARDENING.md](HARDENING.md). For non-technical narrative, see
[EXPLAINED.md](EXPLAINED.md).

---

## 1. Assets

What we are protecting:

| Asset | Why it matters |
|---|---|
| Per-entry **provenance binding** | Auditors must be able to prove "this exact byte sequence was produced by this exact producer at this exact moment, and is the Nth entry in the log." |
| **Tree integrity** | The entire append-only log must be tamper-evident. Modifying or removing *any* historical entry must be mathematically detectable. |
| **Operator non-repudiation** | The operator cannot present different views of the log to different parties (split-brain attack). |
| **Forward secrecy of past entries** | Compromising the operator today must not let an attacker forge entries dated yesterday. |
| **Producer identity** | A registered producer's signing key, and the binding between that key and the producer's organisational identity. |
| **External anchors** | The pointers (Sigstore Rekor, drand beacon, on-disk anchor log) that bind stele's view to a publicly-verifiable ground truth. |
| **Honeypot canaries** | The set of entries that look like real data but whose access is a compromise signal. |

---

## 2. Actors

| Actor | Description | Default trust |
|---|---|---|
| **Operator** | Runs steled, holds the active epoch's signing key (or has it inside an HSM / threshold quorum). Sees every appended entry. | Trusted for liveness; *not* trusted for integrity (the protocol must catch operator misbehaviour). |
| **Producer** | Software (a service, a job, a human via CLI) that submits Append requests. Holds its own per-producer signing key. | Trusted to sign things they want recorded. *Not* trusted to dictate index positions or read others' entries. |
| **Witness** | Independent third-party process that cosigns checkpoints and gossips with peer witnesses. | Trusted for *availability of cosignature*; not trusted on its own to validate anything an auditor could not. |
| **Mirror** | Read-only replica that pulls entries from the operator and verifies them locally. | Trusted to serve a faithful copy *that it has verified itself*. |
| **Auditor** | Third party (regulator, security team, customer) with the verify CLI and the operator's published root pubkey. | Acts as the final arbiter. Holds the strongest verification position. |
| **Cosigner** | Member of the threshold-signature group (when threshold mode is active). One key share, one cosigner daemon per member. | Trusted only with the share they hold; t-of-N security means up to t-1 cosigners may be malicious. |
| **Attacker** | Any party not on this list. May be: a remote network attacker, a malicious producer, a compromised host running steled, a hostile witness, a CDN that selectively serves stale data, a nation-state observer of the future cryptanalysing today's signatures. | None. |

---

## 3. Component-by-component STRIDE

Each row of each table is "threat — defence in code". Where the
defence references a package, the canonical file is named.

### 3.1 Operator daemon (`steled`)

| Threat | Class | Defence |
|---|---|---|
| Attacker tampers with stored entries on disk | Tampering | RFC 6962 Merkle tree; every entry hash-chained to its predecessor. Any byte change invalidates `EntryHash`, `LeafHash`, and the chain. ([pkg/logentry/entry.go](pkg/logentry/entry.go)) |
| Attacker reorders entries | Tampering | Index + `PrevHash` linkage. Reordering breaks the chain. Property test [TestProp_ChainRejectsReordering](pkg/fwdsec/property_test.go). |
| Operator key stolen from disk | Spoofing | Forward-secure key rotation: each epoch's key is destroyed when the next is created. A stolen key only forges *current epoch* signatures. ([pkg/fwdsec/fwdsec.go](pkg/fwdsec/fwdsec.go)) |
| Operator key extracted from host | Spoofing | Optional HSM-backed `KeyStore` (PKCS#11). Key never leaves the HSM; attacker can only request signatures via the HSM, not exfiltrate the key. ([pkg/hsm/pkcs11.go](pkg/hsm/pkcs11.go)) |
| Operator key forged via single compromise | Spoofing | Optional threshold mode: t-of-N cosigner quorum required for both checkpoints and rotation certs. Attacker must compromise ≥ t independent cosigners. ([pkg/threshold/](pkg/threshold/)) |
| Operator presents different log views to different parties | Repudiation | Witness mesh: every published checkpoint requires ≥ q witness cosignatures. Witnesses also gossip with each other and publish signed seen-roots. ([pkg/witness/](pkg/witness/)) |
| Attacker rewrites a past checkpoint | Tampering | External anchoring: every checkpoint is written to a public Sigstore Rekor entry. Rewriting requires also retracting the Rekor record, which is itself in a transparency log. ([pkg/anchor/rekor.go](pkg/anchor/rekor.go)) |
| Attacker replays an old envelope | Tampering | Replay protection: `(envelope_hash → entry_idx)` table refuses any envelope hash already accepted. ([pkg/storage/replay.go](pkg/storage/replay.go)) |
| Attacker rotates operator's wall clock to bypass beacon | Tampering | Clock skew check vs drand beacon round: refuses to checkpoint if wall clock disagrees with the beacon's expected time by more than `DefaultMaxClockSkew`. ([pkg/core/log.go](pkg/core/log.go)) |
| Attacker quietly modifies the on-disk keystore | Tampering | Watchdog with fsnotify: any modification to the key directory triggers immediate rotation, destroying the suspected-compromised key. ([pkg/watchdog/watchdog.go](pkg/watchdog/watchdog.go)) |
| Quantum-capable attacker breaks Ed25519 in 20 years | Spoofing | Hybrid post-quantum mode: every signature site signs with Ed25519 *and* Dilithium3 (NIST FIPS 204 ML-DSA Level 3). Verifiers require both. ([pkg/hybrid/](pkg/hybrid/)) |
| Producer sends malformed envelope to crash steled | DoS | Fuzz testing of every parser at the wire format level; envelopes are size-bounded by `http.MaxBytesReader` ([pkg/httpx/server.go](pkg/httpx/server.go)); ingest gate adds per-producer rate limit + global concurrency cap returning 429 / 503 with `Retry-After` ([pkg/api/ingest.go](pkg/api/ingest.go)). |
| Attacker hammers admin endpoints (rotate / enroll / revoke / witness-add) to credential-stuff or DoS the admin trail | DoS / spoofing | Per-actor admin rate limit keyed off mTLS CN, X-Stele-Admin header, or source IP. POST/PUT/DELETE on admin endpoints rate-limited; GETs unaffected so audit reads stay cheap. ([pkg/api/server.go: rateLimitAdmin](pkg/api/server.go), [pkg/api/ingest.go: allowAdmin](pkg/api/ingest.go)) |
| Attacker quietly enrolls a producer they control after compromising the API surface | Spoofing / tampering | Enrollment ceremony: every producer record is signed by the operator's active fwdsec chain key over canonical fields (id, pubkey, scope, expiry, epoch). `--require-enrollment` mode refuses Append for any producer without a verifiable signature. ([pkg/storage/producers.go](pkg/storage/producers.go), [pkg/core/log.go: IssueEnrollment / Append](pkg/core/log.go)) |
| Stolen producer cert allows impersonation | Spoofing | mTLS with `--tls-require-cn-match`: the client cert's CN must equal `envelope.ProducerID`. ([pkg/api/server.go](pkg/api/server.go), [pkg/tlsutil/ca.go](pkg/tlsutil/ca.go)) |

### 3.2 Witness daemon (`stele-witness`)

| Threat | Class | Defence |
|---|---|---|
| Malicious operator sends different roots to different witnesses | Tampering | Witnesses gossip signed seen-roots. A conflict surfaces as a fork claim with two independently-signed contradictory statements. ([pkg/witness/gossip.go](pkg/witness/gossip.go)) |
| Hostile witness lies about what it has seen | Repudiation | Cross-attestations: every gossip exchange is itself signed by the receiving witness, so a witness that retroactively changes its story creates a self-contradiction. ([pkg/witness/cross_attestation.go](pkg/witness/cross_attestation.go)) |
| MITM substitutes a witness response | Spoofing | Witness cosignatures are validated against the witness's *trusted* public key (registered out of band), not the key in the response. |
| Witness key stolen | Spoofing | Witness keys are independent of operator keys. A stolen witness key only forges that one witness's cosignatures — needs ≥ q to forge a checkpoint. |

### 3.3 Cosigner daemon (`stele-cosigner`)

| Threat | Class | Defence |
|---|---|---|
| Operator coerces cosigner to sign arbitrary bytes | Tampering | Cosigner only signs requests whose `X-Stele-Caller` matches its `--trusted-caller` list; also verifies the requested message is a canonical checkpoint or rotation cert before signing. ([pkg/threshold/cosigner.go](pkg/threshold/cosigner.go)) |
| Compromised cosigner forges signatures | Spoofing | Threshold property: one cosigner's signature alone proves nothing. Verifier requires t-of-N. Property tests [TestProp_BelowQuorumFails](pkg/threshold/property_test.go), [TestProp_ForeignSignerRejected](pkg/threshold/property_test.go). |
| Cosigner returns valid sig but downgrades hybrid → classical | Spoofing | `VerifyMulti` requires a matching quantum signature whenever the group registered a quantum pubkey for that member; classical-only response in hybrid mode is rejected. ([pkg/threshold/multisig.go](pkg/threshold/multisig.go)) |

### 3.4 Mirror daemon (`stele-mirror`)

| Threat | Class | Defence |
|---|---|---|
| Operator quietly omits entries from the read API | Information disclosure | Mirror verifies every entry it pulls (producer sig + chain integrity) and only serves what it has independently verified. Multiple mirrors run on independent infrastructure detect selective omission by divergence. |
| Operator serves a forged checkpoint to the mirror | Tampering | Mirror verifies the checkpoint against the trusted operator root pubkey and any required witness cosignatures. |

### 3.5 Verify CLI (`stele verify`)

| Threat | Class | Defence |
|---|---|---|
| Auditor downloads a trojaned verify CLI | Spoofing | Released binaries are cosign-signed via Sigstore Fulcio keyless and recorded in Rekor. The auditor's recipe (in [HARDENING.md](HARDENING.md)) gives the exact `cosign verify-blob` invocation. |
| Auditor pointed at a CDN serving stale data | Information disclosure | `stele audit` cross-checks the latest checkpoint against the external anchor (Rekor). A stale CDN gets caught by anchor freshness. |

---

## 4. Cross-cutting properties

### 4.1 Defence in depth

Stele intentionally stacks defences so that **no single layer is
load-bearing**:

- **Producer signs** the envelope (Ed25519 ± Dilithium3).
- **Operator hash-chains + Merkle-commits** the entry.
- **Operator signs** the checkpoint (single ± threshold ± hybrid).
- **Witness cosigns** the checkpoint independently.
- **Anchor** records the checkpoint in Sigstore Rekor.
- **Drand beacon** binds the checkpoint to a public time reference.

To insert a forged entry undetectably, an attacker needs to break
*all of these* simultaneously.

### 4.2 What does not require trust

The auditor's verification *should not* require trusting:

- The operator's host integrity.
- Any single witness.
- The network path to the operator.
- The TLS terminator in front of steled.

The auditor *must* trust:

- One of Ed25519, Dilithium3 (in hybrid mode, *both* must break).
- One of the public anchors (Rekor or drand beacon) being honest.
- The cosign-verified verify CLI binary.
- The root pubkey they obtained out of band (e.g. printed at log
  inception, sealed in physical safekeeping, fetched via DNSSEC).

### 4.3 What changes the threat model

Three configuration choices materially change what stele defends:

1. **`--pq-mode classical` vs `hybrid`** — classical is safe against
   classical adversaries today; hybrid additionally resists a
   future quantum break of Ed25519.
2. **HSM vs on-disk keys** — HSM upgrades "host compromise lets
   attacker forge current-epoch sigs" to "host compromise lets
   attacker request signatures through HSM only, no key
   exfiltration."
3. **Single-sig vs threshold** — single-sig requires one operator
   key compromise; threshold requires t cosigner compromises.

These choices are orthogonal — production-grade deployments use all
three (hybrid + HSM + threshold).

---

## 5. Out of scope

Honest enumeration of what stele does NOT defend against:

- **Physical attacks on the operator host.** A motivated attacker with
  physical access to the steled host can read RAM, snapshot disk, etc.
  Mitigation is a hardware HSM + full-disk encryption + tamper-evident
  hardware. Stele does not provide these.
- **Compromise of the Go toolchain or any direct dependency.** Stele's
  supply chain is hardened (see `.github/workflows/release.yml` +
  `hardening.yml`: govulncheck, gosec, Dependabot, reproducible builds,
  Sigstore-signed releases). A backdoor in `crypto/ed25519` or
  `golang.org/x/sys` is out of scope.
- **Compromise of Sigstore / Rekor / Fulcio infrastructure.** Stele
  uses these as external anchors and as signing roots for releases. A
  full Sigstore takeover degrades the anchor guarantee, not the
  per-entry guarantee.
- **Denial of service.** The protocol is fail-safe (refuses to append
  rather than produce a bogus entry), so DoS impairs availability but
  cannot fabricate provenance.
- **Pre-existing forgery in producer source code.** If the producer's
  own software signs an envelope claiming "user X did Y" when X did
  not, stele faithfully records that lie. Stele records what the
  producer signs; it does not validate the producer's claims.
- **Side-channel attacks on the HSM, the Ed25519 implementation, or the
  Dilithium3 implementation.** Timing leaks, EM emissions, fault
  injection on specific hardware are vendor-level concerns.
- **Plaintext content sensitivity.** Stele does not encrypt entry
  payloads. If your audit log contains secrets, you must encrypt them
  before submission (the envelope is opaque bytes to stele).
- **Pre-image attacks against SHA-256.** Mitigation: switch to
  SHA-384 or SHA-3 if SHA-256 ever shows weakening. The Merkle hasher
  is centralised at [pkg/merkle/merkle.go:22](pkg/merkle/merkle.go).

---

## 6. Trust roots

The smallest set of things that must be trusted for the system to be
secure end-to-end:

1. **Root operator pubkey**, obtained out of band by the auditor
   (printed at log inception + sealed; or distributed via DNSSEC TXT
   record under the log's origin).
2. **The verify CLI binary**, verified by cosign against the published
   release certificate identity tied to this very GitHub repository.
3. **One** of: at least one honest witness signing checkpoints, OR at
   least one public anchor (Rekor / drand) functioning.

That is the entire trust base. Everything else is checked locally by
the auditor with cryptographic proofs the operator cannot forge.

---

## 7. How to extend this doc

When you add a feature, ask:

1. **What's the new asset, if any?** (Add to §1.)
2. **Who can talk to it?** (Update §2.)
3. **What new STRIDE threats does it introduce, and what's the
   matching defence in code?** (Add a row to the right table in §3.)
4. **What's now in scope that wasn't?** (Move from §5 to §3.)
5. **What's the smallest set of new things an auditor must trust?**
   (Update §6.)

If a feature can't be slotted in cleanly, that's usually a sign it
hasn't been thought through enough yet.
