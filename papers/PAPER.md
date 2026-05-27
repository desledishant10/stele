# Stele: a Provenance-Anchored Audit Log

**Status**: draft outline + abstract. Not yet submitted anywhere.
This file is the starting point for a real academic submission.

## Suggested venues

In rough decreasing fit:

| Venue | Why | Deadline (typical) |
|---|---|---|
| **USENIX Security** | Practical security systems; tamper-evident logs precedent (Certificate Transparency papers) | Feb / June |
| **NDSS** | Same audience as USENIX Security; faster review | July |
| **IEEE S&P (Oakland)** | More theory-leaning but accepts well-engineered systems | Nov |
| **ACM CCS** | Crypto + systems blend | May |
| **ACSAC** | Applied security, friendly to industrial work | June |
| **DSN** | Dependability angle (fork detection, witness mesh) | Dec |

USENIX Security is the most natural fit. Cite [Laurie et al. 2013
"Certificate Transparency" RFC 6962] in the related work; we sit
adjacent to that tradition.

## Working title

> **Stele: Tamper-Evident Audit Logs with Hybrid Post-Quantum Signatures,
> Witness Mesh Fork Detection, and Cryptographic Producer Enrollment**

## Abstract (draft)

> Audit logs are load-bearing for compliance, incident response,
> regulatory action, and legal proceedings — and yet most real-world
> audit logs offer only operational integrity: a sufficiently
> motivated insider, or a single host-level compromise, can
> retroactively rewrite history. We present **stele**, a
> tamper-evident audit log built on an RFC 6962 Merkle tree with
> three protocol-level guarantees not previously combined in a
> single deployable system: (1) forward-secure operator signing
> with destruction of past keys (forward secrecy of historical
> entries), (2) a witness mesh with signed seen-roots and gossip-
> based fork detection that catches a malicious operator
> presenting divergent histories to different parties, and (3) a
> producer enrollment ceremony with proof-of-possession that binds
> every accepted entry to a mutually-signed, log-recorded
> authorisation. Every signature site is hybrid: classical Ed25519
> plus NIST FIPS-204 Dilithium3 (ML-DSA Level 3), with the wire
> format constructed so that classical-only producers and hybrid-
> mode operators interoperate without downgrade attacks. We give
> a Tamarin symbolic-model proof of the three core protocol
> claims, and a Go reference implementation with fuzz, property-
> based, race, and chaos-injection test coverage. A 30-minute
> 200-RPS soak on the chaos rig produced 181,639 entries with
> zero integrity events.

## Section outline

### 1. Introduction
- Motivation: real-world log tampering incidents
- The gap: Certificate Transparency proves what's PUBLIC; private
  audit logs need similar properties without the public-anchor
  baggage
- What stele provides: protocol + reference impl + formal verification

### 2. Background and related work
- RFC 6962 Merkle tree (CT)
- Sigstore Rekor (transparency-as-a-service)
- Trillian, Key Transparency
- Forward-secure signatures (Bellare-Miner 1999; Itkis-Reyzin 2001)
- Verifiable random functions / VDFs (deferred)
- Recent post-quantum standards (NIST FIPS 204 / 205 / 206)

### 3. Threat model
- Actors: operator, producer, witness, mirror, auditor, attacker
- Goals: integrity, non-repudiation, forward secrecy, fork detection
- Non-goals (honest scope): availability, confidentiality of
  entry payloads, side-channel resistance of the underlying primitives
- (Mirror this from THREATMODEL.md, condensed)

### 4. Protocol
- 4.1 Hash chain + RFC 6962 Merkle tree
- 4.2 Forward-secure rotation (operator chain)
- 4.3 Witness mesh: cosignature + gossip + cross-attestations
- 4.4 Producer enrollment with proof-of-possession
- 4.5 Hybrid signatures across every site
- 4.6 External anchoring (Rekor, drand)
- 4.7 Replay protection, tripwire, watchdog

### 5. Formal verification
- Tamarin model of the three core claims
- Symbolic-to-computational reduction discussion
- What's NOT modeled (replay, threshold, hybrid — and why)
- Verified with `tamarin-prover` in ~minutes

### 6. Implementation
- Go reference (~22k LoC)
- Cross-platform support matrix
- HSM via PKCS#11; threshold via independent cosigners
- Cross-language SDKs (Python, TypeScript) with byte-identical
  envelope canonicalisation, verified by 36 deterministic test
  vectors

### 7. Evaluation
- Microbenchmarks (Append, Merkle proof generation, signing)
- Sustained soak (181K entries / 30 min on Docker Desktop)
- Chaos: byzantine witness scenarios (4 cases), clock skew (6),
  disk tamper via tripwire (4)
- Supply-chain: SLSA L4, reproducible builds, cosign signing, SBOM

### 8. Deployment patterns
- Single-host (sysadmin), Helm (k8s), bare-metal (systemd)
- DR runbook + quarterly drill cadence
- Compliance mapping (SOC 2 / NIST / ISO)

### 9. Discussion and limitations
- No production deployment yet
- 30-minute soak vs the 72-hour soak the project plans
- Performance ceiling at ~7K appends/sec on a single fsync-bound
  host; future work: WAL batching, on-disk Merkle
- Producer-payload encryption left to the producer
- HSM tested only via SoftHSM2

### 10. Conclusion + future work

### A. Tamarin model listing
### B. Selected vector outputs
### C. Comparison table vs CT / Rekor / Trillian / commercial competitors

## Key figures (sketches)

1. **System diagram**: operator + 3 witnesses + mirror + Rekor.
2. **Rotation chain timeline**: epoch 0 → 1 → 2 with key destruction.
3. **Witness gossip + cross-attestation flow**: how a forking
   operator gets caught.
4. **Enrollment ceremony sequence diagram**: begin → challenge →
   confirm with both signatures.
5. **Soak memory growth**: linear-with-log-size (predictable, not a
   leak).
6. **Microbenchmark table**: Append RPS, proof gen latency, signing
   latency vs alternatives.

## Comparison table (for §C)

| Property | stele | RFC 6962 CT | Sigstore Rekor | Trillian | Commercial X |
|---|---|---|---|---|---|
| Tamper-evident Merkle root | ✓ | ✓ | ✓ | ✓ | ✓ |
| Forward-secure operator key | ✓ | ✗ | ✗ | ✗ | ✗ |
| Hybrid PQ signatures | ✓ | ✗ | ✗ | ✗ | ✗ |
| Witness mesh fork detection | ✓ | partial | ✗ | ✗ | ✗ |
| Threshold operator | ✓ | ✗ | ✗ | ✗ | ✗ |
| Producer enrollment with PoP | ✓ | n/a | ✗ | ✗ | ✗ |
| Continuous tripwire | ✓ | ✗ | ✗ | ✗ | partial |
| Formal model | ✓ (Tamarin) | partial | ✗ | ✗ | ✗ |

## Submission checklist (for when the paper is ready)

- [ ] All claims supported by tests + Tamarin proofs
- [ ] Reproducibility artifact: this repo, tagged at submission commit
- [ ] Anonymisation: rename references to authors in commit messages, comments, etc.
- [ ] Page limit: 13 pages USENIX style (excluding refs)
- [ ] LaTeX in `papers/main.tex` once we're past outline
- [ ] Ethics statement: no human subjects; security-tool publication does not introduce new attack
- [ ] Conflict of interest disclosures

## Things to expect reviewers to ask

| Likely question | Pre-rehearsed answer |
|---|---|
| Why not just use CT / Rekor? | They're public anchors; stele is for *private* audit logs that still need third-party verifiability |
| What stops the operator from omitting entries? | They can't — witnesses cosign the Merkle root and would notice missing entries when their seen-map disagrees with the operator's |
| Threshold mode is just N parallel signatures? | Yes, intentionally: t-of-N gives the same security as FROST in our threat model, with materially simpler verification (t signature checks vs. one Schnorr proof) |
| Why hybrid instead of pure-Dilithium? | Compatibility + defence in depth: a future weakness in Dilithium doesn't compromise the log if Ed25519 still holds |
| Production deployment? | Not yet — paper is concurrent with the v0.1.0 release. We'll have one by camera-ready |
