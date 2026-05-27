# Stele Compliance Mapping

This document maps stele's defences to the control families used by
the three audit/compliance frameworks an enterprise procurement team
will most often ask about:

- **SOC 2** (AICPA Trust Services Criteria, 2017 + 2022 updates)
- **NIST SP 800-53 Rev. 5**
- **ISO/IEC 27001:2022** (Annex A controls)

**Honest framing up front.** This is a control *mapping*, not a
certification. Stele has not been audited by an accredited firm. The
mapping is provided so that:

1. Your compliance team can answer "yes, stele covers control X.Y.Z"
   when their auditor asks during your firm's audit.
2. Your team can identify the gaps stele does NOT cover, and arrange
   the rest of your stack accordingly.
3. If you pursue formal certification of an environment that
   includes stele, the auditor has a ready-made reference document.

If you're after FedRAMP / HIPAA / PCI-DSS — those map cleanly onto
NIST 800-53 and SOC 2, so the mapping below covers them
transitively. Drop us a note if you need a control-specific bridge.

---

## Quick verdict per framework

| Framework | What stele covers | What it doesn't |
|---|---|---|
| SOC 2 (Security + Confidentiality + Availability) | All "audit log integrity" controls; key management; change tracking | Org-level controls (HR, vendor management, physical security) — not stele's job |
| NIST 800-53 Rev. 5 | AU (Audit & Accountability), SC (System & Comms Protection), SI (System & Information Integrity), IA-5 / IA-7 (Authenticator Mgmt + Crypto) | AC family beyond mTLS (RBAC, ABAC), PE (Physical), PS (Personnel) |
| ISO 27001:2022 | A.5.32 (privileged user activity), A.8.15 (event logging), A.8.16 (monitoring), A.8.20 (network), A.8.24 (cryptography) | A.6 (HR), A.7 (Physical) |

Stele is **a control implementation**, not **a complete compliance
program**. It maps to the technical controls that produce audit
evidence; your org still owns the operational + people + physical
controls.

---

## SOC 2 Trust Services Criteria mapping

| TSC | Description | How stele addresses it |
|---|---|---|
| **CC4.1** | Monitoring activities are designed and implemented | Operator emits 18 Prometheus metrics; Grafana dashboard + alert rules ship with the project. `/healthz`, `/readyz`, `/metrics` are standard endpoints. See [PLAYBOOK §4.4](PLAYBOOK.md#44-monitoring). |
| **CC5.2** | Internal controls over data integrity | Hash-chained entries + RFC 6962 Merkle tree + multiple witness countersignatures. Every entry is provably immutable post-commit; any modification breaks the chain. See [THREATMODEL §3.1](THREATMODEL.md). |
| **CC6.1** | Logical access — restrict authorized users | mTLS for producer ingest (`--client-ca`); per-producer enrollment ceremony with operator-side signature + producer-side proof-of-possession. Unenrolled producers are rejected when `--require-enrollment` is set. |
| **CC6.6** | Authentication mechanisms protect against unauthorized access | Producer keys never leave the producer host; operator-side enrollment binds a specific Ed25519 pubkey to a producer ID, signed by the operator's chain key. mTLS adds a second factor (TLS client cert) bound to the same producer ID via CN-equals-ProducerID enforcement. |
| **CC6.7** | Confidential information transmitted, processed, stored is protected | TLS (≥ 1.3 required) for every API call; mTLS for ingest. Entry payloads are NOT encrypted at rest by stele — that's a producer-side concern; see "What stele does NOT cover" below. |
| **CC6.8** | Prevention/detection of unauthorized or malicious software | Continuous tripwire (`--tripwire-every`) re-derives the Merkle root from on-disk state every hour by default; any mismatch fires an alert. Watchdog (fsnotify) catches any modification to the key directory and force-rotates. |
| **CC7.1** | Detect changes in system components | Admin log records every rotate / enroll / revoke / witness mutation. The log is itself signed + hash-chained + auditable. |
| **CC7.2** | Anomalies are evaluated to determine if they represent threats | Watchdog rate-anomaly detector triggers on 10x surges or 0.1x drops; honeypot canaries fire on any access to entries pre-marked as honeylog. |
| **CC7.3** | Continually monitor for security events | Prometheus alert rules ship with the project; `/metrics` exposes the full surface. |
| **CC7.4** | Respond to identified security events | [RECOVERY.md](RECOVERY.md) provides a 9-section incident runbook. |
| **CC8.1** | Authorize, design, develop changes | Admin log captures every rotate, producer / witness / threshold-group change. PRs against stele itself go through the [CONTRIBUTING.md](CONTRIBUTING.md) review process. |
| **C1.1** | Identifying confidential information | Honeypot canary entries; honeylog alert sink. |
| **C1.2** | Retention requirements | Stele is append-only — entries are never deleted. Retention policy is operationally decided by the operator (e.g. by archiving + truncating shrinks the disk DB but the Merkle chain history remains anchored to Rekor). |
| **A1.1** | Maintain processing capacity | Per-producer rate limit (`--per-producer-rps`) + bounded concurrency (`--max-concurrent-appends`) + 429/503 with `Retry-After` headers. Documented baseline of ~7K append/sec in [SOAK.md](SOAK.md). |
| **A1.2** | Backup and recovery | `stele-backup` + `stele-export-chain` CLIs; [RECOVERY.md](RECOVERY.md) runbook. |
| **A1.3** | Tested disaster recovery | RECOVERY.md prescribes a quarterly drill. |

---

## NIST 800-53 Rev. 5 control mapping

This table covers the controls most often relevant to a system whose
job IS auditing. The full NIST catalog is large; we list controls
stele genuinely implements + a few near-misses worth being explicit
about.

### Audit & Accountability (AU)

| Control | Description | Stele |
|---|---|---|
| **AU-2** | Event logging | Every Append is captured into the main log; every read into the read log; every admin action into the admin log. All three are signed + hash-chained. |
| **AU-3** | Content of audit records | Each entry carries: producer_id, time_ns, source, data, public_key, attestation_type, signature, optional quantum signature, evidence_hash. The operator adds: index, prev_hash, entry_hash, leaf_hash. |
| **AU-3(1)** | Additional information for audit records | Optional `evidence` field carries platform-specific attestation evidence (TPM quote, SEV report, etc.). |
| **AU-4** | Audit storage capacity | Backed by BadgerDB; growth profile documented in [SOAK.md](SOAK.md). |
| **AU-5** | Response to audit logging failures | `/readyz` returns 503 if the log can't be written; ingest endpoints return 503 with `Retry-After` when bounded. |
| **AU-6** | Audit review, analysis, and reporting | `stele audit --pdf` generates a structured compliance report. `stele-watcher` is the standalone cross-checker. |
| **AU-7** | Audit reduction and report generation | Mirror daemons let auditors run their own queries without operator load. |
| **AU-8** | Time stamps | Entries carry the producer's wall-clock; checkpoints carry the operator's wall-clock; drand beacon binds checkpoints to public randomness that didn't exist before the beacon round (defeats backdating). |
| **AU-9** | Protection of audit information | Forward-secure operator chain (past keys destroyed), HSM-backed keys (`--hsm-module`), watchdog tamper detection, tripwire continuous integrity. |
| **AU-9(2)** | Audit backup on separate physical systems | Stele design encourages witnesses + mirrors on independent infra. `stele-backup` + `stele-export-chain` produce off-host artifacts. |
| **AU-9(3)** | Cryptographic protection | Every audit record is signed (Ed25519, optionally also Dilithium3); the Merkle tree commits to immutability. |
| **AU-10** | Non-repudiation | Producer signatures + operator counter-signature + witness counter-signatures + Rekor anchor. An entry's existence cannot be denied by any of those parties. |
| **AU-11** | Audit record retention | Operationally decided (append-only by design). |
| **AU-12** | Audit record generation | Generated by the operator on every `Append`; not subject to operator omission (witnesses + Rekor anchor would catch). |

### System & Communications Protection (SC)

| Control | Description | Stele |
|---|---|---|
| **SC-7** | Boundary protection | HTTP server with explicit timeouts, body caps, per-producer + per-admin rate limits. mTLS supported. |
| **SC-8** | Transmission confidentiality + integrity | TLS 1.3 (configurable); mTLS for ingest. |
| **SC-12** | Cryptographic key establishment + management | Forward-secure chain with destruction of past keys. HSM-backed in production. Threshold (t-of-N) mode optional. |
| **SC-13** | Cryptographic protection | Ed25519 (FIPS 186-5), optionally hybrid with Dilithium3 (FIPS 204). SHA-256 (FIPS 180-4) for hashing. |
| **SC-17** | PKI certificates | `stele ca-init` + `ca-issue-server` + `ca-issue-producer` provide a minimal CA for mTLS. |
| **SC-23** | Session authenticity | Producer envelopes are signed end-to-end; not vulnerable to TLS strip-and-replay (the envelope signature covers content). |
| **SC-28** | Protection of information at rest | Tripwire continuous integrity check; mlock + MADV_DONTDUMP on key memory ([pkg/keyguard](pkg/keyguard/)). |

### System & Information Integrity (SI)

| Control | Description | Stele |
|---|---|---|
| **SI-3** | Malicious code protection | govulncheck + gosec + shadow analyzer in CI; SLSA L4 reproducible builds; cosign-signed releases. |
| **SI-4** | Information system monitoring | 18 Prometheus metrics, OpenTelemetry tracing, structured slog output, `/healthz`, `/readyz`. |
| **SI-7** | Software, firmware, and information integrity | Tripwire fires within `--tripwire-every` on any out-of-band entry modification. |
| **SI-7(1)** | Integrity checks | The same as SI-7. |
| **SI-10** | Information input validation | Every HTTP endpoint is body-size capped (`http.MaxBytesReader`); JSON parsers are fuzz-tested across 11 wire formats with 0 reachable panics. |

### Identification & Authentication (IA)

| Control | Description | Stele |
|---|---|---|
| **IA-2** | Identification + authentication (organizational users) | Producer enrollment with mutual cryptographic consent. Operator chain key authenticates the operator side. |
| **IA-5(1)** | Authenticator management — password-based | N/A — stele uses public-key crypto, not passwords. |
| **IA-5(2)** | Authenticator management — PKI-based | Producer keypair + operator chain key + witness keypair + cosigner keypair (threshold mode). |
| **IA-7** | Cryptographic module authentication | FIPS-186-5-aligned Ed25519, optionally hybrid with FIPS-204 Dilithium3. Centralised primitive selection at [pkg/merkle/merkle.go](pkg/merkle/merkle.go) + [pkg/hybrid](pkg/hybrid/). |

### Configuration Management (CM)

| Control | Description | Stele |
|---|---|---|
| **CM-3** | Configuration change control | All operator config flags + admin actions are captured in the signed admin log. |
| **CM-5** | Access restrictions for change | Admin rate limit (`--per-admin-rps`) + mTLS-based admin identity. |
| **CM-7** | Least functionality | Distroless OCI image; no shell, no package manager; non-root user; systemd unit drops all caps except CAP_IPC_LOCK. |
| **CM-11** | User-installed software | N/A — stele binaries are signed releases; tampering is detected by cosign verify. |

### Other notable controls

| Control | Description | Stele |
|---|---|---|
| **AC-17** | Remote access | TLS-over-network mandated by config; mTLS supported. |
| **CP-9** | Information system backup | `stele-backup` (entry DB) + `stele-export-chain` (operator trust anchor); see [RECOVERY.md](RECOVERY.md). |
| **CP-10** | Information system recovery and reconstitution | 9-section runbook in RECOVERY.md, drill cadence documented. |

---

## ISO/IEC 27001:2022 Annex A mapping

The 2022 revision restructured ISO 27001 into 93 controls across 4
themes. Stele addresses the technological and process-of-evidence
controls below; organisational + people + physical controls remain
your responsibility.

| Control | Title | Stele |
|---|---|---|
| **A.5.7** | Threat intelligence | THREATMODEL.md documents the threat model; updated as new defences land. |
| **A.5.16** | Identity management | Producer enrollment + admin log of identity changes. |
| **A.5.17** | Authentication information | Ed25519 keys, never shared with operator; HSM option for stronger storage. |
| **A.5.23** | Information security for use of cloud services | Helm chart + OCI image with hardened defaults; Sigstore-signed releases verifiable from any cloud. |
| **A.5.32** | Intellectual property rights | Apache 2.0; no proprietary deps. |
| **A.8.5** | Secure authentication | mTLS + cryptographic envelope signatures. |
| **A.8.7** | Protection against malware | govulncheck + gosec + SLSA L4 supply chain. |
| **A.8.9** | Configuration management | Admin log captures every mutation. |
| **A.8.13** | Information backup | `stele-backup`; documented in RECOVERY.md. |
| **A.8.14** | Redundancy of information processing facilities | Mirror daemons + witness mesh. |
| **A.8.15** | Logging | The whole product. |
| **A.8.16** | Monitoring activities | Prometheus + Grafana + alert rules. |
| **A.8.17** | Clock synchronization | drand beacon binding (`--beacon`) for cryptographic time anchoring. |
| **A.8.19** | Installation of software on operational systems | Cosign-signed binaries; verifiable provenance via SLSA. |
| **A.8.20** | Networks security | TLS / mTLS; HTTP timeouts; size caps; rate limits; graceful shutdown. |
| **A.8.21** | Security of network services | NetworkPolicy template in Helm chart; default-deny. |
| **A.8.23** | Web filtering | N/A — stele is a server, not a client. |
| **A.8.24** | Use of cryptography | Centralised primitive selection; FIPS-aligned defaults; optional hybrid PQ. |
| **A.8.25** | Secure development life cycle | CONTRIBUTING.md + HARDENING.md + CI hardening. |
| **A.8.26** | Application security requirements | THREATMODEL.md + per-PR threat-model review per CONTRIBUTING.md. |
| **A.8.28** | Secure coding | Property + fuzz + race + chaos tests; benchstat regression gating. |
| **A.8.30** | Outsourced development | N/A — stele is operated in-house by adopters. |
| **A.8.31** | Separation of development, test, and production environments | Stele itself ships environment-independent binaries; separation is operationally yours. |
| **A.8.32** | Change management | Admin log + CHANGELOG + signed releases. |

---

## What stele does NOT cover (be honest with your auditor)

Use the following table to scope what your other tools / processes
need to handle. Stele is not a complete compliance solution; it's a
specific control implementation.

| Out of scope | Why | What you'll need |
|---|---|---|
| Entry-payload confidentiality | Stele records signatures over content but does not encrypt content at rest. | Producer-side encryption before signing, or a Key Management Service that holds the decryption keys outside stele. |
| User access management / RBAC | The operator's HTTP API only distinguishes "producer", "admin" (via mTLS CN), "auditor" (read-only). No fine-grained RBAC. | A reverse proxy (Envoy, oauth2-proxy, your IdP) in front of the operator. |
| Physical security | Stele runs on whatever host you give it. | Datacenter / cloud provider's controls. |
| Personnel security | Stele doesn't know who your humans are. | HR controls. |
| Threat detection on entry CONTENT | Stele doesn't inspect payloads. | A SIEM downstream of stele consuming the entry stream. |
| Disaster simulation at the org level | Stele drills cover the stele log specifically. | Tabletop exercises, GameDay programs. |
| External dependency audit | Stele commits to govulncheck reachability scanning + Dependabot, but doesn't pin or audit your specific deployment's full dep tree. | SBOM generation (stele ships its own SBOM); your supply-chain audit tooling. |

---

## Practical procurement workflow

When your enterprise procurement team asks "is stele SOC 2 compliant"
(or NIST / ISO equivalent), the right answer is:

> Stele is **not certified**, but the project provides a control
> mapping (this document) showing which technical controls in the
> framework are addressed by stele's design. The operator
> deployment + the rest of your stack collectively achieve
> certification when audited together. Stele's role is to be the
> *audit log* — the system that produces the evidence the auditor
> reviews.

If your auditor wants more than that, the project can answer
specific control questions via the disclosure flow in
[SECURITY.md](SECURITY.md).

For a third-party security audit of stele itself (separate from
SOC 2 of your environment), the test surface in [HARDENING.md](HARDENING.md)
+ the threat model in [THREATMODEL.md](THREATMODEL.md) is the
auditor's starting kit.
