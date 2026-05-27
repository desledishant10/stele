# Strengthening stele

What ships today is a solid v1. This document is a roadmap of concrete
additions that would harden stele further, organized by the threat each
addition defends against, with effort estimates and prioritization.

If you're operating stele in adversarial environments — financial
services, government, healthcare, anything with serious insider-threat
risk — the items in **Tier 1** are not optional.

---

## Tier 1 — Things every production deployment should add

### 1.1 Hardware Security Module (HSM) for the operator key

**What stele has today.** The operator's active epoch private key lives
in a file at `<datadir>/keys/active.key` with mode `0600`. The forward-
secure rotation means a key compromise has bounded blast radius (only
the current epoch can be forged), but the file is readable by anyone
with root on the operator host.

**The threat this remains exposed to.** An attacker who roots the
operator host can copy `active.key`, then go to a different machine
where they aren't being monitored and forge checkpoints until the
operator next rotates. Even with auto-rotation every 1 hour, that's a
1-hour forgery window per breach.

**The fix.** Store the active private key in an HSM. Common choices:

- **YubiHSM 2** — physical USB device, ~$650, supports Ed25519. Good
  for self-hosted single operator.
- **AWS CloudHSM** — managed HSM-as-a-service, supports Ed25519 via
  PKCS#11.
- **GCP Cloud KMS HSM-protected keys** — supports Ed25519.
- **Azure Key Vault Managed HSM** — same.
- **Thales/SafeNet Luna 7** — enterprise on-prem HSM.

The operator process never sees the private key. It calls
`signer.Sign(message)` and the HSM does the cryptography internally.
Stealing the key requires physical or HSM-credential compromise, not
just root on the operator host.

**Implementation in stele.** Replace `fwdsec.Signer.activePriv` and
the `ed25519.Sign(...)` call with a PKCS#11 client call. Use
`github.com/miekg/pkcs11`. Approximate effort: 2-3 days for someone
familiar with PKCS#11; 1-2 weeks otherwise. ~400 lines.

**Threat-model improvement.** Removes the "active key sits on disk"
class of attack entirely. The new requirement to forge a checkpoint is
"compromise the HSM" (much harder) or "be the attacker's process
running on the operator host while it's actively signing" (limited
window, detectable).

### 1.2 mTLS on the ingest endpoint

**What stele has today.** The `/api/v0/append` endpoint accepts any
HTTP POST. Producer-side cryptographic signature is the only auth: an
attacker with a stolen producer key can submit forever. A network
attacker who doesn't have any producer key cannot submit valid envelopes
(the operator rejects unregistered keys) but can DoS, scrape, or scout.

**The fix.** Require client certificates signed by an operator-run CA.
Bind each producer's certificate Common Name to its Producer ID in the
operator's registry. The signing key on the producer device must match
the cert.

**Implementation in stele.** Standard library: `crypto/tls.Config` with
`ClientCAs` + `VerifyPeerCertificate` hook. The hook looks up the
Producer ID by the cert's CN and confirms the envelope's `PublicKey`
matches what the registry has for that ID. Approximate effort: 1-2
days. ~200 lines.

**Threat-model improvement.** Adds network-layer authentication. Now,
forging an entry requires: stolen producer key *and* stolen producer
TLS client cert *and* network access to the ingest endpoint. The
combination is significantly harder than a key file alone.

### 1.3 Public read-only mirror

**What stele has today.** Auditors fetch entries from the operator's
HTTP API directly. A determined operator can refuse to serve old
entries to specific auditors (selective disclosure), only revealing the
"full" log to parties they trust to be cooperative.

**The fix.** A `stele-mirror` daemon that pulls every entry from the
operator and serves a strict replica. Third parties run their own
mirrors; auditors who don't trust the operator query a mirror they do
trust. If the mirror and operator disagree about an entry, that's
catchable.

**Implementation in stele.** New binary `cmd/stele-mirror` and package
`pkg/mirror`. The mirror is a stele instance in "follower mode":
- Background goroutine pulls `GET /api/v0/entries?from=X&to=X+1000`
- Verifies every entry's envelope + chain link
- Stores into its own BadgerDB
- Serves the same read endpoints as the operator
- Refuses to serve entries that don't verify

Approximate effort: 3-5 days. ~800 lines.

**Threat-model improvement.** Defeats selective-disclosure attacks.
The operator can no longer show different views of history to different
auditors — any auditor can pick which mirror to trust.

### 1.4 Auto-rotation triggers

**What stele has today.** The operator key rotates when an admin runs
`stele rotate` manually, or never. There's no scheduled rotation, no
event-driven rotation, no panic rotation.

**The fix.** Automatic rotation on a cron (every 1 hour by default)
plus event-driven rotation triggered by:
- Unexpected file modification under `<datadir>/keys/`
- File integrity check failure
- Sudden anomalous append rate (10x normal, 0.1x normal)
- Failed login on the host (via syslog hook)
- New process tree spawned by the operator daemon
- Any append from a producer that's been revoked

**Implementation in stele.** A `pkg/watchdog` package. Tickers and
fsnotify watchers feed into a single channel; any event triggers
`log.Rotate()`. Approximate effort: 1-2 days. ~250 lines.

**Threat-model improvement.** Shrinks the forgery window from
"until manual rotation" to "until next rotation tick, typically seconds
to minutes."

### 1.5 Memory protection for keys

**What stele has today.** The active private key is in Go's normal heap.
A core dump, swap leak, or memory-read exploit could expose it.

**The fix.**
- `mlock` the key memory so it never swaps to disk.
- Use `syscall.Madvise(MADV_DONTDUMP)` so it's not in core dumps.
- Zero memory on rotation (already done).
- On Linux, consider running the operator under seccomp to block
  `ptrace` and prevent debugger attachment.

**Implementation in stele.** Add to `fwdsec.Signer` initialization on
Linux/Darwin. ~50 lines, plus runtime config for seccomp.

**Threat-model improvement.** Closes side-channel exposure of the
active key.

---

## Tier 2 — Genuinely advanced (your industry will lag)

### 2.1 Threshold operator signatures

**What stele has today.** A single operator key signs each checkpoint.
HSM-protected, forward-secure, rotated — but still one key.

**The fix.** Replace single-party Ed25519 with N-of-M threshold
signatures. The "operator" becomes (say) 3 internal security people
holding hardware tokens. Any 2-of-3 must agree to sign each checkpoint.
No single compromise can forge.

Use one of:
- **FROST (Flexible Round-Optimised Schnorr Threshold)** — modern,
  efficient, well-studied
- **GG18/GG20** — for ECDSA threshold (not Ed25519)
- **Sparkle** — Schnorr threshold over Ed25519's curve

**Implementation in stele.** Significant. Use
`github.com/coinbase/kryptology` (FROST), build the multi-round
protocol, replace `fwdsec.Signer` with a threshold variant. Operational
complexity: each of the M participants needs a hardware token, a
signing app, a key generation ceremony at bootstrap. ~1500 lines plus
operational documentation.

**Threat-model improvement.** Removes the single point of cryptographic
compromise. To forge a checkpoint, an attacker must simultaneously
compromise at least the threshold number of participants — each on
different devices, different physical locations, different humans.

### 2.2 Witness gossip protocol

**What stele has today.** Witnesses don't communicate with each other.
A sophisticated operator could submit slightly different checkpoints to
different witness subsets — each witness signs a different "story." No
witness compares notes.

**The fix.** Witnesses periodically pull each other's most recent
checkpoint. If witness Alice sees a checkpoint for size 142 with root
R1, and her peer Bob has signed root R2 at the same size, that's an
instant FORK alarm both witnesses publish.

**Implementation in stele.** Either:
- HTTP pull every 30 seconds between witnesses (simple, ~300 lines)
- libp2p PubSub for real-time (more complex, ~800 lines)

Add witness-witness mutual auth via a small "I trust these witness
public keys" file at each.

**Threat-model improvement.** Closes the "split-brain operator" attack.
Currently, a compromised operator could maintain divergent histories
visible to different subsets of witnesses; gossip detects this.

### 2.3 Verifiable producer-key history

**What stele has today.** A producer's key is held in the registry. The
operator could quietly swap a producer's public key in the registry,
then accept envelopes from a new attacker-controlled key as if they
came from the legitimate producer.

**The fix.** Producer key changes are themselves logged into the main
stele log as special entries. Every key rotation becomes part of the
tamper-evident history.

**Implementation in stele.** New entry kind `producer_key_change` with
its own canonical encoding. The registry is rebuilt on replay from
these log entries instead of a separate Badger table. Verifiers can
recompute who was authorized at any point in time.

Approximate effort: 1-2 days. ~300 lines plus migration.

**Threat-model improvement.** Sneaky registry edits become detectable.

### 2.4 Tor onion service for operator endpoint

**What stele has today.** Operator endpoint exposed at a public IP
(or behind a corporate firewall). DDoS, network-layer attacks, location
leak, and TLS-handshake-time correlation attacks are all possible.

**The fix.** Run the operator (and witnesses) as Tor onion services.
Onion services get strong authentication built into the address, no
public IP, and resistance to network-layer attacks. Approximate effort:
configuration only, no code changes.

**Threat-model improvement.** Defeats most network-layer attacks plus
geographic-correlation attacks.

### 2.5 DNSSEC-anchored operator root key

**What stele has today.** New auditors learn the operator's root public
key out-of-band — usually by being told it over Slack or copying it
from a website. They could be tricked into trusting an
attacker-controlled root.

**The fix.** Publish the root public key in a DNSSEC-signed TXT record
at `_stele.example.com`. Auditors look it up via DNS. The chain of
trust runs through DNSSEC, which has its own well-audited PKI.

**Implementation in stele.** Almost no code change — just an
operational procedure to publish the TXT record and a `stele
--anchor-dns example.com` flag that auto-fetches and validates.

**Threat-model improvement.** Reduces social-engineering attack surface
for new auditors. Anyone who knows your domain name can find your
correct root key.

---

## Tier 3 — Bleeding-edge cryptography

### 3.1 Post-quantum signature scheme

**The threat.** Ed25519 (and SHA-256 in the Merkle tree) are not
quantum-safe. A sufficiently large quantum computer breaks Ed25519
using Shor's algorithm. SHA-256 is partially weakened by Grover's
algorithm. Estimates of when this becomes practical range from 10 to
30 years.

**The fix.** Replace Ed25519 with Dilithium (NIST PQC final standard,
ratified 2024) or a hybrid Ed25519+Dilithium scheme. Use SHA-3 instead
of SHA-256.

**Implementation in stele.** Use Cloudflare's `circl` library
(`github.com/cloudflare/circl/sign/dilithium`). Major refactor of every
signature site. Approximate effort: 1-2 weeks. ~600 lines.

**Threat-model improvement.** Future-proofs against the quantum
threat. Important for data that needs to remain verifiable for decades.

### 3.2 Zero-knowledge proofs of selective disclosure

**The threat scenario.** Sometimes you want to prove "I logged the
event you're asking about" without revealing the other entries that
were also logged. Or "the total number of events in my log matches
exactly N." Or "I never logged any event involving user X."

**The fix.** Use ZK-SNARKs to produce proofs that satisfy these
statements without revealing the underlying data. Groth16 over BN254
or PLONK over BLS12-381 are common choices.

**Implementation in stele.** Significant. Use `gnark` (ConsenSys).
Write SNARK circuits for the relevant relations (Merkle inclusion,
signature verification, range queries). Approximate effort: 3-6 weeks.

**Threat-model improvement.** Opens privacy-preserving auditability:
"prove to a regulator that you logged this class of events without
revealing the events themselves." Useful for healthcare, finance, and
intelligence/government use cases.

### 3.3 Verifiable Delay Functions between checkpoints

**The threat.** Currently, the time between checkpoints is enforced only
by the operator's scheduler. A compromised operator could mint many
checkpoints in rapid succession backdated to look like they were spaced
out.

**The fix.** Each checkpoint must include a VDF computation from the
previous checkpoint's root. A VDF takes provably long wall-clock time
to compute (e.g. 1 hour of single-thread CPU). Forging a "weekly"
sequence requires actually waiting a week.

**Implementation in stele.** Use Wesolowski VDF over RSA groups (the
standard). Approximate effort: 2-3 weeks. ~500 lines + parameter
generation ceremony.

**Threat-model improvement.** Time itself becomes cryptographically
enforced. Backdating attacks are defeated even without the drand
beacon (and become impossible with both).

### 3.4 Anonymous credentials for auditors

**The threat.** Auditors who query the operator's API reveal their
identity to the operator (via IP, TLS client cert, etc.). A malicious
operator could surveil auditors.

**The fix.** Use blind signatures or anonymous credentials so auditors
can prove "I am authorized to audit" without revealing who they are.

**Implementation in stele.** Use BBS+ signatures or Idemix. Significant
cryptographic engineering. ~1000 lines.

**Threat-model improvement.** Auditor privacy. Useful for journalist /
regulator / whistleblower use cases where the operator might retaliate
against auditors they can identify.

---

## Tier 4 — Detection layer

### 4.1 Tamper-evident read log

**The fix.** Every read of an entry gets logged into a sibling sub-log,
which is itself anchored. Even attempts to query the main log produce
auditable evidence.

**Implementation in stele.** A second core.Log instance dedicated to
read events. Each `GET /entries/{idx}` writes an entry to it before
serving the response. Anchoring + witnesses + Rekor as for the main
log.

**Threat-model improvement.** Catches "I read this thing but didn't
tell anyone." Used in combination with honeylog, gives near-zero
false-negative detection of unauthorized access.

### 4.2 Anomaly detection on append rate

**The fix.** Maintain a rolling window of append rates and alert on:
- Sudden surge (potential exfiltration disguised as logging)
- Sudden drop to zero (potential silent suppression)
- Unusual per-producer patterns

**Implementation in stele.** A small statistics goroutine, ~300 lines
including config for thresholds.

### 4.3 Independent fork-detector

**The fix.** A separate daemon (`stele-watcher`) runs nightly. It asks
every witness for its current view AND fetches the operator's view AND
checks Sigstore Rekor. If any two report inconsistent roots at the
same size, page someone.

**Implementation in stele.** Standalone binary, ~400 lines. Can run on
any infrastructure independent from the operator.

---

## Tier 5 — Supply chain protection

Even if stele itself is mathematically perfect, the binary you're
running could have been trojaned at build time.

### 5.1 SLSA Level 4 build provenance

**The fix.** Build stele in a fully isolated, reproducible environment.
Publish build attestations to Sigstore Rekor. Every running stele
binary is cryptographically traceable back to a specific git commit
and build environment. SLSA Level 4 is the highest level.

**Implementation.** GitHub Actions with the official SLSA generators.
~3 days of CI work, no code changes.

### 5.2 Cosign signing of releases

**The fix.** Every released binary is signed with cosign, signature
anchored to Rekor. Verifiers must check the binary they're running
before trusting any output.

**Implementation.** Standard cosign release flow. ~1 day.

### 5.3 Reproducible builds

**The fix.** Same source + same Go version + same build flags = bit-
for-bit identical binary. Any auditor can build their own copy and
verify it matches the released binary.

**Implementation.** Set `CGO_ENABLED=0`, pin Go version, strip
timestamps and build paths from the binary. ~1 day.

---

## Tier 6 — Operational hardening

### 6.1 Air-gapped witnesses

Run at least one witness on a machine that is *not network-connected*.
Checkpoints flow in via USB stick, QR code, or one-way serial cable.
The witness's signature flows back the same way. Even total network
compromise can't reach an air-gapped witness.

### 6.2 Geographic and legal-jurisdiction distribution

Witnesses in different legal jurisdictions makes coercion-based attacks
much harder. A reasonable starting set: EU + US + Switzerland +
Singapore + Iceland. No single government can compel all of them.

### 6.3 Public canary statements

The operator publishes a daily signed statement: "I am not under any
government warrant to alter the stele log." If a government issues a
gag order, the operator can't publish that statement anymore — its
absence is the signal. Same pattern Apple, Twitter, and several ISPs
use for transparency reports.

### 6.4 Witness diversity rules

Require witnesses to satisfy:
- Different cloud providers (one AWS, one GCP, one bare-metal)
- Different countries
- Different organizational affiliations
- Different software versions (one on stele 1.0, another on 1.1)

This makes correlated compromise much harder.

---

## Tier 7 — Things that would be cool but are research-grade

### 7.1 Stele-on-blockchain bridge

Anchor not just to Sigstore Rekor but ALSO to a public blockchain
(Bitcoin, Ethereum). Use OpenTimestamps for Bitcoin. Provides a
permanent anchor that not even Sigstore can revoke.

### 7.2 ML-driven anomaly detection on log content

Train a small model on normal log content and alert on outliers (sudden
appearance of new types of events, unusual sequences). Becomes
complementary to honeylog.

### 7.3 Multi-operator log

A single log written to by multiple operators (each with their own
keys), where each entry is signed by exactly one operator but the chain
is shared. Useful for federated systems where multiple parties
contribute to the same audit trail.

### 7.4 Encrypted entries with key escrow

Allow producers to encrypt entries to a known set of recipient public
keys. Only the holders of those keys can read the content; the operator
sees only ciphertext. Combined with stele's integrity, this gives
"encrypted, tamper-evident, audited" — close to ideal for healthcare
records.

---

## Priority recommendation

If I were building a production deployment, I'd add features in this
order:

| Priority | Item | Tier | Effort | Why first |
| -------- | ---- | ---- | ------ | --------- |
| 1 | HSM for operator key | 1.1 | Medium | Largest single jump in real security |
| 2 | mTLS on ingest | 1.2 | Small | Cheap, immediate |
| 3 | SLSA Level 4 + cosign signing | 5.1+5.2 | Small | Supply chain is everyone's blind spot |
| 4 | Auto-rotation triggers | 1.4 | Small | Shrinks forgery window from hours to seconds |
| 5 | Witness gossip | 2.2 | Medium | Closes the most-known protocol gap |
| 6 | Public read-only mirror | 1.3 | Medium | Operationally essential at scale |
| 7 | Threshold operator signatures | 2.1 | Significant | For high-value deployments |
| 8 | Post-quantum signatures | 3.1 | Significant | For long-term-archive deployments |

Beyond #8, the priority depends on your specific threat model.

- A **bank** should prioritize threshold signatures, HSM, geographic
  jurisdiction diversity.
- A **healthcare provider** should prioritize encryption + key escrow,
  HIPAA-compliant HSM, ZK selective disclosure.
- A **government agency** should prioritize air-gapped witnesses,
  post-quantum, jurisdictional diversity.
- A **journalist or activist** should prioritize Tor onion services,
  anonymous credentials, geographic distribution to non-five-eyes
  jurisdictions.

Each of these tiers compounds. Adding all of Tier 1 alone moves stele
from "a tool a single security-aware company runs internally" to "a
tool a regulator could mandate."
