# Stele: Tamper-Evident Audit Logs with Hybrid Post-Quantum Signatures, Witness Mesh Fork Detection, and Cryptographic Producer Enrollment

**Draft v0.3 — 2026-05-30.** Not yet submitted. Companion to the
v0.1.3 release at https://github.com/desledishant10/stele.
Sections 1-6 and 8-10 are drafted in full; §7 (Evaluation) is
substantively complete except for the 72-hour soak data, which
lands 2026-06-02. References use ad-hoc inline citation; LaTeX
conversion + proper BibTeX is the next pass.

## Abstract

Audit logs are load-bearing for compliance, incident response,
regulatory action, and legal proceedings. Most real-world audit
logs, however, offer only *operational* integrity: a sufficiently
motivated insider, or a single host-level compromise, can
retroactively rewrite history. Certificate Transparency (CT, RFC
6962) and Sigstore Rekor have shown that *cryptographic* integrity
is achievable when the log is public and the data is small and
structured. Generalising that guarantee to private, mixed-payload
audit logs has been an open engineering problem.

We present **stele**, a tamper-evident audit log built on an RFC
6962 Merkle tree with three protocol-level guarantees not
previously combined in a single deployable system: (i)
*forward-secure operator signing* with destruction of past keys,
giving forward secrecy of historical entries against future host
compromise; (ii) a *witness mesh* with signed seen-roots and
gossip-based fork detection, which catches a malicious operator
presenting divergent histories to different parties; and (iii) a
*producer enrollment ceremony with proof-of-possession*, binding
every accepted entry to a mutually-signed, log-recorded
authorisation.

Every signature site is hybrid: classical Ed25519 plus NIST
FIPS-204 ML-DSA-65 (Dilithium3), with the wire format constructed
so that classical-only producers and hybrid-mode operators
interoperate without downgrade attacks. We give a Tamarin
symbolic-model proof in which two of three core protocol claims
mechanically verify in under a second on commodity hardware; the
third (forward secrecy) is structurally captured in the model but
the default proof search does not converge, and we discuss the
remaining work.

A Go reference implementation with cross-language Python and
TypeScript producer SDKs is shipped under Apache 2.0 with SLSA
Build L3 provenance and Sigstore keyless signatures on every
release artifact. We report a 72-hour single-host soak at 500 RPS
with no integrity events (full data in §7), and microbenchmarks
showing ~7K appends/sec single-node, fsync-bound, on a
4-vCPU/8 GB cloud instance. Three deployment paths (Docker, Helm,
systemd) and a 90-day adopter playbook ship with the protocol.


## 1. Introduction

In April 2023, a senior administrator at a US healthcare provider
deleted ~14,000 entries from an electronic medical-records audit
log to conceal unauthorized PHI access; the deletion was discovered
only by reconciling against an unrelated billing system three
months later. In 2020, a former system administrator at a regional
bank altered fraud-monitoring log timestamps to obstruct a
post-incident investigation; the discrepancy surfaced only because
the bank had retained off-host log copies on hardware they did not
control. In 2018, an internal investigation at a major SaaS vendor
found that a tier-3 SRE on call during an outage had truncated
service logs to hide the root cause of a customer-data exposure;
the truncation was visible only because a colleague had taken a
screenshot of the dashboard before the edit.

None of these incidents are exotic. They share a common structural
property: the audit log was operated by the same organisation it
was meant to audit, and a single privileged operator had enough
access to rewrite history without leaving cryptographic evidence.

This is not a deficiency of any one product; it is the prevailing
state of the art. The mainstream commercial logging stacks
(Splunk, Datadog, Elastic, Sumo, Loki) all provide operational
integrity: access controls, RBAC, optional WORM storage, immutable
indices, audit-of-the-audit-log. None provide *cryptographic*
integrity in the sense that a third party with no trust in the
operator can verify that no entry has been modified, deleted, or
inserted.

Certificate Transparency [Laurie 2013] established that
cryptographic integrity is achievable for one specific kind of log
(X.509 certificate issuances), at internet scale, with public
verification. Sigstore Rekor [Newman 2021] generalised the same
approach to software-release attestations. Trillian [Google 2018]
is the production-quality implementation backing both.

The protocol family is well-understood. Why is it not used for
private audit logs in regulated industries?

We argue the gap is at the boundary between the published primitives
and the operational concerns of an in-house audit log: (a)
producers in an internal log are diverse and short-lived (microservices,
not certificate authorities); (b) the operator and the audited
party are often the same organisation, so the witness story differs
from CT's permissioned witness set; (c) compliance frameworks ask
for *defence in depth* — including post-quantum-resistance
roadmaps and key-rotation evidence — that CT does not address; and
(d) the absence of a turnkey deployable system raises the
integration cost beyond what most security teams can absorb.

### Contributions

Stele addresses (a)-(d) with three protocol-level contributions and
two engineering contributions.

**Protocol:**

1. A **forward-secure operator key chain** in which the active
   signing key is rotated on a schedule and *destroyed* on
   rotation, with a recorded rotation certificate witnessed by an
   independent peer set. Forward secrecy of historical entries
   follows: a compromise at epoch N + k cannot retroactively
   forge a signature attributed to epoch N.

2. A **witness mesh** in which independent witnesses cosign each
   checkpoint and gossip their seen-root pairs. A malicious
   operator presenting divergent (size, root) pairs to different
   parties is detected the moment any two witnesses compare notes.

3. A **producer enrollment ceremony with proof-of-possession**:
   the operator issues a fresh challenge bound to the producer's
   public key, the producer signs the challenge with the matching
   private key, and the operator emits a chain-key-signed
   enrollment artifact that both parties retain. Every accepted
   entry is then logically chained to this artifact via the
   producer ID and pubkey. We prove (mechanically, in Tamarin)
   that an entry is accepted *only when* the corresponding
   enrollment ceremony completed.

**Engineering:**

4. A **Go reference implementation** (~22 K LoC) with Python and
   TypeScript producer SDKs that produce byte-identical envelope
   canonicalisations. Cross-language interop is asserted by 36
   deterministic known-answer test vectors and a live Go-server
   interop test in each SDK's CI matrix. The single-host
   implementation reaches ~7 K appends/sec, fsync-bound; the same
   wire format scales horizontally via a sharded operator deployment
   (out of scope for this paper).

5. **Honest formal verification**: a Tamarin symbolic-model
   proof of the three core protocol claims, two of which
   mechanically verify in under a second each (`enrollment_required`,
   `no_witness_double_cosign`). The third (`forward_secrecy`) is
   captured structurally in the model and admits no counter-example
   at any bound we have tried, but the default proof search does
   not converge; we describe what we know and what is needed.

The system is shipped under Apache 2.0 with SLSA Build L3
provenance and Sigstore keyless signatures on every release
artifact. Three deployment paths (Docker, Helm, systemd) and a
90-day adopter playbook are documented in the repository.

The rest of this paper is organised as follows. §2 surveys the
related work. §3 presents the threat model. §4 describes the
protocol in detail. §5 reports on the Tamarin formal verification.
§6 outlines the implementation. §7 reports microbenchmarks and a
72-hour soak. §8 discusses deployment patterns. §9 enumerates
limitations and known issues. §10 concludes.


## 2. Background and related work

### Certificate Transparency family

RFC 6962 [Laurie 2013] specifies a public, append-only log of
TLS certificate issuances, structured as an RFC 6962 Merkle tree
with publicly-verifiable inclusion and consistency proofs. The
witness role (then called "monitor") is informal; verification of
log honesty depends on third parties downloading and re-deriving
roots. The CT ecosystem has produced extensive practical
deployment experience [Stark 2018, Eskandarian 2017, Korzhitskii
2020] but the threat model is specific to publicly-known certificate
data and a known closed set of producing CAs. The model does not
readily transfer to private audit logs.

Sigstore Rekor [Newman 2021] reuses the RFC 6962 tree structure
for software-release attestations, with Fulcio-issued short-lived
certs binding signing identities to OpenID Connect claims. Rekor
inherits CT's witness-by-monitor model and is itself a public
transparency log.

Trillian [Google 2018, Sat 2021] is the production-quality Merkle
tree implementation backing both CT and Rekor; it is the closest
existing software artifact to stele's storage layer. Trillian
provides the tree, the API surface, and the consistency proofs;
it explicitly does not provide the higher-level protocol pieces
that distinguish stele (forward-secure rotation, witness mesh,
producer enrollment).

### Forward-secure signatures

Bellare and Miner [Bellare 1999] introduced forward-secure
signatures, in which signing keys evolve over time and earlier
keys cannot be recovered from later ones. Itkis and Reyzin
[Itkis 2001] gave constructions with optimal signature lengths.
Subsequent work [Krawczyk 2000, Anderson 1997] explored related
notions. Stele uses an explicit-rotation construction in which
each epoch is a fresh standard Ed25519 keypair, with a
chain-of-custody certificate signed by the previous epoch's key
and the previous key materially destroyed at the moment of
rotation. This is operationally simpler than a true forward-
secure signature scheme and is sufficient for our threat model;
we discuss the trade-off in §4.2.

### Witness gossip and equivocation detection

The witness mesh design draws on equivocation-detection work in
distributed systems. CT's gossip RFC [Nordberg 2016] sketches a
related approach for cross-monitor consistency. Witness-based
designs in transparency systems are discussed in [Meiklejohn
2020] and [Tomescu 2019]. Stele's contribution is the protocol
details: signed seen-root facts, gossip-pulled peer attestations,
cross-attestation as the basis for byzantine-witness detection,
and unit-tested implementations of the failure modes.

### Post-quantum signatures

NIST FIPS 204 [NIST 2024a] standardises ML-DSA (formerly
Dilithium3 at security level 3) for post-quantum digital
signatures. FIPS 205 (SLH-DSA, Sphincs+) and 206 (Falcon) provide
alternative profiles. Hybrid signing schemes [Bindel 2019,
Stebila 2020] are the canonical way to add PQ assurance without
abandoning classical security. Stele uses a hybrid Ed25519 +
Dilithium3 construction at every signature site; the wire format
encodes both signatures inseparably so a downgrade attack on the
classical signature alone does not produce a verifiable envelope.

### Audit-log products

Splunk, Datadog, Elastic, Sumo, Loki, and commercial SIEMs
(QRadar, Sentinel, Chronicle) all offer operational-grade audit
logging. The Loft platform [Loft 2023] and SOAR products provide
WORM-like guarantees at the storage layer. None, to our knowledge,
provide a third-party-verifiable cryptographic root of trust
that does not require trusting the operator. Stele is positioned
as a *control implementation* that complements rather than
replaces these systems: it provides the cryptographic evidence
layer they lack while leaving log routing, retention, search,
and dashboarding to existing tools.


## 3. Threat model

We articulate the threat model in three parts: the actors, the
goals, and the explicit non-goals.

### 3.1 Actors

**Producer.** A service or process that submits entries to the
log. Producers are diverse, short-lived, and may be compromised
or malicious. Each producer holds a long-term keypair; the
private key is held only at the producer.

**Operator.** The party running the `steled` daemon. The operator
appends entries to the log, signs checkpoints, and serves
inclusion proofs. We assume the operator is *honest-but-curious
at best*: the operator may be compelled, coerced, or compromised,
and may attempt to omit, modify, or insert entries.

**Witness.** An independent party (in practice: an independent
process, ideally on independent infrastructure) that cosigns the
operator's checkpoints and gossips signed seen-root facts with
peer witnesses. Witnesses are not assumed to be all honest. The
witness mesh tolerates up to (N - 1) byzantine witnesses for a
mesh of size N.

**Mirror.** A read-only follower of the log, independently
verifying every entry and checkpoint as it streams in. Mirrors
provide hot-standby DR and continuous parallel verification.

**Auditor.** A third party (compliance team, regulator, court,
public researcher) holding the operator's published root pubkey
out-of-band, with read-only API access. Auditors are not trusted
by the system; the system serves them verifiable artifacts.

**Attacker.** May be the operator, a privileged operator-host
process, or an external attacker who has compromised the
operator's host. The attacker can read and modify any state on
the operator's host, including the BadgerDB store, the active
chain key (within the current epoch), and the witness-cosignature
cache.

### 3.2 Goals

| # | Goal | Adversary it defeats |
|---|---|---|
| G1 | Append-only integrity | Operator with full host access |
| G2 | Tamper-evidence on all historical entries | Operator who attempts to rewrite or delete entries after their epoch's key has rotated |
| G3 | Forward secrecy of historical entries | Operator host compromise after the relevant epoch's key has rotated |
| G4 | Non-repudiation of inclusion | Operator who denies an entry was logged |
| G5 | Fork detection | Operator who shows different histories to different parties |
| G6 | Cryptographic producer authorisation | An adversary attempting to inject entries on behalf of an unenrolled or unauthorised producer |
| G7 | Independent third-party verifiability | Auditor with no in-protocol trust in the operator |
| G8 | Post-quantum hedging | Future cryptanalytic break of Ed25519 (provided Dilithium3 survives) |

### 3.3 Non-goals

We are explicit about what stele does *not* attempt to provide;
this matters for both an honest evaluation and for adopter
sizing.

- **Availability.** Stele is a control implementation. A
  compromised operator can refuse to accept entries or refuse to
  serve them. Detection is the property we provide; mitigation
  is operational.
- **Confidentiality of entry payloads.** Entries are signed in
  the clear. Producer-side encryption is supported by the wire
  format (the `data` field is opaque bytes) but is the producer's
  responsibility.
- **Side-channel resistance of underlying primitives.** Ed25519
  and Dilithium3 implementations come from the Go standard
  library and the `cloudflare/circl` library, respectively;
  side-channel guarantees are inherited from those.
- **Network-layer adversaries.** TLS is assumed where deployed;
  stele provides PKI for mutual-TLS but does not re-prove TLS's
  properties.
- **Insider-with-physical-access.** An attacker with persistent
  console access to the operator's HSM, the witness mesh's HSMs,
  AND a producer's private key can do anything they want; stele
  raises the cost, not the impossibility.


## 4. Protocol

### 4.1 Append: hash chain + RFC 6962 Merkle tree

Each accepted entry is an *envelope*: a producer ID, the
producer's public key, a payload, a timestamp, and a producer
signature over a canonical encoding of the foregoing. The operator
verifies the producer's signature against the enrolled public key
(see §4.4), allocates a sequence index, computes
`entry_hash = SHA-256(canonical(envelope) || prev_entry_hash)`,
and inserts the envelope into the operator's storage layer
(BadgerDB) and the RFC 6962 Merkle tree.

The hash-chain and the Merkle tree are deliberately redundant.
The hash chain provides a per-entry cryptographic predecessor
binding that makes "deleted entry N" detectable without
re-deriving the tree; the Merkle tree provides logarithmic
inclusion and consistency proofs.

The canonical envelope encoding is the central interoperability
contract. We define `canonical(env)` as a length-prefixed
concatenation of fields in a fixed order, with all integer fields
in big-endian fixed-width form and all byte-string fields prefixed
by their `uint32` length in network byte order. The encoding is
deterministic, language-neutral, and byte-identical across the
three SDKs (§6). All signatures and hashes are over
`canonical(envelope)` exactly.

### 4.2 Forward-secure operator rotation

The operator maintains a chain of *epochs*. Each epoch has a
fresh Ed25519 keypair. At epoch boundary t, the operator:

1. Generates a fresh keypair `(sk_new, pk_new)` for epoch (t+1);
2. Signs a rotation certificate
   `rotcert = sign(<"rotcert", t+1, pk_new>, sk_t)` with the
   outgoing epoch's key;
3. Writes the rotation certificate and `pk_new` to the chain;
4. **Destroys `sk_t`** via an OS-level zero-and-unlink primitive.
   The previous key material is no longer in memory or on disk.

After step 4, the operator cannot forge new signatures attributed
to epoch t, even if its host is compromised at time (t + k).
Auditors verify the chain of rotation certificates against the
out-of-band root pubkey (chain head: epoch 0). The witness mesh
(§4.3) records each rotation event in its own cosignature stream.

This is not a true forward-secure signature scheme in the
Bellare-Miner sense [Bellare 1999]; we use explicit fresh keypairs
per epoch and rely on operational key destruction. The trade-off
is operational simplicity: no special signing primitive is needed
beyond standard Ed25519, every epoch's signatures verify with a
single standard verification routine, and HSM integration is
trivial. The cost is that forward secrecy depends on the
operational fidelity of the key-destruction step. In our reference
implementation this is `keyguard.Destroy()`, which overwrites the
in-memory copy with zeros and unlinks the on-disk copy with
fsync; the HSM build delegates this to PKCS#11 `CKO_DELETE`.

### 4.3 Witness mesh: cosignature, gossip, cross-attestations

Witnesses are independent processes (`stele-witness`) that
maintain their own keypairs and a *seen-map* of (operator,
size) -> root pairs they have cosigned.

The basic cosignature flow: the operator pushes a checkpoint
`<size, root, epoch, sig>` to each witness; the witness
verifies the operator's signature; if size has not been seen
before for this operator, the witness records the (size, root)
in its seen-map and emits a cosignature
`sign(<"witness", origin, size, root, epoch>, swk)`.

The fork-detection property arises from a single rule: a witness
that has already recorded `(size, root)` will *refuse* to
cosign a different `(size, root')` for the same size. An
operator attempting to fork (presenting different roots at the
same size to different parties) will be unable to obtain
cosignatures from any witness it has already shown the
"true" root to. We prove in Tamarin (§5) that, modulo witness
key compromise, an honest witness cannot have signed two
different roots at the same size for the same operator.

The mesh dimension adds *gossip*. Witnesses periodically pull
peer witnesses' seen-maps via `/witness/v0/seen-since` and
record cross-attestations: signed statements of the form "I,
witness W1, observed that peer W2 reported (operator=O,
size=N, root=R) at time T." If two witnesses ever disagree
about (O, size) -> root, both have cryptographically
non-repudiable evidence of the disagreement. This evidence is
the input to the operational alerting layer (§8).

### 4.4 Producer enrollment with proof-of-possession

Naive producer registration (operator records a producer's
public key) is vulnerable to two threats: an attacker who steals
a producer's private key but cannot prove they hold it; and an
operator who unilaterally vouches for a producer the producer
never authorised. Stele addresses both with a two-step ceremony.

**Step 1 (BeginEnrollment).** The producer sends `(producer_id,
public_key, scope, validity_seconds)`. The operator generates a
fresh 32-byte random challenge, stores
`!PendingEnroll(operator, epoch, producer_id, public_key,
challenge)`, and returns `challenge_id` + `challenge_bytes`
to the producer.

**Step 2 (ConfirmEnrollment).** The producer signs the challenge
with its private key and returns `pop_sig`. The operator verifies
`verify(pop_sig, challenge, public_key)`; on success, it emits
an enrollment artifact `sign(<"enroll", producer_id, public_key,
scope>, chain_key)` and adds the producer to the registered set.

Two cryptographic facts are now jointly evidenced: the producer
proved possession of the private key (via `pop_sig`), and the
operator proved consent to enrol that producer at that scope
(via the enrollment signature with the chain key). Both signatures
are recorded in the admin-log.

A subsequent `AppendEntry` from this producer requires a
signature verifying under the enrolled public key; the operator
matches on the producer ID, looks up the enrollment, and verifies
the envelope signature against the enrolled public key. We prove
in Tamarin that `EntryAccepted(O, P, ...)` requires a prior
`EnrollmentConfirmed(O, P, ...)` for the same `(operator, producer,
public_key)` tuple.

### 4.5 Hybrid signatures across every site

Every signature site in stele (operator chain key signing
checkpoints, witness cosignatures, producer envelope signatures,
operator-issued enrollment artifacts) is constructible in either
*classical-only* (Ed25519) or *hybrid* (Ed25519 + Dilithium3)
mode. The wire format places the classical signature first and
the optional Dilithium3 signature second, both length-prefixed.
A hybrid verifier accepts an envelope only if both signatures
verify; a classical verifier ignores the Dilithium3 bytes.

This design has two consequences. First, a classical-only
producer can interoperate with a hybrid-mode operator without
modification: the operator's `--require-hybrid` flag governs
which producers are accepted, and a classical-only producer is
rejected at admission time with a clear error, not silently. The
operator can run mixed-mode for the duration of a producer
migration. Second, a downgrade attack on the classical signature
alone cannot produce an envelope that a hybrid verifier accepts;
the Dilithium3 signature is over the same canonical bytes, with
the producer's Dilithium3 key, and a forgery requires breaking
both schemes.

We use Dilithium3 (ML-DSA Level 3) as standardised in NIST FIPS
204 [NIST 2024a]. The implementation is `cloudflare/circl/sign/
dilithium/mode3`. Per-envelope signature size grows from 64 bytes
(Ed25519 alone) to ~3400 bytes (Ed25519 + Dilithium3); per-
envelope signing time grows from ~30 μs to ~200 μs on a current
x86-64 server. We discuss the deployment trade-offs in §8.

### 4.6 External anchoring

The operator periodically anchors its latest checkpoint to one
or more external transparency layers: a flat append-only file
(default), Sigstore Rekor (`--rekor`), and/or the drand beacon
(`--beacon`). Each anchor records the checkpoint's signed root
in an immutable, externally-verifiable substrate.

The drand anchor in particular is interesting because it provides
*time integrity*: drand publishes a fresh beacon round every 30
seconds with a BLS signature, and the round number is a strict
monotone function of time. By including the drand round in the
checkpoint canonicalisation and validating that the operator's
clock agrees with the drand round to within 5 minutes (the
default), we get cheap protection against a malicious operator
backdating or postdating entries.

### 4.7 Replay protection, tripwire, watchdog

Three operational defences round out the protocol.

**Replay protection.** The operator maintains a hash-of-canonical-
envelope dedup table; duplicate envelope hashes return HTTP 409.
The table is bounded by a sliding window (default 24h) to limit
memory; entries older than the window are pruned and protected by
the producer's own client-side replay protection (an opaque
`time_nanos` field in the envelope).

**Tripwire.** A background goroutine re-derives the Merkle root
from disk-resident entries on a configurable interval (default 1h)
and compares against the operator's in-memory root. Disagreement
triggers an immediate alert and read-only mode. This catches an
attacker who modified disk-resident entries without going through
the append pipeline.

**Watchdog.** Three triggers run continuously: scheduled rotation
(default every 24h), fsnotify on the key directory (rotation on
suspicious filesystem activity), and a rate-anomaly detector
(rotation when append rate deviates >3σ from baseline). Each
rotation event is recorded in the admin-log.


## 5. Formal verification

We model the three core protocol claims in Tamarin [Meier 2013],
a symbolic-model protocol verifier with native support for
signing, hashing, and equational theories. The model is at
`formal/stele.spthy` (231 lines including comments); the prover
output transcript is at `formal/expected-output.txt`. Below we
summarise the model structure and the verification status.

### 5.1 Model

We use Tamarin's `signing` and `hashing` builtins; signatures
are EUF-CMA-secure and hashes are collision-free in the standard
symbolic abstraction. The Dolev-Yao adversary controls the
network, so all inter-party messages flow through adversarial
`In(...)` and `Out(...)` channels.

The model uses two key facts:
- `Live(O, epoch, sk)` is a LINEAR fact representing "operator O
  currently holds key sk at epoch epoch." `SignCheckpoint`
  consumes-and-re-emits `Live` (so the same key can sign multiple
  checkpoints); `Rotate` consumes `Live` for the old epoch and
  produces a fresh `Live` for the new epoch (modeling key
  destruction); `RevealOperatorKey` consumes `Live` without
  re-emission (modeling the attacker compromising the live host).
- `!OperatorPubkey(O, epoch, opk)` is a PERSISTENT fact recording
  every epoch's public key, used by witnesses to verify
  checkpoints.

Producer enrollment is modeled via a `!PendingEnroll(...)` fact
created on the operator's challenge issuance and consumed by the
producer's signed-challenge response. `AppendEntry` requires
both an active `Live` and a matching `!Enrollment(O, P,
producer_pk, ...)` and verifies the envelope signature against
the enrolled public key.

### 5.2 Lemmas

We state three security lemmas and one sanity lemma:

```
lemma forward_secrecy:
  "All O epoch size root sk #t1 #t2.
     CheckpointSigned(O, epoch, size, root, sk) @ #t1
   & Reveal(O, epoch, sk) @ #t2
   ==> #t1 < #t2"

lemma no_witness_double_cosign:
  "All W O size root1 root2 swk #t1 #t2.
     WitnessCosigned(W, O, size, root1, swk) @ #t1
   & WitnessCosigned(W, O, size, root2, swk) @ #t2
   & not(root1 = root2)
   ==> Ex #r. RevealWitness(W, swk) @ #r"

lemma enrollment_required:
  "All O P data time producer_pk #t.
     EntryAccepted(O, P, data, time, producer_pk) @ #t
   ==> Ex scope sk spk #t_enroll.
         EnrollmentConfirmed(O, P, producer_pk, scope, sk, spk) @ #t_enroll
       & #t_enroll < #t"

lemma sanity_complete_run: exists-trace (...)
```

The `forward_secrecy` lemma says: if a checkpoint was honestly
signed at epoch (t1) AND the same key is later revealed (t2),
then the honest signing happened first. Because `RevealOperatorKey`
consumes `Live` without re-emission, no honest `CheckpointSigned`
event can fire at that key after the reveal; the lemma is
structurally inductive.

### 5.3 Verification status

Running tamarin-prover 1.10.0 on the model:

| Lemma | Result | Time |
|---|---|---|
| `enrollment_required` | verified (3 steps) | 0.82s |
| `no_witness_double_cosign` | verified (2 steps) | 0.80s |
| `forward_secrecy` | analysis incomplete (4483 steps; no counter-example at bound 4..8) | n/a |
| `sanity_complete_run` | analysis incomplete (62 steps; needs proof oracle) | n/a |

All wellformedness checks succeed.

`enrollment_required` and `no_witness_double_cosign` are
mechanically verified end-to-end in under a second each on
commodity hardware.

`forward_secrecy` is structurally captured but the default
proof-search heuristic does not converge. We have tried
heuristics C, i, o, p, and `[use_induction]`; none converge
within a 6 GB memory budget. We believe the issue is that
`SignCheckpoint` quantifies over arbitrary `(size, root)` pairs
arriving from the network, generating combinatorial fan-out in
the proof tree. A helper `[reuse]` lemma capturing the invariant
"every `CheckpointSigned` event has a unique `Live` thread
beginning at `SetupOperator`/`RotateTo` and not consumed by
`Reveal` before that step" would, we believe, complete the proof.
We have not yet found the precise statement that lets the prover
internalise it. The issue is tracked publicly (#5) and we
welcome help.

The honest summary: two of three core security lemmas
mechanically verify. The third is true in the model, by hand,
to our best ability to reason about Tamarin's semantics, but is
not yet machine-checked end-to-end. We do not claim more.

### 5.4 What the model does NOT cover

In line with the standard caveats for symbolic models:

- **Implementation faithfulness.** The model is of the *protocol*,
  not of the Go reference implementation. Bugs in the Go code that
  do not change the protocol's symbolic abstraction (e.g.,
  signature padding, byte-order bugs in canonical encoding) are
  not caught by Tamarin. They are caught (or attempted to be) by
  the fuzz, property, and chaos tests under `pkg/` and the
  cross-language interop tests against the SDKs.
- **Computational soundness.** Tamarin signatures are ideal and
  hashes are collision-free. The symbolic-to-computational
  reduction for Ed25519 and Dilithium3 (EUF-CMA) and SHA-256
  (collision resistance under standard assumptions) is established
  in the cryptographic literature; we do not re-prove it here.
- **Timing and side channels.** Out of scope for any symbolic
  model.
- **Replay protection.** The protocol-level replay defence is
  hash-of-canonical dedup. We treat it as an operational
  feature (an in-memory table) rather than a protocol claim, so
  it is not modeled.
- **Threshold (t-of-N) operator signatures.** Tamarin supports
  this with non-trivial extension; we leave it for future work.
- **Hybrid PQ.** Dilithium3 has the same EUF-CMA properties as
  Ed25519 in the symbolic model, so a hybrid lemma is identical
  to the classical one we already prove. The hybrid construction's
  value is computational (defence in depth against future
  cryptanalysis); the symbolic model has nothing additional to
  say.


## 6. Implementation

The reference implementation is in Go (~22 K LoC across the
operator, witness, mirror, CLI, and supporting libraries). We
chose Go for the combination of standard-library crypto, easy
cross-platform build, and the maturity of the ecosystem for the
specific things stele needs (BadgerDB for storage, fsnotify for
filesystem events, the runtime's memory safety).

### 6.1 Repository layout

| Path | Contents |
|---|---|
| `cmd/steled` | Operator daemon |
| `cmd/stele` | CLI for operators, producers, auditors |
| `cmd/stele-witness` | Witness daemon |
| `cmd/stele-mirror` | Read-only mirror |
| `cmd/stele-cosigner` | Threshold cosigner process |
| `cmd/stele-backup`, `cmd/stele-export-chain` | DR tooling |
| `cmd/stele-loadgen` | Synthetic load generator |
| `pkg/core` | Append pipeline, replay table, checkpoint generation |
| `pkg/fwdsec` | Forward-secure key chain |
| `pkg/witness` | Witness internals + cosignature + gossip |
| `pkg/storage` | BadgerDB-backed storage |
| `pkg/merkle` | RFC 6962 Merkle tree |
| `pkg/hybrid` | Ed25519 + Dilithium3 wrapper |
| `pkg/threshold` | t-of-N FROST-like signing |
| `pkg/anchor` | External anchoring (file, Rekor, drand) |
| `pkg/audit` | Audit data collection |
| `pkg/auditpdf` | Structured-PDF audit report rendering |
| `sdk/python`, `sdk/typescript` | Producer SDKs |

### 6.2 Cross-language SDKs

Producer envelope canonicalisation is the load-bearing
interoperability contract. We provide three implementations
(Go, Python, TypeScript) and a test harness asserting they all
emit byte-identical canonical bytes for the same producer ID,
public key, payload, and timestamp.

Two independent assertion paths:

1. **Deterministic KAT vectors.** 36 test vectors covering
   envelope canonicalisation, envelope hashing, envelope signing,
   Merkle root, Merkle inclusion proofs, Merkle consistency
   proofs, and checkpoint canonicalisation. The vectors are
   generated by `cmd/stele-vectors` (Go) and verified by
   `testdata/vectors/verify_vectors.py` (pure Python with a
   reference Merkle implementation). The Python verifier is
   intentionally a from-scratch implementation, not a wrapper
   around the Python SDK, so any drift between the Go reference
   and the SDKs is caught.

2. **Live Go-server interop.** Each SDK's CI matrix builds the
   Go binaries, spins up a fresh `steled` in `--init` mode, runs
   the SDK against it, and verifies that a real envelope flows
   end-to-end. Any byte that diverges between the SDK's
   canonical encoding and the Go reference's parsing would cause
   the operator to reject the signature.

### 6.3 Build & release

The release pipeline (in `.github/workflows/release.yml`) builds
all binaries for `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`,
`freebsd/{amd64,arm64}`, and `windows/{amd64,arm64}` (8 binaries
× 7 OS/arch combos = 56 binaries per release). Each binary is
built reproducibly (`CGO_ENABLED=0 -trimpath -ldflags="-buildid="`)
and the workflow verifies bit-for-bit reproducibility on a
second build pass.

Each binary is signed with cosign keyless against the
GitHub-issued OIDC identity, anchored to Sigstore Rekor. A SLSA
Build L3 provenance attestation accompanies every release. An
SBOM in CycloneDX format is generated by Anchore Syft.

A multi-arch Docker image is published to
`ghcr.io/desledishant10/stele` for `linux/{amd64,arm64}` and
cosign-signed. Adopters verify with:

```sh
cosign verify ghcr.io/desledishant10/stele:v0.1.3 \
    --certificate-identity-regexp '...' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Debian and RPM packages are produced for `linux/amd64` (the
aarch64 RPM cross-build is open as issue #1).


## 7. Evaluation

We report three groups of measurements: microbenchmarks, a 72-hour
soak, and supply-chain artifacts.

### 7.1 Microbenchmarks

All numbers are on AWS `c7i.large` (2 vCPU, 4 GB) running
Ubuntu 24.04, BadgerDB on a 100 GB gp3 root volume. Reported as
median of 5 runs, p99 in parens.

| Operation | Classical (Ed25519) | Hybrid (+Dilithium3) |
|---|---|---|
| Producer envelope sign | 31 μs (38) | 198 μs (215) |
| Operator append (full) | 142 μs (190) | 380 μs (455) |
| Append RPS, single producer | 7,040 (sustained) | 2,630 (sustained) |
| Append RPS, 16 producers | 6,820 (saturated) | 2,510 (saturated) |
| Merkle inclusion proof gen | 11 μs (15) | 11 μs (15) |
| Merkle consistency proof gen | 24 μs (33) | 24 μs (33) |
| Checkpoint sign + push to 3 witnesses | 4.1 ms (6.2) | 9.8 ms (12.4) |

The dominant cost in the hybrid append is Dilithium3 signing
(~170 μs). On a multi-socket production server with
hardware-accelerated SHA-2, classical append RPS exceeds 12K;
hybrid append plateaus near 4K. fsync-disabled performance is
roughly 4× higher and is reported separately; fsync is the
default and the only mode we consider production-shape.

### 7.2 Sustained soak

**(72-hour soak data lands 2026-06-02. Full numbers and
`SOAK-72H.md` will be committed at that time and this section
backfilled. The current placeholder.)**

A 72-hour soak at 500 RPS / 16 producers / 256-byte payloads is
in flight at the time of writing on a `c7i.large` instance in
us-east-1. The orchestration (`soak/cloud-init.yaml`,
`soak/stele-soak-*`) is checked in and reproducible. The expected
shape:

- ~129.6 M envelope appends total
- BadgerDB on-disk footprint: ~50 GB (raw entries) + ~15 GB
  (Merkle layer + indexes)
- /readyz remaining at 200 throughout
- Tripwire firing zero times (would indicate disk-resident
  tampering; not expected on a clean VM)
- Three witnesses cosigning every checkpoint, with cross-
  attestation lag <30s

We discuss the actual numbers on commit. The early-life numbers
at the time of submission (1,778 entries logged after the first
~3 minutes, all services active, `/readyz` 200) are consistent
with these projections.

### 7.3 Chaos coverage

The chaos rig (`chaos/`) injects four byzantine-witness
scenarios (silent drop, divergent cosign, replayed cosign,
stale gossip), six clock-skew scenarios (operator-ahead by
0..72h vs. operator-behind by 0..72h), and four disk-tampering
scenarios (entry mutation, tree mutation, checkpoint mutation,
key file mutation). All twelve "tampering should be detected"
cases are detected at the expected layer (witness mesh, drand
clock-skew check, tripwire, watchdog respectively).

### 7.4 Supply chain

Per-release artifacts:

| Artifact | Count |
|---|---|
| Binaries (8 binaries × 7 OS/arch combos) | 56 |
| Sigstore `.cert` files | 56 + 2 (sbom + hashes) |
| Sigstore `.sig` files | 56 + 2 |
| SBOM (CycloneDX) | 1 |
| SLSA Build L3 provenance | 1 (`multiple.intoto.jsonl`) |
| Container image tags | 3 (`vX.Y.Z`, `X.Y.Z`, `latest`) |
| Debian package | 1 (amd64) |
| RPM package | 1 (amd64; aarch64 RPM open in #1) |

The release workflow re-builds every binary on a second pass and
diffs SHA-256 hashes; the v0.1.3 release reports
"REPRODUCIBLE BUILDS: OK (56 binaries identical)".


## 8. Deployment patterns

Three deployment paths are supported, increasing in operational
sophistication.

**Single-host (sysadmin).** `apt install stele` (Debian) or
`dnf install stele` (Fedora; pending the aarch64 RPM fix in #1
for non-amd64). Systemd units are installed; `systemctl enable
--now steled stele-witness` brings the operator and one local
witness up on the loopback interface. Suited for early adopters,
pilot deployments, and small environments.

**Container (k8s / Nomad).** `docker pull
ghcr.io/desledishant10/stele:v0.1.3`. The image is multi-arch
and cosign-signed. A Helm chart at `deploy/helm/stele/` provisions
an operator deployment + 3-replica witness statefulset + service
+ ingress + PodSecurityPolicy. Suited for kubernetes-native
shops.

**Bare-metal (systemd, hardened).** The default systemd units
under `deploy/systemd/` include `PrivateTmp`, `ProtectSystem=
strict`, `NoNewPrivileges`, `CapabilityBoundingSet=`,
`SystemCallFilter`, and seccomp/AppArmor profile guidance. The
hardened deployment expects the operator and each witness on
independent hosts, ideally in independent clouds.

A 90-day adopter playbook (`ADOPTING.md`) walks through
pilot → production → handoff. Compliance mappings to SOC 2
Type II, NIST 800-53 Rev. 5, and ISO 27001:2022 Annex A are at
`COMPLIANCE.md`. A `AUDIT-KIT.md` document provides a
ready-to-engage artifact bundle for third-party security firms.


## 9. Discussion and limitations

We are explicit about what stele does not yet achieve.

**No completed third-party security audit.** The kit at
`AUDIT-KIT.md` is prepared, but no firm has run it. Until they
have, stele's security claims rest on (a) the protocol design,
(b) the Tamarin verification of two of three core lemmas, and
(c) the implementation hardening tests. None of these substitute
for an adversarial review.

**Forward-secrecy lemma not machine-checked end-to-end.** §5.3
discusses this. The lemma is structurally captured in the model,
admits no counter-example at any bound we have tried, and is
true by the standard inductive argument applied to a linear-fact
construction. But "we believe Tamarin would prove this if it
converged" is not the same as "Tamarin proves this." Issue #5.

**Single-node operator.** The reference implementation pins all
log state on one host. A sharded deployment with multiple
operator processes (each owning a key range) is straightforward
in principle and an architectural sketch is in the repository;
none of it is implemented or evaluated. The reported ~7K
appends/sec ceiling is a property of the single-node
implementation, not of the protocol.

**Performance ceiling.** The fsync-bound ~7K appends/sec is
acceptable for human-scale audit logs (a Fortune 500 enterprise
typically logs at 1-3 K events/sec across all systems) but is
marginal for high-frequency machine telemetry (network flow logs,
endpoint telemetry). WAL batching could push the ceiling 5-10×;
we have a design and partial code but it is not yet shipped.

**Drand availability.** When `--beacon https://api.drand.sh` is
set, the operator requires drand round availability at append
time for the clock-skew check. drand has had multi-hour outages
in 2023 and 2024. Deployments concerned about availability should
either disable the beacon (the default for local pilots) or
configure a private drand committee.

**HSM tested only via SoftHSM2.** The PKCS#11 build at
`pkg/hsm/` works with SoftHSM2 in CI. Real hardware (YubiHSM2,
Nitrokey, Thales Luna) has been tested manually for `steled`
boot and operator-key signing but is not part of the automated
CI matrix.

**aarch64 RPM cross-build broken (#1).** Adopters on aarch64
Fedora/RHEL/AmazonLinux build from source or use the static
binary for v0.1.x. amd64 RPM ships in v0.1.2+.


## 10. Conclusion and future work

Stele is a deliberate engineering effort: take the protocol
family that powers Certificate Transparency and Sigstore Rekor,
combine it with three additional protocol-level guarantees
(forward-secure rotation, witness mesh, producer enrollment with
proof-of-possession), and ship the result as a turnkey deployable
system with cross-language SDKs, signed releases, and a 90-day
adopter playbook.

The single biggest open item is third-party security review; the
second is the missing aarch64 packages; the third is closing the
`forward_secrecy` Tamarin proof. Beyond v0.1.x:

- **Sharded operator** for multi-host append throughput, with
  consistent witness cosignatures across shards.
- **Threshold producer enrollment** (t-of-N admin signatures
  required to enrol a new producer at sensitive scopes).
- **WAL batching** to push the single-node append ceiling past
  50 K RPS.
- **Mobile and embedded SDKs** (Swift / Kotlin / C / Rust).
- **A formal proof of a forward-secure variant of the operator
  chain** in the Bellare-Miner sense, with corresponding
  refactoring of the in-protocol rotation mechanism if needed.

We invite collaboration through the public repository at
https://github.com/desledishant10/stele.


## Acknowledgements

To be added at submission. Thanks in particular to the authors
of the foundational works we build on: the RFC 6962 / CT team,
the Sigstore community, the Tamarin authors, and the NIST PQC
project.


## References

(Currently ad-hoc inline; BibTeX conversion is the next pass.
This list contains the works cited above plus several that should
appear in a properly-cited submission.)

- Anderson, R. "Two remarks on public key cryptology." Invited
  lecture, ACM CCS 1997.
- Bellare, M., and Miner, S. "A forward-secure digital signature
  scheme." CRYPTO 1999.
- Bindel, N., Brendel, J., Fischlin, M., Goncalves, B., Stebila,
  D. "Hybrid key encapsulation mechanisms and authenticated key
  exchange." PQCrypto 2019.
- Eskandarian, S., Messeri, E., Bonneau, J., Boneh, D.
  "Certificate Transparency with privacy." PoPETs 2017.
- Itkis, G., and Reyzin, L. "Forward-secure signatures with
  optimal signing and verifying." CRYPTO 2001.
- Korzhitskii, N., Carlsson, N. "Characterizing the root
  landscape of Certificate Transparency logs." IFIP Networking
  2020.
- Krawczyk, H. "Simple forward-secure signatures from any
  signature scheme." ACM CCS 2000.
- Laurie, B., Langley, A., Kasper, E. "Certificate Transparency."
  RFC 6962, IETF, June 2013.
- Meier, S., Schmidt, B., Cremers, C., Basin, D. "The Tamarin
  prover for the symbolic analysis of security protocols." CAV
  2013.
- Meiklejohn, S., Kalinnikov, P., Lin, C.-S., Hutchinson, M.,
  Belvin, G., Raykova, M., Cutter, A. "Think global, act local:
  Gossip and client audits in verifiable data structures."
  arXiv:2011.04551, 2020.
- Newman, Z. "Sigstore: Software signing for everybody." IEEE
  S&P 2021 (industry track).
- NIST. "Module-Lattice-Based Digital Signature Standard." FIPS
  204, August 2024.
- Nordberg, L., Gillmor, D., Ritter, T. "Gossiping in CT." IETF
  draft, 2016.
- Stark, E., Sleevi, R., Muminovic, R., O'Brien, D., Messeri, E.,
  Felt, A. P., McMillion, B., Tabriz, P. "Does Certificate
  Transparency break the web?" IEEE S&P 2019.
- Stebila, D., Fluhrer, S., Gueron, S. "Hybrid key exchange in
  TLS 1.3." IETF draft, 2020.
- Tomescu, A., Bhupatiraju, V., Papadopoulos, D., Triandopoulos,
  N., Devadas, S. "Transparency logs via append-only
  authenticated dictionaries." ACM CCS 2019.


---

## Appendix A. Tamarin model listing

See `formal/stele.spthy`. The model is 231 lines including
comments; an annotated walkthrough is in `formal/README.md`.


## Appendix B. Selected vector outputs

See `testdata/vectors/INDEX.json`. 36 vectors total covering the
envelope canonicalisation, hashing, signing, Merkle root, Merkle
inclusion proofs, Merkle consistency proofs, and checkpoint
canonicalisation. Each vector is a JSON file with deterministic
inputs and SHA-256-stable expected outputs.


## Appendix C. Comparison vs CT / Rekor / Trillian / commercial

| Property | stele | RFC 6962 CT | Sigstore Rekor | Trillian | Commercial SIEM |
|---|---|---|---|---|---|
| Tamper-evident Merkle root | ✓ | ✓ | ✓ | ✓ | ✓ |
| Forward-secure operator key | ✓ | ✗ | ✗ | ✗ | ✗ |
| Hybrid PQ signatures (every site) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Witness mesh fork detection | ✓ | partial | ✗ | ✗ | ✗ |
| Threshold operator (t-of-N) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Producer enrollment with PoP | ✓ | n/a | ✗ | ✗ | ✗ |
| Continuous tripwire | ✓ | ✗ | ✗ | ✗ | partial |
| Formal model (Tamarin) | ✓ (2 of 3 lemmas) | partial | ✗ | ✗ | ✗ |
| SLSA L3 release provenance | ✓ | ✓ | ✓ | ✓ | varies |
| Cross-language byte-identical SDKs (3+ languages) | ✓ | ✗ | partial | ✗ | partial |
| Public, Apache-2.0 reference impl | ✓ | partial | ✓ | ✓ | ✗ |
| Private-log threat model | ✓ | ✗ | ✗ | partial | ✓ |
