# stele

> A tamper-evident audit log that survives a fully-compromised log operator.

Most audit logs lose all integrity guarantees the moment an attacker gets root
on the box that runs them. They edit a row, restart the daemon, and the
audit trail tells whatever story they want. Cloud audit logs (CloudTrail,
Audit Logs) help, but they trust the cloud provider absolutely and never
prove anything cryptographically.

`stele` (Greek for *stone monument bearing inscriptions* — like the Rosetta
Stone, which survived 2200 years legible) is an append-only audit log that
binds every entry into a structure no single party can rewrite, even with
full root access:

1. **Every entry is attested by the producer.** A registered producer
   signs the (source, data) it submits with an Ed25519 key — software,
   OS keychain, or TPM/SE-backed. The operator cannot inject fabricated
   entries.

2. **The chain of entries is committed to an RFC 6962 Merkle tree.** Any
   modification of any past entry invalidates the root.

3. **Roots are signed by a forward-secure key.** Periodic rotation
   irrevocably destroys the previous epoch's private key. Even if an
   attacker steals today's key, they cannot forge a checkpoint dated
   yesterday.

4. **Each checkpoint embeds a recent drand randomness beacon.** Because
   the beacon's value couldn't have existed before its round time,
   backdating a checkpoint is provably impossible.

5. **Each checkpoint is countersigned by independent witnesses.** A
   verifier requires N-of-M signatures from a known cohort. To rewrite
   history, an attacker must compromise the operator key AND N witnesses
   simultaneously, all run by independent parties.

6. **Each checkpoint is anchored to Sigstore Rekor** (a globally public,
   internet-scale transparency log). Once anchored, the operator cannot
   silently roll back without breaking Rekor's own integrity — detectable
   by every Rekor monitor on the internet.

7. **Selected entries are honeypots.** Any read of a flagged entry fires
   an alert webhook. The audit log itself becomes a detection tool: the
   attacker reading the log to learn what is known about them gets caught
   by the entry they read.

## Components

| Binary | Role |
| ------ | ---- |
| `steled` | Operator daemon. Accepts producer-attested entries, signs checkpoints, anchors them. |
| `stele` | Client + auditor CLI. Submits entries, fetches proofs, runs full audits, manages CA + producer + witness registration. |
| `stele-witness` | Tiny daemon run by independent parties. Countersigns checkpoints from registered operators; gossips with peer witnesses to detect operator forks; refuses to cosign once a fork is detected. |
| `stele-mirror` | Read-only replica daemon. Continuously pulls every entry from an operator and re-verifies producer sigs + chain integrity locally, then serves a strict copy. Run multiple mirrors on independent infrastructure to defeat selective-disclosure attacks. |
| `stele-cosigner` | Threshold-group member daemon. Each one holds a single Ed25519 key and signs canonical bytes on request. Run N independent cosigners on independent hardware; the operator's t-of-N coordinator collects their signatures. |
| `stele-tamper` | Demonstration-only attacker tool. Bypasses `steled` and mutates the BadgerDB directly so we can show tamper detection working. |

## Threat model

| Attack | Defence |
| ------ | ------- |
| Read everything | Out of scope (encrypt sensitive `data` client-side before logging). |
| Tamper with on-disk DB | Caught by replay: every entry self-verifies. |
| Replace DB and re-sign a new checkpoint | Caught by witness cosignature cohort and Rekor anchor — they remember the old root. |
| Steal the active operator key from disk | **Defeated by --hsm-module** — with HSM-backed signing, the private key never touches disk and cannot be extracted from the HSM. Even a full host-root compromise can only *ask* the HSM to sign, until the breach is detected and rotated out. |
| Steal current operator signing key, forge checkpoints | **Past checkpoints remain unforgeable** thanks to forward-secure key evolution. Future forgeries detected on next watchdog-triggered rotation (typically minutes). |
| Reach the ingest endpoint at all from the network | **Defeated by mTLS**: TLS handshake aborts without a valid client cert; HTTP-only requests are rejected. |
| Inject a fabricated entry pretending to come from producer X | Caught at THREE layers: (1) network — mTLS rejects unless client cert CN == ProducerID; (2) crypto — envelope must carry a valid Ed25519 signature; (3) registry — operator must have ProducerID registered. |
| Mess with files under <dir>/keys/ on the operator | **Caught by --watch-keys**: any modification fires immediate rotation. |
| Suddenly start logging 1000× normal volume (exfil disguise) | **Caught by --watch-rate**: surge triggers rotation + audit alert. |
| Backdate a checkpoint | Defeated by drand beacon embedded in every signed checkpoint. |
| Read a sensitive log entry without telling anyone | Caught: flag the entry as honeypot, get a webhook the moment it is queried. |
| Compromise ONE witness | Defended — verifier requires N-of-M. |
| Compromised witness lies during gossip about what it saw | **Defeated by signed gossip**: every gossip response is signed by the responding witness. Peers persist the signed statement; if the witness later contradicts itself, both signed claims are kept as cryptographic evidence. |
| Feed different checkpoints to different witness subsets | **Defeated by witness gossip**: any divergence between any two witnesses is detected and recorded with mathematical evidence. Affected witnesses refuse further cosignatures until cleared. |
| Read sensitive entries via the API without leaving a trace | **Defeated by --read-log**: every read is appended to a hash-chained, signed journal. Erasing a past read requires re-signing the entire downstream chain, detectable by any auditor with a prior reading. |
| Hide specific entries from specific auditors (selective disclosure) | **Defeated by --tls-ca-anchored mirrors**: third-party-run mirrors replicate everything via the public read API. Discrepancies between mirror and operator are auditable. |
| Substitute a trojaned `steled` binary | **Defeated by SLSA L4 provenance + cosign-verified releases**: every released binary is cryptographically traceable to a specific git commit and build environment, signature anchored to Sigstore Rekor. |
| HSM compromise (operator's signing HSM is stolen or coerced) | **Defeated by --threshold-group**: in threshold mode, no single HSM is sufficient — at least `threshold` of N independent cosigners must each sign. Forging requires compromising a quorum of them simultaneously. Threshold protection also applies to ROTATION certs (an attacker who steals the rotation key alone cannot advance to a new epoch). |
| Network attacker replays a recorded valid envelope | **Defeated by envelope dedup**: every accepted envelope's hash is recorded; re-submission is refused at the API layer. |
| Operator manipulates its wall clock | **Defeated by --beacon**: the drand beacon's known schedule cross-checks the operator's clock; divergence > 5 min refuses the checkpoint. |
| Witness lies but no other witness can prove its claims were wrong at time T | **Defeated by cross-attestations**: witnesses sign confirmations of peers, producing an auditable web of trust over time. |
| New auditor is tricked into trusting an attacker-provided root key | **Defeated by DNSSEC anchor**: the operator's domain owner publishes the root pubkey at `_stele.<domain>` and DNSSEC signs it; auditors authenticate via DNS. |
| Future quantum computer breaks Ed25519 ("harvest now, forge later") | **Defeated by hybrid mode across every signature site** (operator, producer envelopes, threshold cosigners, witness countersignatures, read log). Every signature carries BOTH an Ed25519 AND a Dilithium3 sig. Verifiers require both. Breaking just Ed25519 leaves the Dilithium half secure; the downgrade attack (stripping the quantum half) is refused at every site. |
| Compromise the operator AND ≥N witnesses simultaneously | Out of scope. Choose witnesses run by parties that would not collude. |
| Compromise the operator AND ≥threshold cosigners simultaneously | Out of scope by definition (this is what `threshold` was set to protect against). Choose N members held by N humans on N independent hosts in N jurisdictions. |

## Cryptographic stack

- **SHA-256** for all hashing (RFC 6962 leaves, internal nodes, EntryHash).
- **Ed25519** for every signature — operator, producer, witness.
- **Forward-secure key chain.** Each epoch's private key is generated
  fresh, used, then destroyed. A self-signed genesis cert anchors the
  chain at a single public key the operator publishes out-of-band.
- **RFC 6962 Merkle tree.** Compatible with Certificate Transparency,
  Sigstore Rekor, and the Go module checksum database. Inclusion +
  consistency proofs built using `github.com/transparency-dev/merkle`.
- **drand randomness beacon** for unpredictable time anchoring.

## Project layout

```
stele/
├── cmd/
│   ├── steled/        # operator daemon
│   ├── stele/         # client + auditor CLI
│   ├── stele-witness/ # witness daemon
│   └── stele-tamper/  # demo attacker tool
└── pkg/
    ├── merkle/      # RFC 6962 tree wrapper
    ├── logentry/    # canonical record + hash chain
    ├── attest/      # producer attestation (Envelope, SoftwareAttestor, KeychainAttestor, TPM2Attestor stub)
    ├── storage/     # BadgerDB append-only store + producer registry + witness registry
    ├── fwdsec/      # forward-secure signing chain
    ├── checkpoint/  # signed tree statement, witness signatures, beacon, verify
    ├── beacon/      # drand client
    ├── witness/     # witness daemon library + cosign protocol
    ├── anchor/      # external sinks (FileSink, RekorSink, MultiSink)
    ├── honeylog/    # canary entries + alert sinks (StderrSink, WebhookSink)
    ├── api/         # HTTP wire format + handlers
    ├── core/        # the Log: orchestrates everything
    └── verify/      # standalone client-side audit (no DB required)
```

## Quickstart

```bash
go build ./cmd/...

# 1. Operator
./steled --dir ./op-data --origin example.com/audit --init &

# 2. Witness (run on a different host in production)
./stele-witness --dir ./witness-alice --id auditor-alice --addr :9090 &
./stele-witness --dir ./witness-bob   --id auditor-bob   --addr :9091 &

# 3. Tell operator about both witnesses (this also tells each witness to watch the operator)
./stele witness-add --id auditor-alice --url http://localhost:9090
./stele witness-add --id auditor-bob   --url http://localhost:9091

# 4. Create a producer key and register it
./stele producer-init --id app-frontend --out ./frontend.key
./stele producer-register --id app-frontend --key ./frontend.key --desc "frontend service"

# 5. Log some events
./stele log --producer app-frontend --key ./frontend.key "user alice deleted /etc/passwd"
./stele log --producer app-frontend --key ./frontend.key --honey "fake AWS_ACCESS_KEY=AKIA...IGNORE"

# 6. Mint + anchor a checkpoint (also auto-runs every 30s)
./stele mint-checkpoint
./stele anchor

# 7. Verify
./stele audit
./stele verify-inclusion 0
```

## What the demo proves end-to-end

When you tamper with the on-disk database (using the included
`stele-tamper` tool), `steled` refuses to start back up because replay
catches the broken hash chain:

```
steled: replay: entry N failed self-verify: EntryHash mismatch
```

When you tamper with a checkpoint instead, every witness refuses to
re-cosign it (signature mismatch) and Rekor either refuses or
demonstrates the discrepancy publicly.

When an attacker reads a honey entry, the operator's webhook receives an
alert within seconds. The attacker has no way to know which entries are
honey because the flag is hashed into the Merkle root, identical-looking
to ordinary entries.

## HSM-backed signing (production deployments)

By default, `steled` stores the active forward-secure signing key as a
file under `<datadir>/keys/`. For production you should keep the key
inside a Hardware Security Module so a host-root compromise cannot
extract it.

stele ships with a PKCS#11 backend that works with any HSM exposing the
v3.0 EdDSA mechanism (`CKM_EDDSA`):

- **YubiHSM 2** — USB hardware, supports Ed25519 directly
- **AWS CloudHSM** — managed
- **Azure Key Vault Managed HSM** — via PKCS#11 broker
- **Thales Luna / Entrust nShield** — enterprise on-prem
- **SoftHSM2** — free software simulator (development, CI)

Quickstart with SoftHSM2 on macOS:

```bash
brew install softhsm
softhsm2-util --init-token --free --label stele-prod \
    --so-pin 1234 --pin 5678
# Note the allocated slot number from the output, then:
./steled \
    --dir /var/lib/stele/op \
    --origin example.com/audit \
    --init \
    --hsm-module /opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so \
    --hsm-slot <slot> \
    --hsm-pin 5678 \
    --hsm-key-prefix stele-prod
```

The operator data directory will now contain only `chain.json` (rotation
chain — public information) and `root.pub` (the genesis public key). No
private key material is ever written to disk. Verify with:

```bash
find /var/lib/stele/op/keys -name '*.key'   # empty output
```

Rotation works identically to the file-backed mode — each `stele rotate`
generates a fresh Ed25519 keypair inside the HSM, has the previous
HSM-held key sign the rotation cert, then calls `C_DestroyObject` to
irrevocably destroy the old private key. Forward-secure semantics
compose with HSM: even with `--extractable=false` keys, past signatures
remain unforgeable because past keys no longer exist anywhere.

For production, pass the PIN through `STELE_HSM_PIN` env var
(`--hsm-pin-env`) rather than `--hsm-pin` so it doesn't leak into
process listings or shell history.

## mTLS ingest with client certificates

Production deployments should require client certificates on the
append endpoint. stele ships with an in-process CA that issues
short-lived (90-day default) client certs whose Common Name binds to a
specific producer ID. The operator's ingest handler rejects any append
where the TLS client cert CN doesn't match `envelope.ProducerID`.

```bash
# 1. Bootstrap the operator CA (one time).
stele ca-init --org "example.com" \
  --out-cert /etc/stele/tls/ca.crt --out-key /etc/stele/tls/ca.key

# 2. Issue a server cert for steled.
stele ca-issue-server \
  --ca-cert /etc/stele/tls/ca.crt --ca-key /etc/stele/tls/ca.key \
  --cn "stele-operator" --host "stele.example.com,127.0.0.1" \
  --out-cert /etc/stele/tls/server.crt --out-key /etc/stele/tls/server.key

# 3. Issue a client cert per producer (CN = producer ID).
stele ca-issue-producer \
  --ca-cert /etc/stele/tls/ca.crt --ca-key /etc/stele/tls/ca.key \
  --id app-frontend \
  --out-cert /etc/stele/tls/app-frontend.crt --out-key /etc/stele/tls/app-frontend.key

# 4. Start steled with mTLS enforced.
steled --dir /var/lib/stele/op --origin example.com/audit --init \
  --tls-cert /etc/stele/tls/server.crt --tls-key /etc/stele/tls/server.key \
  --client-ca /etc/stele/tls/ca.crt

# 5. Producers connect with their client cert.
stele log --server https://stele.example.com:8443 \
  --tls-ca /etc/stele/tls/ca.crt \
  --tls-cert /etc/stele/tls/app-frontend.crt \
  --tls-key /etc/stele/tls/app-frontend.key \
  --producer app-frontend --key /etc/stele/producers/app-frontend.signkey \
  "..."
```

What's now defended:

- **HTTP requests are refused** (TLS only).
- **HTTPS without client cert is refused** (TLS handshake aborts).
- **Producer signature key theft alone is not enough**: an attacker who
  somehow obtained `app-frontend.signkey` but not `app-frontend.crt+key`
  is rejected at the TLS layer with HTTP 403 (`client cert CN does not
  match envelope ProducerID`).

## Auto-rotation watchdog

Three rotation triggers, all gated by a configurable debounce:

- `--rotate-every 1h` — scheduled rotation
- `--watch-keys` — fsnotify on `<dir>/keys/`; any modification triggers
  immediate rotation (catches the attacker who pokes at key material)
- `--watch-rate` — anomaly detection on append rate (10x surge or 0.1x
  drop)

```bash
steled ... \
  --rotate-every 1h \
  --watch-keys \
  --watch-rate \
  --watch-debounce 30s
```

Combined with forward-secure signing, this shrinks the forgery window
from "until manual rotation" to "until the next watchdog tick or
trigger event."

## Witness gossip (split-brain defence)

Witnesses pull each other's `seen` map every `--gossip-every` interval.
If witness A signed root `R1` at size 5 and witness B signed `R2` at the
same size, A's gossip round detects this, fetches B's actual signed
checkpoint as evidence, persists the fork record, and refuses any
further cosignatures for that operator until a human investigates.

```bash
# Boot 3 independent witnesses with gossip.
stele-witness --dir ./wA --id auditor-A --addr :9090 --gossip-every 30s &
stele-witness --dir ./wB --id auditor-B --addr :9091 --gossip-every 30s &
stele-witness --dir ./wC --id auditor-C --addr :9092 --gossip-every 30s &

# Wire them as peers of each other.
for me in 9090 9091 9092; do
  for peer in 9090 9091 9092; do
    [ "$me" = "$peer" ] && continue
    stele witness-peer-add \
      --on http://localhost:$me \
      --peer http://localhost:$peer
  done
done

# Inspect any forks a witness has detected.
stele witness-forks --on http://localhost:9090
```

What the operator can no longer get away with: feeding different
checkpoint roots to different witness subsets. The first gossip round
after a divergent cosignature exposes the contradiction, with both
signed checkpoints persisted as mathematical proof.

## Public read-only mirror (selective-disclosure defence)

Run one or more `stele-mirror` daemons on infrastructure outside the
operator's control. Each mirror continuously pulls every entry from the
operator's read API, re-verifies the producer signature and chain link
on every entry, and persists into its own BadgerDB. Auditors that
distrust the operator query a mirror instead — divergences in what
mirror vs. operator serves for the same index are obvious.

```bash
stele-mirror --dir ./mirror-data \
    --upstream https://stele.example.com:8443 \
    --tls-ca ./ca.crt \
    --addr :8444
```

Mirrors expose `/api/v0/entries/{idx}`, `/api/v0/entries?from=N&to=M`,
`/api/v0/size`, and `/api/v0/mirror-status` (sync lag, error count).

## Post-quantum hybrid signatures

Boot the operator with `--pq-mode hybrid` to make every operator
signature (rotation certs + checkpoints) a hybrid of **Ed25519 +
Dilithium3** (NIST FIPS 204 ML-DSA Level 3). Verifiers then require
BOTH signatures to validate — an attacker has to break classical AND
post-quantum cryptography simultaneously to forge.

```bash
steled --dir ./op --origin example.com/audit --init --pq-mode hybrid
```

What the operator's `chain.json` looks like in hybrid mode:

```
epoch 0: ed25519=32B, dilithium3=1952B
```

What each signed checkpoint carries:

```
classical sig : 64 bytes   (Ed25519)
quantum sig   : 3293 bytes (Dilithium3)
```

The verifier (and the `stele audit` command) auto-detect hybrid mode
from the chain's per-epoch quantum public key. Tamper-detection matrix:

| Attack | Verifier behaviour |
| ------ | ------------------ |
| Verbatim checkpoint | accepts |
| Flip a byte in the Ed25519 half | rejects: classical signature invalid |
| Flip a byte in the Dilithium half | rejects: quantum signature invalid |
| Strip the quantum half (downgrade attack) | rejects: chain has quantum pubkey but checkpoint is missing quantum signature |
| Tamper with the canonical message | rejects: both halves fail |

This protects against the "harvest now, forge later" threat from
future quantum computers: an attacker who records today's stele log
and someday breaks Ed25519 cannot retroactively forge any hybrid-mode
signature, because Dilithium3 remains secure.

Hybrid signing now covers EVERY signature site in stele:

| Site | Classical | Quantum | Switch with |
| ---- | --------- | ------- | ----------- |
| Operator checkpoint / rotation cert | Ed25519 | Dilithium3 | `steled --pq-mode hybrid` |
| Producer envelope | Ed25519 | Dilithium3 | `stele producer-init --pq` |
| Threshold cosigner | Ed25519 | Dilithium3 | `stele-cosigner --pq-mode hybrid` |
| Witness countersignature | Ed25519 | Dilithium3 | `stele-witness --pq-mode hybrid` |
| Read log event | Ed25519 | Dilithium3 | enabled automatically when `steled --pq-mode hybrid` |

Every site implements:
- Quantum public key binding into canonical bytes — quantum half cannot be substituted without invalidating the classical signature
- Refusal-to-downgrade when the trust anchor (rotation chain, registered producer record, witness registration, group descriptor) carries a quantum pubkey but the signature is classical-only
- Independent verification path — both halves must verify against their own pubkeys

Caveats for v1:

- **HSM + hybrid is not yet supported**: no PKCS#11 mechanism exists
  for Dilithium yet. Use `--pq-mode hybrid` with on-disk keys until
  HSM vendors ship PQC support (most are on the roadmap).
- **Mixed deployments work**: a hybrid producer can submit to a
  classical operator (the operator just verifies the classical half
  and stores the quantum fields verbatim for future audits). A
  classical witness can countersign hybrid checkpoints — though the
  verifier should require hybrid witness sigs against hybrid
  operators for full post-quantum protection.

## Tamper-evident read log

Every read served by the operator (entry-by-index lookups, range
queries) is appended to a hash-chained, signed journal at
`<dir>/read-log/`. Each event records:

- the entry index + leaf hash that was read,
- the caller IP + User-Agent (best-effort from the HTTP layer),
- a chain hash linking to the previous read event,
- a signature by the operator's read-log key.

To quietly erase a past read, the operator would have to re-sign the
entire downstream chain — detectable if any auditor has retained an
earlier reading of the read log. Combined with honeylog canaries, the
read log catches passive surveillance attempts that bypass the
checkpoint/anchor layer entirely.

```bash
# Read log is on by default; disable with --read-log=false.
steled --dir ./op --origin example.com/audit --init   # read log auto-created

# Inspect.
curl http://localhost:8080/api/v0/read-log/size
curl 'http://localhost:8080/api/v0/read-log/events?from=0&to=100'
```

## Signed witness gossip (dishonesty proofs)

When witnesses gossip with each other, every response is now signed
by the responding witness. Receiving peers persist the signed
statements per (peer, origin). If a peer ever contradicts an earlier
signed claim — same size, different root — both signed statements are
kept as cryptographic evidence of dishonesty, and the affected origin
is automatically flagged as forked.

```bash
# A's view of B (gathered via gossip).
curl 'http://localhost:9090/witness/v0/peer-attestations?peer_id=auditor-B'
```

This closes the gap where a malicious witness could lie during gossip
without leaving a record. A peer cannot deny anything they previously
signed — and cannot quietly amend the public record without exposing
the contradiction to every peer that retained the older statement.

## Replay protection

Every accepted envelope's SHA-256 (over its canonical bytes) is
recorded in BadgerDB. A second submission of the same envelope is
refused with `replay: envelope already accepted as entry N`. This
closes the "network attacker records a valid past request and replays
it later" attack — even an attacker with full TLS visibility into the
ingest endpoint cannot make the same envelope count twice.

## Clock-skew validation

When the operator's checkpoint embeds a drand beacon round, the
operator's wall clock is cross-checked against the beacon's known
schedule (drand mainnet ticks every 3 seconds from a fixed Genesis
time). If they disagree by more than 5 minutes, the operator REFUSES
to mint the checkpoint. This closes the subtle attack where an
attacker manipulates the operator's clock to forge timestamps that
beat the beacon's coarse-grained protection.

## Cross-witness attestations (web of trust)

When witness A pulls witness B's signed view during gossip and finds
their views agree at one or more sizes, A signs a cross-attestation:
"I, A, confirm peer B's view at time T." This cross-attestation is
itself stored and exposed via `GET /witness/v0/cross-attestations`.

Aggregating cross-attestations across the witness mesh produces a web
of trust. A witness that consistently signs others' views and is
counter-signed back is "well-connected" — its claims have independent
endorsement. A witness that no peer cross-attests is isolated, which
is itself a flag.

## DNSSEC-anchored trust

`stele dns-record --domain example.com` prints the TXT record content
an operator should publish at `_stele.example.com`. Once DNSSEC-signed,
new auditors fetch the operator's root public key via DNS instead of
out-of-band exchange:

```bash
dig +dnssec TXT _stele.example.com
```

This closes a social-engineering vector at auditor onboarding. The
trust chain runs through DNSSEC's well-audited PKI to the domain
owner's TLD.

## Threshold operator signatures (t-of-N)

For environments where even an HSM compromise is unacceptable, run the
operator in **threshold mode**: instead of one signing key, the
"operator key" becomes a group of N members. Each checkpoint must be
signed by at least `threshold` of them. The members are independent
`stele-cosigner` daemons, ideally on independent hardware, in
different physical locations, held by different humans.

To forge anything in threshold mode, an attacker must compromise at
least `threshold` of the N cosigners simultaneously. No HSM theft, no
operator-host root, no single-human bribery is sufficient.

```bash
# 1. Boot 3 cosigners on independent infra.
stele-cosigner --dir ./cos-alice --id alice --addr alice.example.com:9101 &
stele-cosigner --dir ./cos-bob   --id bob   --addr bob.example.com:9101 &
stele-cosigner --dir ./cos-carol --id carol --addr carol.example.com:9101 &

# 2. Build a 2-of-3 group descriptor.
stele group-init \
    --origin example.com/audit \
    --threshold 2 \
    --cosigners http://alice.example.com:9101,http://bob.example.com:9101,http://carol.example.com:9101 \
    --out group.json

# 3. Boot the operator in threshold mode.
steled --dir ./op --origin example.com/audit --init \
    --threshold-group ./group.json

# 4. Inspect the active group via the operator's API.
stele group-show --server http://localhost:8080
```

Behaviour in the demo we ran:

- **All cosigners up** → every checkpoint carries 3 valid MemberSigs (more than the threshold; verifier counts up to threshold).
- **2 of 3 cosigners down** → operator REFUSES to mint a checkpoint:
  `threshold not reached: 1/3 valid sigs (need 2)`.
- **Recovery** → as soon as a second cosigner returns, the next mint
  succeeds.

The cosigner identity (member ID) is hard-bound to the public key in
the group descriptor. Any substitution attempt — e.g. an attacker
returning a signature with the right MemberID but a different pubkey —
is caught by `threshold.VerifyMulti` and contributes zero to the count.

The `stele audit` command auto-detects threshold mode by fetching
`/api/v0/threshold-group` and validating the active group's digest
against what each checkpoint claims.

## SLSA Level 4 builds + cosign-signed releases

Releases are built by GitHub Actions with:

- `CGO_ENABLED=0`, pinned Go version, `-trimpath`, `-buildvcs=false`,
  `-buildid=` ldflag — bit-for-bit reproducible.
- A **second independent build** runs in the same workflow and the two
  outputs are byte-compared. If reproducibility breaks, releases fail.
- The **SLSA generic generator** publishes signed provenance
  attestations for every binary, tied via Sigstore Fulcio to the
  workflow's OIDC identity — provenance cannot be forged.
- Each binary is signed with **cosign keyless**, signatures anchored to
  **Sigstore Rekor** (a globally-replicated public transparency log).
- A CycloneDX **SBOM** ships alongside.

Auditor verification:

```bash
slsa-verifier verify-artifact ./steled \
  --provenance-path ./steled.intoto.jsonl \
  --source-uri github.com/<owner>/stele \
  --source-tag v1.2.3

cosign verify-blob ./steled \
  --certificate ./steled.cert \
  --signature ./steled.sig \
  --certificate-identity-regexp '^https://github\.com/<owner>/stele/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

See [.github/workflows/release.yml](.github/workflows/release.yml) for
the full pipeline.

## What's intentionally NOT in this build

For honest scoping, these are real production needs that we have not
implemented in this round:

- **Real Rekor-compliant signature format** for `RekorSink`. The
  current shape submits hashedrekord with `format: "raw"`, which
  Sigstore's strict validator may reject. Wire in SSH or x509-PEM
  signing for production.
- **Producer-side hardware attestation (TPM2 / SEV / SGX).** The
  `TPM2Attestor` is a stub. (The operator's key is HSM-backed.)
- **gRPC streaming ingest** for high-volume producers.
- **Prometheus metrics** for ingest rate, witness lag, anchor failures.
- **Threshold operator signatures (FROST).** For deployments where
  even an HSM compromise is unacceptable.

## Tests

```bash
go test ./...
```

Coverage today: Merkle tree (empty / append / exhaustive consistency /
fork detection / random 500-leaf), entry sealing + chain + tamper
detection, checkpoint sign + every-field-tamper + rotation, forward-
secure chain genesis + rotate + replay + forged-cert rejection, core
flow (append + inclusion + replay across restart + anchor chain).
