# Stele Playbook

The complete operator + producer + auditor manual for using and
running stele. Read this end-to-end once; then bookmark §7
(Cookbook) and §9 (Troubleshooting) for daily use.

## Table of contents

1. [What stele is](#1-what-stele-is)
2. [Who reads what](#2-who-reads-what)
3. [Concepts](#3-concepts)
4. [Operator playbook](#4-operator-playbook)
5. [Producer playbook](#5-producer-playbook)
6. [Auditor playbook](#6-auditor-playbook)
7. [Cookbook — common scenarios](#7-cookbook)
8. [Reference](#8-reference)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. What stele is

Stele is a **tamper-evident audit log**. It's the system you reach for when:

- You need a record that nobody — including the system's own operator — can rewrite without leaving public evidence.
- You need to prove to a third party (regulator, customer, auditor) that a specific event was logged at a specific time, AND that no other event was hidden from them.
- You need this property to survive every realistic threat: host compromise, malicious admin, network attacker, the operator going rogue, even (in hybrid PQ mode) a future quantum computer.

It's the same family of system as Certificate Transparency, Sigstore Rekor, Trillian, and Google's Key Transparency — but generalised to "log anything, not just certificates."

Stele is appropriate for:

- Compliance / regulatory audit trails (SOX, HIPAA, GDPR access logs)
- Internal security event logs that must survive insider tampering
- Build / release provenance ("this artifact was built on this date from this commit")
- Voting receipts, scientific lab notebooks, anti-fraud transaction logs
- Anywhere "the log is the contract"

Stele is NOT appropriate for:

- High-throughput general-purpose logging (use Loki / Elastic / Splunk; stele tops out at ~7K appends/sec on a single node by design — each append fsyncs)
- Logs of secret content you don't want the operator to see (stele records what producers sign; it doesn't encrypt content)
- "I just want grep-able server logs" — stele is over-engineered for that

---

## 2. Who reads what

| You are | Read |
|---|---|
| Deciding whether to use stele | §1, §3 |
| Going to operate stele in production | §4, §7 (cookbook), §9 (troubleshooting), [THREATMODEL.md](THREATMODEL.md), [RECOVERY.md](RECOVERY.md) |
| Writing software that submits to stele | §5 + §8 (API reference) |
| Auditing a stele log | §6, §7 (auditor scenarios) |
| Contributing to stele itself | [HARDENING.md](HARDENING.md) + [THREATMODEL.md](THREATMODEL.md) |

---

## 3. Concepts

The minimum vocabulary to operate stele confidently.

### 3.1 The log

A stele **log** is an ordered append-only sequence of **entries**. Each entry is:

- A **producer-signed envelope** containing data + producer identity + timestamp
- An **operator-assigned index** (monotonically increasing from 0)
- A **chain link** (this entry's hash includes the previous entry's hash)
- A **Merkle leaf** that places it in the global RFC 6962 Merkle tree

The combination of hash chain + Merkle tree means: changing any historical entry breaks the chain AND changes the tree root.

### 3.2 The operator (`steled`)

The single party that runs `steled` and accepts producer submissions. The operator:

- Receives producer envelopes via HTTP at `/api/v0/append`
- Validates the producer signature + producer registration
- Assigns the next index, builds the entry, persists to BadgerDB
- Signs **checkpoints**: a {root, size, time} statement signed by the operator's chain key
- Anchors checkpoints to external sinks (file + Sigstore Rekor)
- Serves read endpoints for producers, mirrors, auditors

In a healthy deployment, the operator is **trusted for liveness** but **NOT trusted for integrity**: the protocol's job is to catch any operator that misbehaves.

### 3.3 The chain (forward-secure signing)

The operator's signing key rotates over time:

- **Genesis (epoch 0)**: the operator generates a keypair. The pubkey is the **trust anchor** — published to auditors out of band.
- **Rotation**: every `--rotate-every` interval (or triggered by the watchdog), the operator generates a new keypair. A **rotation certificate** signed by the OLD key vouches for the NEW key. The old key is then irrevocably destroyed.
- The full sequence of rotation certs is the **chain**. Auditors anchor on the genesis pubkey, then walk the chain to verify any later epoch.

Forward security means: a key compromise today cannot forge yesterday's signatures.

### 3.4 Witnesses

Independent third parties that **countersign** every operator checkpoint. A witness:

- Holds its own keypair
- Watches one or more operators
- Refuses to cosign two different roots at the same size from the same operator (detects forks)
- **Gossips** with other witnesses, comparing signed seen-roots; a witness that returns inconsistent statements between gossip rounds gets caught mathematically (both signed statements survive as evidence)

A checkpoint with `q` witness cosignatures is "vouched for by `q` independent observers." Compliance auditors check this count.

### 3.5 The mirror

Read-only replica of the operator. Each mirror:

- Pulls every entry from the operator
- Independently verifies producer signatures + chain integrity
- Stores its own copy
- Serves the same read API as the operator

Auditors hit mirrors they trust instead of (or in addition to) the operator. A mirror that disagrees with the operator about any entry is evidence of tampering.

### 3.6 Threshold mode (t-of-N operator key)

Optional. Instead of one operator keypair, the chain key is split across **N cosigners** (each on independent infrastructure). Any **t** of them must agree to sign each checkpoint and each rotation cert.

To forge anything, an attacker must compromise at least `t` cosigners simultaneously — different hosts, different humans, ideally different jurisdictions. The single-host operator compromise no longer suffices.

Use threshold mode when single-key compromise is unacceptable (banks, regulators, multi-party governance).

### 3.7 Hybrid post-quantum mode

Optional. Every signature site (envelopes, checkpoints, rotation certs, witness countersignatures, member sigs, enrollments) is signed TWICE: classical Ed25519 + post-quantum **Dilithium3** (NIST FIPS 204 ML-DSA Level 3). Verifiers require both signatures to validate.

Future-proofs against a quantum computer that breaks Ed25519 via Shor's algorithm.

Use hybrid mode for logs whose verifiability matters for 10+ years.

### 3.8 Anchoring

The operator publishes each checkpoint to one or more **external sinks**:

- **File anchor**: append-only file on disk (`/anchors/anchor.log`)
- **Sigstore Rekor**: a public transparency log run by the Sigstore project
- **drand beacon**: binds the checkpoint to a public randomness value that didn't exist before a specific time (defeats backdating)

Auditors check the operator's claimed checkpoint against the external anchor. The operator can't both forge the log AND retract the public anchor entry — Rekor itself is a transparency log.

### 3.9 Producer enrollment

Producers don't just appear in the operator's registry — they go through an enrollment ceremony:

- **Operator-side**: signs the producer record with the chain key. A producer in the registry that doesn't carry a verifiable signature is rejected by `--require-enrollment` mode.
- **Producer-side (challenge-response)**: the producer proves it controls the private key by signing a server-issued challenge. The resulting record carries BOTH the operator's enrollment signature AND the producer's challenge response — provable mutual consent.

### 3.10 Tripwire

A background goroutine inside `steled` that periodically re-derives the Merkle root from BadgerDB and compares to the last anchored checkpoint. If anyone modifies a stored entry out-of-band (disk-level attacker, buggy ops script, bad backup-restore), tripwire fires within `--tripwire-every`.

### 3.11 Watcher

`stele-watcher` is the **standalone** cross-checker. Runs OUTSIDE the operator and witness mesh. Each pass:

- Fetches the operator's latest checkpoint
- Fetches each witness's signed seen-root
- Compares — if any source disagrees with the others at the same size, exits non-zero

Run from a CI cron, independent infrastructure, anywhere. It's the "what if everything else is compromised" backstop.

### 3.12 Read log + admin log

Two additional tamper-evident journals:

- **Read log** (`/read-log/...`): every served `GET /entries/...` writes a signed event to a separate hash-chained log. Catches "I read this and didn't tell anyone."
- **Admin log** (`/admin-log/...`): every admin mutation (rotate, producer enrollment, witness add, threshold-group change) writes a signed event. Catches "I changed the rules and pretended I didn't."

Both journals have their own signing keys (independent of the operator chain) and their own auditable read endpoints.

---

## 4. Operator playbook

### 4.1 Deploying

Three paths. Pick the one that matches your environment. See
[QUICKSTART.md](deploy/QUICKSTART.md) for full commands.

| Path | Best for |
|---|---|
| **Docker** | Single host, evaluation, demos |
| **Helm** | Existing Kubernetes cluster (production-shape topology in 5 minutes) |
| **systemd** | Bare metal / VMs, no container runtime |

After whichever path:

```sh
curl -fsS http://<operator>/healthz       # liveness
curl -fsS http://<operator>/readyz        # readiness
curl -fsS http://<operator>/metrics       # Prometheus exposition
```

### 4.2 First-time setup

```sh
# 1. Print + seal the trust anchor (BEFORE any producer enrols!).
stele-export-chain identity --dir /var/lib/stele --format paper > root.txt
# → print, fold, seal in safe. This is the auditor's trust seed.

# 2. Register witnesses.
for url in https://w1.example:9090 https://w2.example:9090 https://w3.example:9090; do
    id="$(basename "$url" | cut -d. -f1)"
    stele witness-add --server http://<operator> --url "$url" --id "$id"
done

# 3. (Optional) Threshold mode.
# Deploy 3 cosigners on independent infra, then mint a group:
stele group-init --members alice,bob,carol --threshold 2 --out group.json
# Restart steled with --threshold-group=group.json
```

### 4.3 Day-2 operations

#### Rotate the operator key

```sh
curl -X POST http://<operator>/api/v0/rotate
# Scheduled rotation: pass --rotate-every=1h on startup. The watchdog
# also rotates on key-directory tamper detection.
```

After rotation, every existing producer continues to work — the chain links the old and new key cryptographically. Auditors holding the genesis root pubkey verify the rotation cert + the new key automatically.

#### Enroll a producer (challenge-response, default)

```sh
# Producer side: generate the key.
stele producer-init --id alice --out alice.priv

# Run the two-step ceremony.
stele enroll-producer --server http://<operator> \
    --id alice --key alice.priv \
    --scope "logs:audit" --validity 90d
```

The resulting `Producer` record carries the operator's enrollment signature AND the producer's challenge-response signature — provable mutual consent.

#### Revoke a producer

```sh
stele revoke-producer --server http://<operator> --id alice --reason "key compromised"
```

Past entries from `alice` remain valid (their envelope was signed at the time and the log is immutable). Future `Append` calls from `alice` are refused.

#### Backups (hourly via cron or systemd timer)

```sh
# Option A: pause-restart (briefest outage).
systemctl stop steled
stele-backup snapshot --dir /var/lib/stele --out /backups/stele.bin
systemctl start steled

# Option B: filesystem snapshot (no downtime).
zfs snapshot stelepool@hourly
stele-backup snapshot --dir /mnt/zfs-snap/stele --out /backups/stele.bin
```

ALSO every key rotation, export the rotation chain off-host:

```sh
stele-export-chain full --dir /var/lib/stele --out /backups/chain-$(date +%s).json
```

See [RECOVERY.md](RECOVERY.md) for the runbook.

#### Add a witness mid-flight

```sh
# 1. Stand up the new witness server (Docker / Helm / systemd).
# 2. Tell the operator about it.
stele witness-add --server http://<operator> --id w-d --url https://w4.example:9090
# 3. The operator immediately starts asking w-d to countersign on
#    the next checkpoint cycle. No downtime.
```

#### Switch to hybrid PQ mode

```sh
# 1. Stop the operator + every witness.
# 2. Start each with --pq-mode=hybrid. They generate Dilithium3 keys
#    alongside their existing Ed25519 keys.
# 3. New checkpoints carry both classical + quantum signatures.
#    Existing checkpoints remain classical-signed but the chain
#    forward-binds the quantum pubkey from the rotation cert that
#    follows the switch.
```

### 4.4 Monitoring

Stele exposes 18 Prometheus metrics. The Grafana dashboard at [deploy/grafana/stele-overview.json](deploy/grafana/stele-overview.json) renders all of them.

| Metric | What it means | Alert on |
|---|---|---|
| `stele_appends_total{outcome}` | Append result rate | `outcome="error"` > 1% |
| `stele_append_duration_seconds` | Append p50/p95/p99 | p99 > 250ms for 10m |
| `stele_tree_size` | Current entry count | Stops growing during expected ingest |
| `stele_active_epoch` | Current chain epoch | Unexpected change |
| `stele_last_anchor_age_seconds` | Time since last anchor | > 1h |
| `stele_witness_quorum_healthy` | 1 if quorum reachable | = 0 |
| `stele_witness_cosign_total{witness,outcome}` | Per-witness cosign rate | sustained `outcome="error"` |
| `stele_tripwire_runs_total{outcome}` | Continuous integrity | `outcome="tamper"` ANY count |
| `stele_ingest_rejects_total{reason}` | Ingest guards firing | sudden spike (DOS?) |
| `stele_honeypots_total` | Canary triggers | ANY increment is alarming |
| `stele_watchdog_rotations_total{reason}` | Watchdog firings | `reason="key_dir_modified"` |

Prometheus alert rules ship in [deploy/prometheus/alerts.yml](deploy/prometheus/alerts.yml).

### 4.5 Incident response

| Signal | Page who | Runbook |
|---|---|---|
| `stele_tripwire_runs_total{outcome="tamper"}` ticked | On-call (page) | [RECOVERY.md §7](RECOVERY.md) "Detected tampering" |
| `stele_witness_quorum_healthy = 0` for 5m+ | On-call (page) | [RECOVERY.md §6](RECOVERY.md) |
| `stele_honeypots_total` ticked | Security (page) | Compromise indicator. Investigate which honey entry was read + by whom. |
| Fork detected (any witness reports `forks > 0`) | Security (page) | Operator integrity compromised. Stop ingest, investigate, plan recovery per [RECOVERY.md §9](RECOVERY.md). |
| `stele_last_anchor_age_seconds > 3600` | On-call (page) | Anchor sinks failing. Inspect Rekor / file sink. |
| `stele_append_duration_seconds` p99 > 1s sustained | On-call (ticket) | Disk + concurrency check. |

### 4.6 Upgrading

Stele commits to:
- **Wire format stability** across minor versions
- **CLI flag stability** with one-minor-version deprecation
- **Persistence format stability** with forward-only migrations

Upgrade flow:
```sh
# 1. Read CHANGELOG for breaking changes (none expected on patch versions).
# 2. Stop steled, install the new binary, restart.
# 3. Watch /metrics for any unexpected outcome=error increments in the
#    first 10 minutes.
# 4. Run stele audit --pdf upgrade-evidence.pdf — file the PDF in your
#    release-evidence repo.
```

---

## 5. Producer playbook

### 5.1 First-time enrollment

```sh
# 1. Generate a producer key (kept LOCAL; NEVER given to the operator).
stele producer-init --id my-service --out my-service.priv

# 2. Enroll via challenge-response.
stele enroll-producer --server http://<operator> \
    --id my-service --key my-service.priv \
    --scope "logs:my-service" --validity 90d
# Output confirms: "consent: operator + producer (proof of possession)"
```

### 5.2 Submitting entries

Three paths, ranked by ergonomics:

**Python** ([sdk/python](sdk/python/README.md)):
```python
from stele import Producer, PrivateKey
priv = PrivateKey.from_file("alice.priv")
producer = Producer(id="alice", private_key=priv, server="http://<operator>")
producer.log(source="/var/log/app", data=b"hello stele")
```

**TypeScript / JavaScript** ([sdk/typescript](sdk/typescript/README.md)):
```ts
import { Producer, PrivateKey } from "@stele/sdk";
const priv = await PrivateKey.fromBase64(privB64);
const producer = new Producer({ id: "alice", privateKey: priv, server: "http://<operator>" });
await producer.log({ source: "/var/log/app", data: "hello stele" });
```

**Go CLI** (reference implementation):
```sh
stele log --server http://<operator> \
    --producer my-service --key my-service.priv \
    --source "/var/log/app/access.log" \
    "user alice deleted /etc/passwd"
```

**Other languages**: build envelope canonicalisation against the byte format documented at [pkg/attest/attest.go](pkg/attest/attest.go). The format is `length-prefixed-strings + i64 timestamp + zero-length-bound quantum field` — see the inline comment on `Envelope.Canonical`. Both SDKs are byte-tested against the Go output for guaranteed interop.

HTTP wire format (for code that doesn't want to use an SDK):

```http
POST /api/v0/append HTTP/1.1
Content-Type: application/json

{
  "envelope": {
    "producer_id": "my-service",
    "public_key": "<base64 ed25519>",
    "attestation_type": "software",
    "time_ns": 1701000000000000000,
    "source": "/var/log/app/access.log",
    "data": "<base64 of your payload>",
    "signature": "<base64 ed25519 signature over canonical bytes>"
  }
}
```

Hybrid mode: add `quantum_public_key` and `quantum_signature` (Dilithium3) to the envelope.

### 5.3 Day-2

| Action | How |
|---|---|
| Rotate your producer key | `stele producer-init` to mint a new key, then `stele enroll-producer` with the new key under the same `--id`. The operator records the change in the admin log. |
| Check if you're rate-limited | Look for 429 responses. Server returns `Retry-After`. Default limit: 100 RPS per producer with 200 burst. |
| Verify your own entries were recorded | `stele verify-inclusion <index>` returns OK if the operator + your envelope agree |
| Watch for admin changes affecting you | `curl http://<operator>/api/v0/admin-log/events?from=<last_seen>` |

---

## 6. Auditor playbook

### 6.1 Get the trust anchor

The trust anchor is the operator's **genesis root pubkey**. Three ways to obtain it, ranked by trust strength:

| Method | Strength | When to use |
|---|---|---|
| **Paper safe** (`stele-export-chain identity --format paper`) | Strongest — physical chain of custody | Operator-side; gives auditors a one-page reference |
| **DNSSEC** (`stele dnssec-fetch --origin example.com`) | Strong — DNSSEC PKI vouches | Auditor's first-mile; replaces Slack/email pubkey exchange |
| **Mirror or Rekor** | Medium — trusts the mirror operator + Sigstore | Quick smoke audits; never relied on alone for compliance |

DNSSEC path:
```sh
stele dnssec-fetch --origin myorg.example.com
# ==== STELE TRUST ANCHOR — DNSSEC-VALIDATED ====
# origin       : myorg.example.com
# root_pubkey  : <base64>
# chain_digest : <hex>
```

Save the `root_pubkey` value. You'll pass it to every subsequent audit.

### 6.2 Run an audit

```sh
stele audit --server https://stele.myorg.example.com \
    --root <base64-from-step-6.1> \
    --root-source dnssec \
    --pdf my-audit-$(date +%Y-%m-%d).pdf \
    --json my-audit-$(date +%Y-%m-%d).json \
    --sample-n 50
```

Output:
- **stdout**: human-readable 5-step walkthrough showing chain, checkpoint, hash-chain, Merkle inclusion all OK
- **`.pdf`**: structured report — the deliverable you give a compliance reviewer
- **`.json`**: machine-readable for archival / diffing

The PDF includes:
1. Cover page with verdict (PASS / WARN / FAIL)
2. Trust anchor — root pubkey + how you obtained it
3. Rotation chain — every epoch + whether each verified
4. Latest checkpoint — root, witnesses cosigning, threshold + hybrid status
5. Inclusion sample — N entries fetched + verified
6. Findings — any specific defects

### 6.3 Continuous fork detection

For high-stakes deployments, run `stele-watcher` on a schedule from independent infrastructure:

```sh
stele-watcher --once \
    --origin myorg.example.com/audit \
    --operator https://stele.myorg.example.com \
    --witnesses https://w1.example:9090,https://w2.example:9090,https://w3.example:9090 \
    --json
```

Exit codes:
- `0` — all sources agree
- `1` — divergence detected (FORK)
- `2` — sources unreachable

Wire to your alert pipeline: a non-zero exit pages on-call.

### 6.4 Independently verifying inclusion

```sh
stele verify-inclusion 12345 --server <mirror-or-operator>
stele verify-consistency 1000000 1500000 --server <mirror-or-operator>
```

Both checks are local: they fetch the proof + verify against the trust anchor. The operator can't cheat them — a tampered proof fails the cryptographic check.

### 6.5 Reading the PDF audit report

The PDF is self-explanatory by design. Specifically check:

- **Verdict on page 1**: must be PASS for compliance use. WARN means at least one finding deserves operator attention. FAIL means do not accept this log as evidence.
- **Trust anchor section**: "Matches operator-reported root" must be **Yes**. Source should be `paper` or `dnssec` for compliance-grade evidence.
- **Chain section**: "Chain verifies against trust anchor" must be **Yes**.
- **Checkpoint section**: "Signature verifies" must be **Yes**. Witness count should be at least the operator's required quorum.
- **Inclusion-proof sample**: every sample row must read `PASS`. Any FAIL row is grounds to reject the audit.

---

## 7. Cookbook

Common scenarios with concrete commands.

### Bootstrap a brand-new stele log in 15 minutes

See [QUICKSTART.md](deploy/QUICKSTART.md). Then §4.2 above.

### Migrate from legacy producers to enrollment mode

```sh
# 1. While --require-enrollment is OFF, re-enroll every existing producer:
for id in $(stele producer-list --server http://<operator> | jq -r '.producers[].id'); do
    stele enroll-producer --server http://<operator> \
        --id "$id" --key "/keys/$id.priv" --scope "migrated" --validity 365d
done

# 2. Restart steled with --require-enrollment. Future Appends from
#    un-enrolled producers are refused.
```

### Switch the whole stack to hybrid PQ

1. Stop everything.
2. On each daemon (`steled`, every `stele-witness`, every `stele-cosigner`), add `--pq-mode=hybrid` and restart.
3. Each daemon generates a Dilithium3 keypair alongside its existing Ed25519 keypair.
4. Future signatures carry both halves; verifiers require both.

### Recover from operator disk loss

[RECOVERY.md §3 + §8](RECOVERY.md). Quick form:

```sh
# 1. Restore entry DB from most recent backup.
stele-backup restore --dir /var/lib/stele --in /backups/stele-latest.bin

# 2. Restore the rotation chain from off-host export.
cp /backups/chain-latest.json /var/lib/stele/keys/chain.json

# 3. Restart steled.
systemctl start steled

# 4. Confirm via independent audit.
stele audit --server http://<operator> --root <paper>
```

### Detect a malicious operator (fork)

Run `stele-watcher` from an independent host on a cron. The first time it detects divergent roots between the operator and any witness, it exits non-zero. Wire that exit to PagerDuty.

### Sample compliance evidence (every release / quarterly audit)

```sh
stele audit --server https://stele.myorg.com \
    --root <paper-anchor> --root-source paper \
    --sample-n 100 \
    --pdf evidence/$(date +%Y-Q%q)-audit.pdf \
    --json evidence/$(date +%Y-Q%q)-audit.json
```

Archive both files. The PDF is the human deliverable; the JSON is the machine-readable record for diffing against previous quarters.

### Stand up a chaos rig for engineering practice

```sh
cd chaos
docker compose up -d --build
./run-chaos.sh setup
./run-chaos.sh assert-all   # exit 0 = healthy + every defence fires correctly
```

See [chaos/README.md](chaos/README.md).

---

## 8. Reference

### 8.1 Binaries

| Binary | Purpose |
|---|---|
| `steled` | Operator daemon |
| `stele` | CLI: producer, auditor, admin |
| `stele-witness` | Independent countersigner |
| `stele-mirror` | Read-only replica |
| `stele-cosigner` | Threshold-mode cosigner |
| `stele-backup` | Hot backup of the entry DB |
| `stele-export-chain` | Off-host rotation chain export |
| `stele-watcher` | Standalone fork detector |
| `stele-loadgen` | Synthetic load generator |
| `stele-tamper` | DEMO ONLY — attacker tool |

### 8.2 Operator flags (most common)

```
--addr              HTTP listen address (default :8080)
--dir               data directory (required)
--origin            log identity, e.g. example.com/audit (required)
--init              first-time genesis (single use)
--require-enrollment refuse Append for unsigned producers
--pq-mode           classical | hybrid
--checkpoint-every  auto-checkpoint interval (default 30s)
--anchor-every      auto-anchor interval (default 30s)
--rotate-every      auto-rotation interval (default 0 = manual)
--watch-keys        rotate on key-dir modification (default true)
--watch-rate        rotate on rate anomaly (default false)
--tripwire-every    continuous integrity check (default 1h)
--read-log          tamper-evident read journal (default true)
--max-concurrent-appends server-wide cap (default 256)
--per-producer-rps  per-producer rate limit (default 100)
--per-admin-rps     admin endpoint rate limit (default 5)
--tls-cert / --tls-key   enable HTTPS
--client-ca         enable mTLS
--hsm-module        PKCS#11 module path (HSM mode)
--threshold-group   path to group.json (threshold mode)
--beacon            drand endpoint
--rekor             Sigstore Rekor endpoint
--otlp-endpoint     OpenTelemetry OTLP/HTTP for traces
```

### 8.3 HTTP API endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/v0/append` | POST | Submit an envelope |
| `/api/v0/entries/{idx}` | GET | Fetch one entry |
| `/api/v0/entries?from=X&to=Y` | GET | Range fetch |
| `/api/v0/size` | GET | Current size, root, head |
| `/api/v0/checkpoint` | GET/POST | Latest checkpoint / force new |
| `/api/v0/anchor` | POST | Force external anchor |
| `/api/v0/proof/inclusion?index=X&tree_size=N` | GET | Merkle inclusion proof |
| `/api/v0/proof/consistency?old=X&new=Y` | GET | Merkle consistency proof |
| `/api/v0/pubkey` | GET | Operator's chain pubkey |
| `/api/v0/keychain` | GET | Full rotation chain |
| `/api/v0/rotate` | POST | Manual key rotation (admin) |
| `/api/v0/producers` | GET/POST | List / register producer (legacy) |
| `/api/v0/enrollments/begin` | POST | Two-step enrollment, step 1 |
| `/api/v0/enrollments/confirm` | POST | Two-step enrollment, step 2 |
| `/api/v0/enrollments` | GET/POST | List / mint enrollment (legacy unilateral) |
| `/api/v0/producers/revoke` | POST | Revoke a producer |
| `/api/v0/witnesses` | GET/POST | List / register witness |
| `/api/v0/threshold-group` | GET | Active threshold group |
| `/api/v0/read-log/{size,events}` | GET | Read journal |
| `/api/v0/admin-log/{size,events}` | GET | Admin journal |
| `/healthz` | GET | Liveness |
| `/readyz` | GET | Readiness (probe-based) |
| `/metrics` | GET | Prometheus exposition |

### 8.4 File layout (operator)

```
/var/lib/stele/                  data root
├── db/                          BadgerDB (entries, checkpoints, anchors, producer registry)
├── keys/
│   ├── chain.json               rotation chain (NEVER lose this)
│   ├── root.pub                 published root pubkey
│   └── epoch-<n>.key            active epoch's private key (0o600)
├── read-log/
│   ├── journal.log              tamper-evident read journal
│   ├── journal.key              journal signing key
│   └── journal.pub
├── admin-log/
│   └── admin.log
└── anchors/
    └── anchor.log               file-sink external anchor
```

### 8.5 Metrics ([pkg/obs/metrics.go](pkg/obs/metrics.go))

| Metric | Type | Labels |
|---|---|---|
| `stele_appends_total` | counter | outcome |
| `stele_append_duration_seconds` | histogram | — |
| `stele_append_in_flight` | gauge | — |
| `stele_rotations_total` | counter | outcome |
| `stele_checkpoints_total` | counter | outcome |
| `stele_witness_cosign_total` | counter | witness, outcome |
| `stele_witness_cosign_duration_seconds` | histogram | witness |
| `stele_anchor_writes_total` | counter | sink, outcome |
| `stele_honeypots_total` | counter | — |
| `stele_watchdog_rotations_total` | counter | reason, outcome |
| `stele_active_epoch` | gauge | — |
| `stele_tree_size` | gauge | — |
| `stele_last_anchor_age_seconds` | gauge | — |
| `stele_witness_quorum_healthy` | gauge | — |
| `stele_build_info` | gauge | component, version, commit |
| `stele_tripwire_runs_total` | counter | outcome |
| `stele_ingest_rejects_total` | counter | endpoint, reason |
| `stele_admin_actions_total` | counter | action, outcome |

### 8.6 Platform support

See [PLATFORMS.md](PLATFORMS.md). Quick form:

- Pure-Go binaries cross-compile to linux / darwin / windows / freebsd × amd64 / arm64
- HSM (PKCS#11) requires `CGO_ENABLED=1` rebuild (not in default release binaries)
- `mlock` memory protection: Linux + macOS only (Windows + FreeBSD log a warning and proceed)
- systemd units: Linux only (other OSes use their native supervisor)

---

## 9. Troubleshooting

### Symptom: `/readyz` returns 503 indefinitely

```sh
curl -fsS http://localhost:8080/readyz
# {"ok":false,"probes":[{"name":"store","ok":false,"err":"..."}]}
```

The JSON tells you exactly which probe failed:
- `chain` failure: rotation chain missing/corrupt. See [RECOVERY.md §4](RECOVERY.md).
- `store` failure: BadgerDB can't open. Check disk space, file permissions, another `steled` process holding the lock.
- `not_draining` failure: SIGTERM in flight; graceful shutdown in progress.

### Symptom: Append returns 429 for a legitimate producer

Per-producer rate limit kicked in. Check the response's `Retry-After` header. Tune `--per-producer-rps` if real traffic exceeds 100 RPS sustained.

### Symptom: Append returns 503 with `Retry-After`

Server-wide concurrency cap reached. Either:
- Increase `--max-concurrent-appends` (if you have CPU/disk headroom)
- Investigate why handlers are slow (`stele_append_duration_seconds` p99 likely high — check disk I/O, fsync latency)

### Symptom: tripwire ticked `outcome="tamper"`

**CRITICAL**. Read [RECOVERY.md §7](RECOVERY.md) — "Detected tampering". Do NOT just re-checkpoint to "fix" the divergence; you'd be signing a forged root.

### Symptom: a witness's `outcome="error"` is climbing

The witness is unreachable or rejecting requests. Common causes:
- Network partition between operator and witness (run `stele-watcher` to confirm scope)
- The witness was put on a forked operator before — check witness's `/witness/v0/forks`
- TLS / mTLS misconfiguration

If 2+ witnesses are erroring, your quorum is broken; investigate immediately.

### Symptom: `stele audit` finds a checkpoint signature mismatch

The operator's chain key doesn't match the trust anchor you supplied. Either:
- The operator has been replaced (illegitimate substitution)
- You're using a stale root pubkey (the operator started a new log — should be communicated explicitly)

Either way, do NOT proceed to trust the log without an out-of-band explanation.

### Symptom: builds fail with `pkcs11.X undefined`

Cross-compiling with CGO disabled while trying to use HSM mode. Either:
- Build with `CGO_ENABLED=1` (requires a C toolchain on the build host)
- Or accept that HSM mode is unavailable on this binary; the rest of stele works fine without it.

### Symptom: `mlock` warning at startup

```
keyguard: failed to mlock key memory  err=operation not permitted
```

`ulimit -l` is too low. Fix one of:
- systemd unit: `LimitMEMLOCK=4M` (the bundled unit already has this)
- Container: grant `CAP_IPC_LOCK`
- Bare process: `ulimit -l 4096` before exec

Stele continues without mlock; reduced posture, not broken.

### Symptom: `stele-watcher` returns exit code 2

One or more sources unreachable. Check connectivity from the watcher host to each `--operator` and `--witnesses` URL. The `--json` report shows per-source status.

### Symptom: `helm install` fails with PVC pending

Cluster has no default StorageClass for `ReadWriteOnce`. Either:
- `--set operator.persistence.storageClass=<your-sc>` etc.
- Or `operator.persistence.enabled=false` for a stateless eval — DO NOT use stateless in production.

### Symptom: production image is 174 MB

Yes; that's the cost of bundling 9 Go binaries in one image. Each binary is ~25 MB statically-linked. Use single-purpose images if you want smaller — but each one is still ~25 MB.

---

## Where else to look

- [README.md](README.md) — the project at a glance
- [QUICKSTART.md](deploy/QUICKSTART.md) — 15-minute deployment paths
- [THREATMODEL.md](THREATMODEL.md) — what stele defends against, STRIDE-by-component
- [HARDENING.md](HARDENING.md) — the test surface; how to extend
- [RECOVERY.md](RECOVERY.md) — DR runbook
- [LOADTEST.md](LOADTEST.md) — load + chaos testing
- [PLATFORMS.md](PLATFORMS.md) — per-OS support matrix
- [STRENGTHENING.md](STRENGTHENING.md) — the (now mostly-completed) hardening roadmap
- [deploy/README.md](deploy/README.md) — Prometheus / Grafana / OTel deployment notes
- [chaos/README.md](chaos/README.md) — toxiproxy chaos rig
- [EXPLAINED.md](EXPLAINED.md) — the same content in non-technical language
- [ADOPTING.md](ADOPTING.md) — 90-day adopter playbook (pilot → prod → hand-off)
- [COMPLIANCE.md](COMPLIANCE.md) — SOC 2 / NIST 800-53 / ISO 27001 control mapping
- [sdk/python/README.md](sdk/python/README.md) — Python producer SDK
- [sdk/typescript/README.md](sdk/typescript/README.md) — TypeScript / browser producer SDK
