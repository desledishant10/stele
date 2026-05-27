# Adopting Stele

The "I'm convinced — how do I actually roll this out in my org"
guide. Written from the perspective of an engineer making the case
to their team + driving a 90-day rollout.

This is a sibling of [PLAYBOOK.md](PLAYBOOK.md) (operate stele) and
[QUICKSTART.md](deploy/QUICKSTART.md) (deploy in 15 minutes); the
goal here is the **human + organisational** path, not the technical
deploy.

---

## Before you start: is stele a fit?

A 60-second check:

| Question | If yes |
|---|---|
| Do you have a log that, if tampered with, would cause a real business / compliance / legal problem? | Stele is a candidate. |
| Does that log need to survive a malicious internal actor — including an SRE with root on the operator host? | Stele's threat model is built for this. |
| Do you need to *prove* (not just assert) to a third party that the log is intact? | This is stele's headline feature. |
| Do you generate fewer than a few million entries per day? | Stele is comfortably sized for this. |
| Are you OK with append-only — no deletions, no edits, ever? | Required. |

If any answer is "no," reach for a conventional logging stack
(Loki, Elastic, Splunk, etc.) instead.

---

## Phase 1 — Internal pilot (days 1-30)

### Goal

Run stele against one real internal log. Prove it works. Build
internal references.

### Pick the right pilot

Pick a log that has three properties:

1. **High value, low volume.** A log where every entry matters and
   you generate < 10K/day. Build pipeline events, deployment events,
   security alerts, change-management approvals all fit.
2. **One team owns it.** Cross-team logs are politically harder.
3. **Reading it isn't time-critical.** Initial deployment is best
   with the audit log as a *parallel* destination — production
   systems unaffected.

### Week 1: Stand it up

```sh
# On a real Linux VM (not your laptop — see PLATFORMS.md):
git clone https://github.com/desledishant10/stele && cd stele

# Deployment: pick from
#   docker run ghcr.io/desledishant10/stele:0.1.0 steled ...
#   helm install stele ./deploy/helm/stele/
#   sudo ./deploy/systemd/install.sh all
# Full commands in deploy/QUICKSTART.md.

# Print + seal the root pubkey BEFORE accepting any producer.
stele-export-chain identity --dir /var/lib/stele --format paper > root.txt
# Print this. Fold it. Lock it somewhere physical.
```

### Week 2: Wire your first producer

Pick the language your pilot service is written in:

- **Go**: import `github.com/desledishant10/stele/pkg/attest` and use `attest.NewSoftwareAttestor`.
- **Python**: `pip install stele-sdk`; use `stele.Producer(...).log(...)`. See [sdk/python](sdk/python).
- **TypeScript**: `npm install @stele/sdk`; use `new Producer(...).log(...)`. See [sdk/typescript](sdk/typescript).
- **Other languages**: build your envelope canonicalisation against [pkg/attest/attest.go: Envelope.Canonical](pkg/attest/attest.go) — the byte format is documented and tested cross-language.

### Week 3: Get one witness running

Stand up exactly one witness on independent infrastructure. Not the
same VM as the operator. Not the same cloud account if you can help
it. Register it with the operator. Confirm it's cosigning every
checkpoint.

```sh
# On the witness host:
stele-witness --addr :9090 --dir /var/lib/stele-witness --id witness-a

# Back on the operator:
stele witness-add --server http://operator:8080 \
    --id witness-a --url https://witness-a.example.com:9090
```

Check Prometheus: `stele_witness_cosign_total{witness="witness-a",outcome="ok"}` should be ticking.

### Week 4: Wire monitoring + write your own runbook

- Import [deploy/grafana/stele-overview.json](deploy/grafana/stele-overview.json) into your Grafana.
- Import [deploy/prometheus/alerts.yml](deploy/prometheus/alerts.yml) into your Alertmanager.
- Test one alert: stop the operator briefly and confirm your on-call gets paged.
- Read [RECOVERY.md](RECOVERY.md). Write *your* version of it — your contacts, your S3 bucket names, your DNS records.

**End of phase 1 deliverable**: a deck-able demo of "we logged 30 days of \<event type\> into stele, here's the audit PDF, here's the grafana dashboard, here's the cost ($X/month)."

---

## Phase 2 — Production rollout (days 31-60)

### Goal

Move from pilot to running production for one team. Get the
operational muscle in place.

### Topology decisions

| Choice | Pilot default | Production default |
|---|---|---|
| Witnesses | 1 | **3** (different cloud / region) |
| Mirror | none | **1**, served to auditors instead of the operator |
| Operator-key storage | file | **HSM** (YubiHSM 2 ~$650, or AWS CloudHSM, or Azure Key Vault Managed HSM) |
| Signing mode | classical Ed25519 | classical (or **hybrid PQ** if data must remain auditable for 10+ years) |
| `--require-enrollment` | off (easier first wiring) | **on** (refuses un-enrolled producers) |
| Rotation cadence | manual | **`--rotate-every=1h`** + watchdog on key dir |
| External anchor | none | **Sigstore Rekor** (`--rekor`) + drand beacon (`--beacon`) |
| Backup cadence | manual | **hourly** to off-host S3 + every-rotation chain export |

### Cutover plan

A safe cutover keeps the legacy logging in place while stele runs in
parallel. After two weeks of clean operation you delete the legacy
path.

1. Add stele as a *second* destination from every producer. Keep
   the old destination.
2. Two weeks pass. Compare entry counts daily.
3. If counts match, cut the old destination.
4. Run `stele audit --pdf` against your stele log. Archive the PDF.

### Compliance / procurement parallel track

Use [COMPLIANCE.md](COMPLIANCE.md) to answer the SOC 2 / NIST / ISO
questions your compliance team will ask. The mapping doc is
structured so you can copy-paste rows into your auditor's
spreadsheet.

### Quarterly DR drill

[RECOVERY.md §10](RECOVERY.md) — actually run the drill. Time how
long it takes to restore from backup. Record the time-to-recovery
(TTR) and track it across drills.

**End of phase 2 deliverable**: a written internal runbook (your
copy of RECOVERY.md), a recorded DR drill, and the first formally
archived audit PDF.

---

## Phase 3 — Hand-off + scale (days 61-90)

### Goal

Stele runs without you as the day-one expert. The team that uses it
also operates it.

### Hand-off checklist

- [ ] At least two engineers can run a manual rotation
- [ ] At least two engineers can restore from backup (have done so in a drill)
- [ ] Grafana dashboard + alerts are linked in your team's runbook
- [ ] Producers in every relevant language have their SDK integration documented
- [ ] The compliance team has the COMPLIANCE.md mapping
- [ ] An incident-response procedure for "tripwire fired" is written and known
- [ ] On-call rotation includes the stele operator
- [ ] Quarterly DR drill is on the team calendar
- [ ] The trust anchor (root pubkey) is in physical storage AND DNSSEC

### Scaling considerations

| Trigger | Action |
|---|---|
| Sustained > 5K appends/sec | Consider WAL-batched appends (deferred feature; see [STRENGTHENING.md](STRENGTHENING.md)) or sharding across multiple operators per-origin |
| > 100M entries in the log | Memory growth becomes noticeable; consider periodic checkpoint archival + truncation (manual procedure today) |
| > 1 region | Add witnesses + mirrors in each region. Operator still single-instance v1. |
| Compliance audit incoming | Start producing weekly `stele audit --pdf` reports + archiving for the auditor's evidence pack |
| Acquired / acquiring a company | Discontinuity announcement procedure per [RECOVERY.md §8.a](RECOVERY.md) if you're terminating an existing stele log |

### Adding a second producer team

Each new team:
1. Generates its own producer keypairs (one per service)
2. Enrolls each via two-step PoP ceremony
3. Wires the SDK into its services
4. Owns its own producer key rotation (90-day default validity)

The team that runs the *operator* stays the same. Producer teams
don't need any operator-side knowledge.

---

## When NOT to use stele

To save you time:

- **You want a high-throughput shipping pipeline** (> 50K events/sec sustained). Use Loki / Elastic. Stele is fail-safe (refuses to append rather than produce a wrong entry); it's tuned for correctness over throughput.
- **You want full-text search of log content**. Stele stores opaque bytes. Search is a downstream consumer's job.
- **The data MUST stay private from the operator**. Producers must encrypt before signing. Stele records signatures; it doesn't encrypt content.
- **You need a few-day retention then drop**. Stele is append-only. Truncation is possible but the merkle root keeps proving the truncated entries existed.

---

## Adopter case studies

(none yet — file a PR when you ship the first one!)

If you're an adopter, we'd love to know. Open a discussion at
https://github.com/desledishant10/stele/discussions with:

- What you log
- What size / shape of deployment
- What you wish was easier
- What you wish stele did that it doesn't

The honest gaps you surface go straight into [STRENGTHENING.md](STRENGTHENING.md).

---

## Frequently asked questions

### How much does this cost to run?

A standard production deployment (1 operator + 3 witnesses + 1 mirror) on cloud VMs runs around **$80-$150/month** at low traffic (~100 RPS sustained, < 10M entries). HSM adds $50-$200/month depending on the vendor.

### What's the SLA stele commits to?

Stele commits to **no integrity errors under normal operation**.
Availability is "best effort" — stele is fail-safe, so it refuses to
append rather than commit a bad entry. Plan your producer-side
retry queue accordingly.

### How long is the wire format stable?

The wire format + CLI flags freeze as compatibility surface at
v0.1.0 and are committed to be additive (new optional fields, never
removing existing ones) within the v0.x line. See
[CHANGELOG.md](CHANGELOG.md).

### What happens if you (stele) disappear?

The project is Apache 2.0; the threat model + protocol are
documented exhaustively. Anyone with the source can keep operating
their existing log; new releases would need a fork or
re-implementation.

### Can I run stele in air-gapped environments?

Yes. Disable `--rekor` and `--beacon`. Use file-only anchoring +
witnesses on independent hosts within your air gap. You lose the
"public ground truth" anchor; you keep every other defence.
