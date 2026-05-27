# Stele Recovery Runbook

> **Read this before you need it.** When you actually have an incident,
> follow the relevant numbered section without thinking — the time you
> spend deliberating during an incident is the time the log goes
> unverifiable.

Stele has three independent assets that need to be backed up. Losing any
of them has a different blast radius, and the recovery procedure
differs. Memorise the difference.

| Asset | What it is | Lose it and... | Backed up by |
|---|---|---|---|
| **Entry database** | `<dir>/db/` (BadgerDB) | Every appended entry is gone | `stele-backup snapshot` |
| **Rotation chain** | `<dir>/keys/chain.json` + root pubkey | Auditors can no longer verify *anything* the log ever produced — even what they have local copies of | `stele-export-chain` |
| **Active key material** | `<dir>/keys/<epoch>.key` *or* HSM-resident | New entries can't be signed (existing entries unaffected) | HSM-internal backup *or* sealed copy *or* threshold quorum redundancy |

The chain is the *most precious*. The entries can sometimes be rebuilt
from the mirror; the chain can never be regenerated.

---

## 1. Standard operating cadence

| Cadence | Action | Why |
|---|---|---|
| At log inception | `stele-export-chain identity --format paper`. Print on paper, fold, seal in tamper-evident envelope, store in physical safe. | The minimal trust anchor an auditor needs. If everything else is destroyed, this single sheet recovers verifiability of any byte-copy of the log entries you ever produce. |
| After every key rotation | `stele-export-chain full --out chain-N.json`. Upload to S3 with Object Lock (or equivalent immutable storage). | The auditor needs the full chain to follow your root pubkey forward to the current epoch. |
| Hourly (cron / systemd timer) | One of: (a) pause steled, run `stele-backup snapshot --dir <log> --out -` → encrypted pipe → off-host storage, then resume; OR (b) take a filesystem snapshot (ZFS/LVM/btrfs/EBS) and run `stele-backup snapshot` against the read-only snapshot dir. Tune cadence to your RPO. | Entry database durability. BadgerDB holds an exclusive directory lock — option (b) is recommended for HA. |
| Daily | Validate the most recent snapshot is readable: pipe it back into `stele-backup restore --dir <scratch>`. | Detects backup corruption *before* an incident. |
| Quarterly | Full **recovery drill** (§3). Time the restore end to end and record. | A backup you have never restored is a backup you do not have. |

The default `--checkpoint-every` and `--anchor-every` of 30s push every
log update through Rekor + the local anchor file, so even if you lose
the entry database the *checkpoint* trail in Rekor proves the log
existed at every committed size. That's a fallback, not a substitute,
for `stele-backup`.

---

## 2. Scenario index

Jump to the section that matches your incident:

| Symptom | Section |
|---|---|
| `steled` won't start; "database corrupt" | §3 — Restore entry DB from snapshot |
| `chain.json` is missing or unreadable | §4 — Restore rotation chain |
| Lost the active signing key (file or HSM) | §5 — Lost active key, chain intact |
| HSM died / unreachable | §6 — HSM disaster |
| Tripwire fired (`stele_tripwire_runs_total{outcome="tamper"}` ticked) | §7 — Detected tampering |
| Operator host destroyed (fire, ransomware, etc.) | §8 — Total host loss |
| Auditor reports a different root than you have | §9 — Root divergence |

---

## 3. Restore entry DB from a snapshot

**Prereqs:** the most recent `stele-backup snapshot` blob, and the
`<dir>/keys/` directory either intact on disk or restored per §4.

```sh
# 1. Stop steled if running.
systemctl stop steled

# 2. Move the suspect db dir out of the way (don't delete yet —
#    you may need it for forensic analysis).
mv /var/lib/stele/db /var/lib/stele/db.suspect.$(date +%s)

# 3. Restore from the most recent good snapshot.
stele-backup restore --dir /var/lib/stele --in /backups/latest.bin

# 4. Verify the restore matches your last anchored checkpoint.
#    Stele's tripwire will run this automatically on first append,
#    but doing it explicitly is faster feedback.
stele audit --server "" --dir /var/lib/stele

# 5. Start steled.
systemctl start steled

# 6. Confirm /readyz returns 200 and tree_size matches your
#    expectation. Hit /metrics and check stele_tree_size.
curl -fsS http://localhost:8080/readyz
curl -fsS http://localhost:8080/metrics | grep stele_tree_size
```

**Expected time: 5–30 minutes** depending on log size (Badger restore
is O(N), roughly 100K entries/sec on commodity SSD).

---

## 4. Restore rotation chain

**Symptom:** `chain.json` is missing, truncated, or rejected by
`fwdsec` on startup (`fwdsec: load active key: ...`).

This is the most painful recovery. The chain is your trust anchor, so
the procedure depends on what you still have:

### 4.a — Off-host chain export available

```sh
# 1. Stop steled.
systemctl stop steled

# 2. Restore chain.json from your most recent `stele-export-chain full`.
cp /backups/chain-N.json /var/lib/stele/keys/chain.json
chown stele:stele /var/lib/stele/keys/chain.json
chmod 0600 /var/lib/stele/keys/chain.json

# 3. Re-stage the active epoch's private key. THIS DEPENDS ON YOUR
#    KEY STORAGE:
#      - File-backed: restore the key file referenced by chain.json's
#        active_locator (e.g. /var/lib/stele/keys/<epoch>.key). If you
#        do not have a backup, see §5.
#      - HSM-backed: the HSM still holds the key — nothing to do.
#      - Threshold: nothing to do at the operator level; the cosigners
#        hold the shares.

# 4. Start steled and confirm health.
systemctl start steled
curl -fsS http://localhost:8080/readyz
```

### 4.b — Only the paper identity export available

You have the genesis root pubkey on paper but no full chain export
from any post-genesis epoch.

This is a **partial recovery**. Auditors with the genesis root can
still verify entries signed by epoch 0, but anything signed by epoch
≥ 1 is unverifiable without the rotation cert that links epoch 0 to
its successor. Your options:

1. **Pull from a mirror.** Every mirror caches the full chain it
   pulled. If any mirror is still alive, `curl
   <mirror>/api/v0/keychain` and you have the chain back.
2. **Pull from a witness.** Witnesses store the operator chain they
   were registered with (per-origin). Same `curl` against any
   witness's `/witness/v0/keychain` endpoint.
3. **Pull from a Rekor entry.** Every checkpoint anchored to Rekor
   includes a copy of the chain at that epoch (in the inclusion proof
   payload). The most recent Rekor entry for your origin contains
   everything.

If all three sources are gone, you cannot recover. Plan §8 (rotate to
a new root + publish the discontinuity) is the only path.

---

## 5. Lost active key, chain intact

**Symptom:** `chain.json` is fine but the file `<dir>/keys/<epoch>.key`
is missing/corrupt OR the HSM rejects the active key handle.

The active key is the *signing* key, not the verification key. You
cannot recover the missing key bytes, but you do not need to — the
right move is to declare a new epoch.

```sh
# 1. Stop steled.
systemctl stop steled

# 2. If the key file is corrupt, move it aside.
mv /var/lib/stele/keys/<epoch>.key /var/lib/stele/keys/<epoch>.key.corrupt

# 3. Manually invoke a rotation. Because the active key is unusable,
#    rotation must be authorised by your DR procedure:
#      - Single-sig classical/hybrid: the active key is needed to sign
#        the rotation cert. If the key is destroyed, ROTATION IS
#        IMPOSSIBLE — see §8.
#      - HSM: see §6 if HSM is the issue.
#      - Threshold: the cosigners can sign a fresh rotation cert
#        WITHOUT the lost operator-side material. This is one of the
#        strongest reasons to run in threshold mode.

# 4. (Threshold mode) trigger an emergency rotation:
curl -fsS -X POST http://localhost:8080/api/v0/rotate
```

---

## 6. HSM disaster

**Symptom:** HSM unreachable, returns errors, or is destroyed.

Stele's PKCS#11 mode treats the HSM as the sole holder of the active
signing key (and, if hybrid, the Dilithium private). Loss of the HSM
is loss of the active key.

| HSM topology | Recovery |
|---|---|
| **Single HSM, no backup** | Active epoch is unsignable. If single-sig, go to §8. If threshold, cosigners can sign a rotation cert binding a *new* HSM into the chain (§6.a). |
| **HSM cluster (Thales Luna HA, AWS CloudHSM cluster)** | Survives one HSM failure transparently. No operator action required beyond updating PKCS#11 module paths in `--hsm-module`. |
| **Single HSM, encrypted-backup workflow** | Restore the backup blob into a fresh HSM following your vendor's wrap/unwrap procedure. The new HSM holds byte-identical key material; stele resumes. |

### 6.a — Cosigner-driven HSM swap

When the operator runs in `--threshold-group` mode AND the rotation
chain is configured for threshold rotation:

```sh
# 1. Provision a fresh HSM. Generate a new keypair *inside* it.
#    Capture the new public key.

# 2. Issue a rotation cert binding the new pubkey, signed by the
#    cosigner quorum (NOT by the old, lost HSM):
stele rotate-threshold \
    --new-pubkey ./new-hsm.pub \
    --cosigner alice.example.com:9101 \
    --cosigner bob.example.com:9101 \
    --cosigner carol.example.com:9101 \
    --threshold 2

# 3. Restart steled with --hsm-module pointed at the new HSM. The
#    chain.json now lists the new epoch; auditors with the old chain
#    can verify forward through the cosigner-signed rotation cert.
```

This is the only HSM-loss recovery that does not require declaring a
discontinuity (§8).

---

## 7. Detected tampering (tripwire fired)

**Symptom:** `stele_tripwire_runs_total{outcome="tamper"}` increased,
or the structured log contains `msg=TRIPWIRE FIRED`.

Stele has detected that one or more on-disk entries no longer match
the committed Merkle root. This is a high-severity signal: an attacker
with disk access, a corrupt backup-restore, a buggy ops script, or a
bit-flip storage event. Treat as compromise until proven otherwise.

```sh
# 1. STOP THE LINE. Refuse new appends until investigation is complete.
systemctl stop steled

# 2. Take a forensic snapshot of the entire data directory NOW. Do
#    not let any process write to it until you have this copy.
tar -C /var/lib -cf /forensic/stele-$(date +%s).tar stele/

# 3. From the tripwire log line, identify the first failing index.
#    The structured log will contain: first_failure_index=<N>.

# 4. Cross-check the failing entry against every available source:
#      - The most recent stele-backup snapshot (§3) — does the entry
#        match the snapshot?
#      - Any mirror — does the mirror's stored entry match the
#        operator's claimed entry?
#      - Rekor — fetch the inclusion proof for size > N; the proof
#        commits to the Merkle root over the historical leaves.
#
#    If the mirror or Rekor disagrees with the operator's local entry,
#    that's confirmation of operator-side tampering.

# 5. Decide:
#      - If the snapshot matches and is recent, restore (§3).
#      - If the tampering is more recent than the snapshot, escalate
#        per your incident response plan. The log is COMPROMISED until
#        the source of tamper is identified.
```

**Do NOT** simply re-checkpoint to "fix" the divergence. Doing so signs
a forged Merkle root and burns your auditor's trust permanently.

---

## 8. Total host loss

**Symptom:** the operator host is destroyed — disk, HSM, RAM, all gone.
You have your off-host backups (entry DB + chain) and your paper
identity export.

This is the recovery the paper export was made for.

```sh
# 1. Provision a fresh host.

# 2. Restore the chain from off-host backup.
mkdir -p /var/lib/stele/keys
cp /backups/chain-latest.json /var/lib/stele/keys/chain.json
chmod 0600 /var/lib/stele/keys/chain.json

# 3. Restore the entry DB.
stele-backup restore --dir /var/lib/stele --in /backups/db-latest.bin

# 4. (If applicable) restore HSM access:
#      - HSM cluster: PKCS#11 client config points at the cluster URL.
#      - HSM backup blob: restore into a fresh HSM per vendor docs.
#      - Threshold mode: nothing to do — cosigners hold the shares.
#      - Single classical with lost host-key: see §5; cannot recover
#        active key, must declare discontinuity (§8.a).

# 5. Start steled. /readyz must return 200 before serving traffic.
systemctl start steled
curl -fsS http://localhost:8080/readyz

# 6. Publish a recovery notice (out of band — email to known
#    auditors, status page) stating: "stele log at <origin> restored
#    from off-host backup as of <timestamp>; size at recovery is N;
#    chain root and digest unchanged."
```

### 8.a — Lost active key with no recovery path

If §5 / §6 / §8 above all fail and the active key cannot be
recovered, you must publish a **DISCONTINUITY** notice:

1. Generate a brand new operator keypair + a brand new chain.json.
2. Publish the OLD root pubkey + last anchored size + last anchored
   root as the "final state" of the old log, signed by you out of
   band (PGP, x509, whatever your org uses for high-stakes
   announcements).
3. Publish the NEW root pubkey as the start of a new log epoch.
4. Auditors with old artefacts can still verify them against the old
   root; new artefacts verify against the new root. There is no
   cryptographic continuity between the two.

This is the worst possible outcome short of silent compromise. The
goal of every other section is to make sure you never get here.

---

## 9. Root divergence

**Symptom:** an external party (auditor, mirror, witness) reports a
Merkle root for size N that does not match yours.

This is the classic split-brain signal. Stele's witness mesh exists
specifically to detect this — but if you got here without a witness
alert, the witnesses might be compromised too.

```sh
# 1. Capture both roots. Note size N. Note source of each.

# 2. Run stele audit from THREE independent vantage points:
#      - Locally on the operator host.
#      - From a mirror you trust.
#      - From the auditor's own machine.

# 3. Pull the inclusion proof at size N from Rekor. The Rekor entry's
#    root is the ground truth — it cannot be retroactively changed
#    without leaving a public trail in Rekor's own transparency log.

# 4. Whoever disagrees with the Rekor root is compromised or stale:
#      - If the operator disagrees with Rekor: the operator has been
#        forking. Treat as §7-level incident.
#      - If the auditor disagrees with Rekor: their local copy is
#        stale or modified.
#      - If multiple parties disagree with each other but not with
#        Rekor: a network MITM is rewriting in-flight responses.
```

---

## 10. The recovery drill (quarterly)

Once per quarter, on a scheduled date, execute end-to-end. This is the
only way to know your runbook works.

```sh
# On a scratch host that is NOT the production operator:

# 1. Fetch the most recent off-host snapshot + chain export.
aws s3 cp s3://stele-backups/db-latest.bin .
aws s3 cp s3://stele-backups/chain-latest.json .

# 2. Time the recovery, end to end.
START=$(date +%s)
mkdir -p ./drill/keys
cp chain-latest.json ./drill/keys/chain.json
stele-backup restore --dir ./drill --in db-latest.bin
stele audit --server "" --dir ./drill --root <pasted-from-paper>
END=$(date +%s)
echo "TTR: $((END - START))s"

# 3. Record in the drill log: date, TTR, anomalies, action items.
#    Compare against the previous quarter's number — TTR creeping up
#    over time is its own signal.
```

Drill logs live alongside the runbook. If a drill takes longer than
30 minutes, that's a finding worth a follow-up ticket.
