# Soak run — currently in flight

A live 72-hour soak is running on AWS. This file exists so we don't
lose track of it across sessions. Delete it after the run completes
and the SOAK-72H.md report is updated.

## What's running

| Field | Value |
|---|---|
| Stele version | `v0.1.5` (per `soak/cloud-init.yaml`) |
| Provider | AWS EC2, us-east-1a |
| Instance ID | `i-059dbc11b0c5ae3ec` |
| Instance type | `c7i.xlarge` (4 vCPU / **8 GB RAM**, same as v4 for apples-to-apples) |
| AMI | `ami-0021ac0c2e69d9c55` (Ubuntu 24.04 LTS, dated 2026-06-04) |
| Public IP | `44.202.183.70` |
| Security group | `sg-0c5aa8f04500ff6ab` (SSH from `71.229.148.177/32` only) |
| Key pair | `stele-soak` (private at `~/.ssh/stele-soak.pem`) |
| Launched | 2026-06-06T01:36:12Z |
| Expected finish | 2026-06-09T01:36:12Z (72h target) |
| Estimated cost | ~$8 (72h × $0.103/h c7i.xlarge + ~$0.30 storage) |

## Why this run matters

v0.1.4 was the first "the leaks are capped" release. It still OOM'd
on this exact instance type because Go's GC couldn't keep up with
allocation bursts. v0.1.5 ships three fixes:

- Auto-`GOMEMLIMIT` to 70% of host RAM (5.6 GB on 8 GB host)
- `MaxConcurrentAppends` default lowered from 256 to NumCPU × 4 = 16
- BadgerDB compactor count + vlog size reduced

If v0.1.5 clean-runs 72h on c7i.xlarge where v0.1.4 OOM'd at 3h,
that's strong evidence the burst-tolerance diagnosis was correct
and the fix sufficient.

## Caveat: concurrency override

Discovered post-launch: the `stele-soak-setup` script hard-codes
`--max-concurrent-appends=512` (and `--per-producer-rps=200 -burst=400`)
on the operator's systemd unit. This OVERRIDES the new v0.1.5 default
of NumCPU × 4 = 16. So of v0.1.5's three changes, only two are
actually active on this run:

| v0.1.5 change | Active in this soak? |
|---|---|
| Auto-`GOMEMLIMIT` to 70% of host RAM (5.6 GB) | YES (no flag override) |
| Lower `MaxConcurrentAppends` default | NO (script forces 512) |
| Lower BadgerDB compactor count + vlog size | YES (no flag override) |

This is actually a stronger test in one sense: if GOMEMLIMIT alone
holds the line even with concurrency=512, that's the most important
finding. v0.1.6 should fix the soak setup script to either drop the
override or set v0.1.5-tuned values.

Indirect verification that GOMEMLIMIT IS being set:
- Process VmRSS at t=4min is 310 MB
- 23,787 entries already logged
- If GOMEMLIMIT is NOT being applied, RSS will climb past 5.6 GB
  within a few hours and OOM (like v4 did)
- If RSS stays under ~5.6 GB throughout the run, GOMEMLIMIT is
  doing its job

## Health checks

```sh
# SSH in any time:
ssh -i ~/.ssh/stele-soak.pem ubuntu@44.202.183.70

# Confirm the soak driver is alive:
ssh -i ~/.ssh/stele-soak.pem ubuntu@44.202.183.70 \
    'systemctl status stele-soak stele-soak-operator stele-soak-witness-a stele-soak-witness-b stele-soak-witness-c stele-soak-report.timer 2>&1 | head -50'

# Live tail of cloud-init progress (during the first 3 min):
ssh -i ~/.ssh/stele-soak.pem ubuntu@44.202.183.70 \
    'sudo tail -f /var/log/cloud-init-output.log'

# Snapshot timeline (grows by one line every 30 min):
ssh -i ~/.ssh/stele-soak.pem ubuntu@44.202.183.70 \
    'sudo tail /var/lib/stele-soak/timeline.ndjson'

# OOM watch (this is what we're hoping NOT to see):
ssh -i ~/.ssh/stele-soak.pem ubuntu@44.202.183.70 \
    'sudo dmesg | grep -i "out of memory" | tail'
```

## If your IP changes mid-run

The SG only allows SSH from `71.229.148.177/32`. If your home/work IP
rotates, SSH will time out. Recover with:

```sh
MY_IP=$(curl -fsS https://checkip.amazonaws.com)
aws ec2 authorize-security-group-ingress \
    --group-id sg-0c5aa8f04500ff6ab \
    --protocol tcp --port 22 \
    --cidr "${MY_IP}/32"
```

## End-of-run procedure (2026-06-09 or later)

```sh
HOST=44.202.183.70
KEY=~/.ssh/stele-soak.pem
cd /Users/dishantdesle/Tools/stele

# 1. Pull the timeline + final loadgen JSON.
scp -i "$KEY" ubuntu@"$HOST":/var/lib/stele-soak/timeline.ndjson .
scp -i "$KEY" ubuntu@"$HOST":/var/lib/stele-soak/loadgen-final.json . 2>/dev/null || true

# 2. Build the report.
python3 soak/report.py timeline.ndjson loadgen-final.json > /tmp/soak-v6.md
head -40 /tmp/soak-v6.md

# 3. If the run was clean, SOAK-72H.md gets a fourth section
#    appended (v0.1.5 results). If it OOM'd, the partial-run pattern
#    from earlier rounds applies.

# 4. Tear down.
aws ec2 terminate-instances --instance-ids i-059dbc11b0c5ae3ec
aws ec2 wait instance-terminated --instance-ids i-059dbc11b0c5ae3ec
aws ec2 delete-security-group --group-id sg-0c5aa8f04500ff6ab
```

## Abort early

```sh
# Pull whatever data exists first, THEN terminate.
scp -i ~/.ssh/stele-soak.pem ubuntu@44.202.183.70:/var/lib/stele-soak/timeline.ndjson . || true
aws ec2 terminate-instances --instance-ids i-059dbc11b0c5ae3ec
```

## What to expect each day

| Day | Expected | Red flags |
|---|---|---|
| 0-4h | cloud-init finishes (~3 min); loadgen ramps to ~250 RPS; RSS settles around 500-1500 MB | RSS climbs past 4 GB → GOMEMLIMIT not effective |
| 4-24h | Steady-state at ~250 RPS; RSS oscillating 1-3 GB inside the GOMEMLIMIT ceiling; ~21M entries by 24h | RSS hits 5.6 GB regularly → GOMEMLIMIT being respected but at edge |
| 24-48h | More of the same; first rotation event around 24h | Any rotation failure |
| 48-72h | Steady continuation | `/readyz` 503; tripwire fires |
| End | scp + report + terminate | Crash-loop in the system journal |

A clean v0.1.5 run validates the burst-tolerance fix and closes
issue #8 empirically (it's already closed in the issue tracker; this
would be the receipts).
