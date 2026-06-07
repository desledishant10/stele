# Soak run — currently in flight (v7 against v0.1.6)

A live 72-hour soak is running on AWS. This file exists so we don't
lose track of it across sessions. Delete it after the run completes
and the SOAK-72H.md report is updated.

## What's running

| Field | Value |
|---|---|
| Stele version | `v0.1.6` (per `soak/cloud-init.yaml`) |
| Provider | AWS EC2, us-east-1c |
| Instance ID | `i-0398511706564d52d` |
| Instance type | `c7i.xlarge` (4 vCPU / **8 GB RAM**, same as v4/v6 for apples-to-apples) |
| AMI | `ami-0021ac0c2e69d9c55` (Ubuntu 24.04 LTS) |
| Public IP | `107.21.13.141` |
| Security group | `sg-0cf01b26646fd1833` (SSH from `71.229.148.177/32` only) |
| Key pair | `stele-soak` (private at `~/.ssh/stele-soak.pem`) |
| Launched | 2026-06-07T04:23:04Z |
| Expected finish | 2026-06-10T04:23:04Z (72h target) |
| Estimated cost | ~$8 (72h × $0.103/h c7i.xlarge + ~$0.30 storage) |

## Why this run matters (different from v6)

v6 (v0.1.5) OOM'd at ~17h because:
1. `soak/stele-soak-setup` hard-coded `--max-concurrent-appends=512`,
   overriding v0.1.5's NumCPU×4 default
2. Workload was 16 producers × 500 RPS = 8K aggregate RPS, much
   higher than a realistic deployment

v0.1.6 fixes both:
1. Setup script no longer overrides the concurrency flag
2. Default workload is 4 producers × 250 RPS = 1K aggregate RPS

So this run tests the **complete** v0.1.5 fix package (GOMEMLIMIT +
real concurrency cap + BadgerDB tuning) at a **representative**
workload.

If it OOMs again, the diagnosis is fundamentally different from what
we've seen (per-entry steady-state growth still unbounded somewhere
we missed). If it cleanly hits 72h, the story is "single-node
operator handles a realistic Fortune-500-scale workload on a $50/mo
VM, indefinitely."

## Health checks

```sh
# SSH:
ssh -i ~/.ssh/stele-soak.pem ubuntu@107.21.13.141

# Concise health snapshot:
ssh -i ~/.ssh/stele-soak.pem ubuntu@107.21.13.141 \
    'echo "uptime: $(uptime)"; echo ---OOMs---; sudo dmesg | grep -c "Out of memory"; echo ---snapshots---; sudo wc -l /var/lib/stele-soak/timeline.ndjson 2>&1; echo ---RSS---; sudo cat /proc/$(pgrep -x steled | head -1)/status 2>/dev/null | grep -E "VmRSS|VmSize"'

# Live tail (Ctrl-C to exit):
ssh -i ~/.ssh/stele-soak.pem ubuntu@107.21.13.141 \
    'sudo tail -f /var/log/stele-soak.log /var/lib/stele-soak/timeline.ndjson'

# OOM watch (we want this empty):
ssh -i ~/.ssh/stele-soak.pem ubuntu@107.21.13.141 \
    'sudo dmesg | grep -i "out of memory" | tail'
```

## If your IP changes mid-run

```sh
MY_IP=$(curl -fsS https://checkip.amazonaws.com)
aws ec2 authorize-security-group-ingress \
    --group-id sg-0cf01b26646fd1833 \
    --protocol tcp --port 22 \
    --cidr "${MY_IP}/32"
```

## End-of-run procedure (2026-06-10 or later)

```sh
HOST=107.21.13.141
KEY=~/.ssh/stele-soak.pem
cd /Users/dishantdesle/Tools/stele

# 1. Pull data.
scp -i "$KEY" ubuntu@"$HOST":/var/lib/stele-soak/timeline.ndjson .
scp -i "$KEY" ubuntu@"$HOST":/var/lib/stele-soak/loadgen-final.json . 2>/dev/null || true

# 2. Generate report.
python3 soak/report.py timeline.ndjson loadgen-final.json > /tmp/soak-v7.md
head -40 /tmp/soak-v7.md

# 3. If clean → update SOAK-72H.md with the v7 section.
#    If OOM → save artifacts to soak/artifacts-v7/ and diagnose.

# 4. Teardown.
aws ec2 terminate-instances --instance-ids i-0398511706564d52d
aws ec2 wait instance-terminated --instance-ids i-0398511706564d52d
aws ec2 delete-security-group --group-id sg-0cf01b26646fd1833
```

## Abort early

```sh
# Pull data BEFORE terminating.
scp -i ~/.ssh/stele-soak.pem ubuntu@107.21.13.141:/var/lib/stele-soak/timeline.ndjson . || true
aws ec2 terminate-instances --instance-ids i-0398511706564d52d
```

## Expected RSS trajectory

At 250 RPS sustained, with GOMEMLIMIT=5.6 GB and concurrency=16,
RSS should:

- Climb to ~1 GB in the first hour as Merkle leaves accumulate
- Settle into 1-2 GB oscillation as the LRU cap evicts internal
  nodes and GC catches allocation bursts
- Never approach the 5.6 GB GOMEMLIMIT ceiling

If RSS climbs steadily past 3 GB without plateauing, something
else is unbounded. If RSS oscillates BUT inside the 5.6 GB ceiling,
GOMEMLIMIT is holding. If RSS hits 7 GB and OOMs, the GOMEMLIMIT
ceiling was insufficient for the new workload — much less likely
at 1K aggregate RPS but possible.

## What to expect each day

| Day | Expected | Red flags |
|---|---|---|
| 0-1h | cloud-init finishes; loadgen ramps; RSS ~500 MB-1 GB | RSS over 2 GB in first hour |
| 1-24h | Steady at ~250 RPS aggregate; RSS 1-2 GB; first rotation at 4h | RSS climbing not oscillating |
| 24-48h | Steady; 21M-43M entries accumulated | Any rotation failure |
| 48-72h | Steady; final hour | /readyz 503; tripwire fires |
| End | scp + report + terminate | OOM in dmesg |

A clean 72h validates v0.1.5 + v0.1.6 together. The story becomes
"protocol is sound; defaults converged after two rounds of soak
iteration; production-shape deployment of single-node operator at
realistic workload is empirically clean for 72 hours."
