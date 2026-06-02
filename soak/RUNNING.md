# Soak run — currently in flight

This is the v0.1.4 re-soak that validates the issue #8 fix. Delete
this file (and remove the soak/artifacts/ snapshot) after the run
completes and the new SOAK-72H.md is committed.

## What's running

| Field | Value |
|---|---|
| Stele version | `v0.1.4` |
| Provider | AWS EC2, us-east-1a |
| Instance ID | `i-05d551da596a9b6bf` |
| Instance type | `c7i.xlarge` (4 vCPU, **8 GB RAM**) |
| AMI | `ami-0fbcf351e82d18381` (Ubuntu 24.04 LTS, dated 2026-05-29) |
| Public IP | `44.195.20.195` |
| Security group | `sg-069c97ac28fea23fa` (SSH from `71.229.148.177/32` only) |
| Key pair | `stele-soak` (private at `~/.ssh/stele-soak.pem`) |
| Launched | 2026-06-02T02:56:37Z |
| Expected finish | 2026-06-05T02:56:37Z |
| Estimated cost | ~$8 (72h × $0.103 + ~$0.30 storage) |

The instance is intentionally **larger** than the v0.1.3 attempt
(c7i.large, 4 GB) so that even if v0.1.4's memory fix is imperfect
we have headroom. The success criterion for closing #8 is "72 hours
clean with no OOM kills." If RSS stays well under 4 GB throughout
we know the fix works; if it climbs near 8 GB we know we still have
work to do.

## Health checks

```sh
ssh -i ~/.ssh/stele-soak.pem ubuntu@44.195.20.195

# Confirm soak driver alive:
ssh -i ~/.ssh/stele-soak.pem ubuntu@44.195.20.195 \
    'systemctl is-active stele-soak.service stele-soak-report.timer; \
     curl -fsS http://127.0.0.1:8080/api/v0/size; \
     sudo tail /var/lib/stele-soak/timeline.ndjson'

# Snapshot timeline grows by one line every 30 min.
```

## End-of-run procedure (2026-06-05 or later)

```sh
HOST=44.195.20.195
KEY=~/.ssh/stele-soak.pem

# 1. Pull the timeline + final loadgen JSON.
scp -i "$KEY" ubuntu@"$HOST":/var/lib/stele-soak/timeline.ndjson .
scp -i "$KEY" ubuntu@"$HOST":/var/lib/stele-soak/loadgen-final.json . 2>/dev/null || true

# 2. Build the report (overwrites SOAK-72H.md).
cd /Users/dishantdesle/Tools/stele
python3 soak/report.py timeline.ndjson loadgen-final.json > SOAK-72H.md

# 3. Tear down.
aws ec2 terminate-instances --instance-ids i-05d551da596a9b6bf
aws ec2 wait instance-terminated --instance-ids i-05d551da596a9b6bf
aws ec2 delete-security-group --group-id sg-069c97ac28fea23fa

# 4. Commit + close #8.
git add SOAK-72H.md && git commit -m "soak: clean 72h run against v0.1.4 - closes #8"
git push
gh issue close 8 -c "Validated: clean 72h run, see SOAK-72H.md"
```

## Abort early

```sh
aws ec2 terminate-instances --instance-ids i-05d551da596a9b6bf
aws ec2 delete-security-group --group-id sg-069c97ac28fea23fa
```

## Notes

- This is the **second** soak attempt against the same protocol.
  The first (v0.1.3 on c7i.large, 4 GB) OOM'd at ~17 h after the
  operator's RSS reached ~3.4 GB. The v0.1.4 fix caps that
  with documented small-host defaults (`--merkle-cache-nodes`,
  `--badger-block-cache-mb`, `--badger-index-cache-mb`,
  `--badger-memtables`, `--replay-ttl`).
- The cloud-init script doesn't pass any of those flags
  explicitly; it relies on the v0.1.4 defaults. If a future soak
  wants to test specific tunings, edit `soak/stele-soak-setup`
  to add the flags to the `steled` invocation.
