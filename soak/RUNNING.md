# Soak run — currently in flight

A live 72-hour soak is running on AWS. This file exists so we don't
lose track of it across sessions. Delete it after the run completes
and the SOAK-72H.md report is committed.

## What's running

| Field | Value |
|---|---|
| Stele version | `v0.1.2` (per `soak/cloud-init.yaml`) |
| Provider | AWS EC2, us-east-1d |
| Instance ID | `i-0d13cf07f12ce2048` |
| Instance type | `c7i.large` |
| AMI | `ami-0fc0d6e8d70ab2d42` (Ubuntu 24.04 LTS, dated 2026-05-15) |
| Public IP | `3.93.190.196` |
| Security group | `sg-0a07d09c67c85be2d` (SSH from `71.229.148.177/32` only) |
| Key pair | `stele-soak` (private at `~/.ssh/stele-soak.pem`) |
| Instance launched | 2026-05-27T05:30:00Z (approx) |
| Loadgen started | 2026-05-27T05:52:06Z |
| Expected loadgen finish | 2026-05-30T05:52:06Z |
| Notes | (1) First two instance launches (`i-0bcfd7d3c38df6567`, `i-0e761246e3851151c`) terminated during cloud-init debug. (2) Live VM needed three follow-up fixes after launch: scripts didn't ship via write_files, witness ports collided with Prometheus on `:9090`, and the operator's default admin rate limit blocked enrolling 16 producers in burst. All three are now fixed in soak/ and committed; the live VM has the fixed scripts. |
| Estimated cost | ~$6.50 (72h × $0.0851 + ~$0.30 storage) |

## Health checks

```sh
# SSH in any time:
ssh -i ~/.ssh/stele-soak.pem ubuntu@3.93.190.196

# Confirm the soak driver is alive (from the host):
ssh -i ~/.ssh/stele-soak.pem ubuntu@3.93.190.196 \
    'systemctl status stele-loadgen stele-soak-snapshot.timer steled stele-witness 2>&1 | head -40'

# Live tail of cloud-init progress (during the first 3 min after launch):
ssh -i ~/.ssh/stele-soak.pem ubuntu@3.93.190.196 \
    'sudo tail -f /var/log/cloud-init-output.log'

# Snapshot timeline (grows by one line every 30 min):
ssh -i ~/.ssh/stele-soak.pem ubuntu@3.93.190.196 \
    'sudo tail /var/lib/stele-soak/timeline.ndjson'
```

## End-of-run procedure (2026-05-30 or later)

```sh
HOST=3.93.190.196
KEY=~/.ssh/stele-soak.pem

# 1. Pull the timeline + final loadgen JSON.
scp -i "$KEY" ubuntu@"$HOST":/var/lib/stele-soak/timeline.ndjson .
scp -i "$KEY" ubuntu@"$HOST":/var/lib/stele-soak/loadgen-final.json .

# 2. Build the report (commits as SOAK-72H.md at the repo root).
cd /Users/dishantdesle/Tools/stele
python3 soak/report.py timeline.ndjson loadgen-final.json > SOAK-72H.md
head -40 SOAK-72H.md   # sanity check

# 3. Tear down the VM (and the security group + everything else).
aws ec2 terminate-instances --instance-ids i-0d13cf07f12ce2048
aws ec2 wait instance-terminated --instance-ids i-0d13cf07f12ce2048
aws ec2 delete-security-group --group-id sg-0a07d09c67c85be2d

# 4. (Optional) delete the IAM user + key pair if you want a clean slate.
aws ec2 delete-key-pair --key-name stele-soak
aws iam list-attached-user-policies --user-name stele-soak \
    --query 'AttachedPolicies[].PolicyArn' --output text \
    | xargs -n1 -I{} aws iam detach-user-policy --user-name stele-soak --policy-arn {}
aws iam list-access-keys --user-name stele-soak \
    --query 'AccessKeyMetadata[].AccessKeyId' --output text \
    | xargs -n1 -I{} aws iam delete-access-key --user-name stele-soak --access-key-id {}
aws iam delete-user --user-name stele-soak

# 5. Commit SOAK-72H.md.
git add SOAK-72H.md
git commit -m "soak: 72h run against v0.1.2 — see SOAK-72H.md"
git push
rm soak/RUNNING.md
git add -u soak/RUNNING.md
git commit -m "soak: clear RUNNING.md after report committed"
git push
```

## Abort early (if something looks bad)

```sh
# Terminate before the 72 hours are up (instance-storage gp3 still costs
# pro-rata until terminated). The VM's data is lost on termination.
aws ec2 terminate-instances --instance-ids i-0d13cf07f12ce2048

# If you want the partial timeline first, scp it BEFORE terminating.
```

## What to expect each day

- **Day 1**: cloud-init finishes (~3 min). Loadgen ramps up to 500 RPS. Snapshots start landing in `timeline.ndjson` every 30 min.
- **Day 2**: ~24h of clean appends. Memory should be tracking entry-count growth predictably. `/readyz` 200 in every snapshot.
- **Day 3**: ~48h. Look for any super-linear memory creep or p99 climb.
- **End of day 3**: scp + report + terminate. Result either lands as `SOAK-72H.md` (clean) or as a CHANGELOG line referencing the finding (if something interesting fired).
