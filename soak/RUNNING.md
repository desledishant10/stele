# Soak run — currently in flight

A live 72-hour soak is running on AWS. Delete this file after the
report is committed.

## What's running

| Field | Value |
|---|---|
| Stele version | `v0.1.3` |
| Provider | AWS EC2, us-east-1 |
| Instance ID | `i-0c11cd5346b1e2c0a` (v4 — see history below) |
| Instance type | `c7i.large` |
| AMI | `ami-0fc0d6e8d70ab2d42` (Ubuntu 24.04 LTS) |
| Public IP | `54.160.151.63` |
| Security group | `sg-0a07d09c67c85be2d` (SSH from `71.229.148.177/32`) |
| Key pair | `stele-soak` (private at `~/.ssh/stele-soak.pem`) |
| Setup completed | 2026-05-30T18:42:38Z |
| Loadgen started | 2026-05-30T18:42:38Z |
| Expected finish | 2026-06-02T18:42:38Z |
| Soak parameters | `duration=72h rps=500 producers=16 payload=256` |
| Estimated cost | ~$6.50 (72h × $0.0851 + ~$0.30 storage) |

## Launch history (for the record)

| Attempt | Instance | Outcome |
|---|---|---|
| v1 | `i-0bcfd7d3c38df6567` | terminated — cloud-init.yaml was missing `#cloud-config` magic header on line 1 |
| v2 | `i-0e761246e3851151c` | terminated — same root cause (script changes hadn't propagated) |
| v3 | `i-0d13cf07f12ce2048` | terminated — `stele-soak.service` failed because `/tmp/stele-soak-setup` didn't exist (cloud-init referenced it but never wrote it) |
| **v4** | `i-0c11cd5346b1e2c0a` | **running** — fixed in commit 36cd9b8: fetch soak driver scripts from raw.githubusercontent.com/desledishant10/stele/v0.1.3/ |

## Health checks

```sh
# SSH in any time:
ssh -i ~/.ssh/stele-soak.pem ubuntu@54.160.151.63

# Confirm everything is alive (from the host):
ssh -i ~/.ssh/stele-soak.pem ubuntu@54.160.151.63 \
    'systemctl is-active stele-soak.service stele-soak-operator.service stele-soak-witness-a.service stele-soak-witness-b.service stele-soak-witness-c.service stele-soak-report.timer'

# Current log size + root:
ssh -i ~/.ssh/stele-soak.pem ubuntu@54.160.151.63 \
    'curl -fsS http://127.0.0.1:8080/api/v0/size'

# Loadgen + operator logs:
ssh -i ~/.ssh/stele-soak.pem ubuntu@54.160.151.63 \
    'sudo tail /var/log/stele-soak.log /var/log/stele-soak-loadgen.log /var/log/stele-operator.log'

# Snapshot timeline (one new line every 30 min):
ssh -i ~/.ssh/stele-soak.pem ubuntu@54.160.151.63 \
    'sudo wc -l /var/lib/stele-soak/timeline.ndjson; sudo tail -1 /var/lib/stele-soak/timeline.ndjson | jq .'
```

## End-of-run procedure (after 2026-06-02T18:42Z)

```sh
HOST=54.160.151.63
KEY=~/.ssh/stele-soak.pem

# 1. Pull the timeline + final loadgen JSON.
scp -i "$KEY" ubuntu@"$HOST":/var/lib/stele-soak/timeline.ndjson .
scp -i "$KEY" ubuntu@"$HOST":/var/lib/stele-soak/loadgen-final.json .

# 2. Generate the report.
cd /Users/dishantdesle/Tools/stele
python3 soak/report.py timeline.ndjson loadgen-final.json > SOAK-72H.md
head -40 SOAK-72H.md

# 3. Tear down.
aws ec2 terminate-instances --instance-ids i-0c11cd5346b1e2c0a
aws ec2 wait instance-terminated --instance-ids i-0c11cd5346b1e2c0a
aws ec2 delete-security-group --group-id sg-0a07d09c67c85be2d

# 4. (Optional) clean up IAM user + key pair.
aws ec2 delete-key-pair --key-name stele-soak
aws iam list-attached-user-policies --user-name stele-soak \
    --query 'AttachedPolicies[].PolicyArn' --output text \
    | xargs -n1 -I{} aws iam detach-user-policy --user-name stele-soak --policy-arn {}
aws iam list-access-keys --user-name stele-soak \
    --query 'AccessKeyMetadata[].AccessKeyId' --output text \
    | xargs -n1 -I{} aws iam delete-access-key --user-name stele-soak --access-key-id {}
aws iam delete-user --user-name stele-soak

# 5. Commit + clean up bookkeeping.
git add SOAK-72H.md
git commit -m "soak: 72h run against v0.1.3 - see SOAK-72H.md"
rm soak/RUNNING.md
git add -u soak/RUNNING.md
git commit -m "soak: clear RUNNING.md after report committed"
git push
```

## Abort early

```sh
aws ec2 terminate-instances --instance-ids i-0c11cd5346b1e2c0a
# (scp timeline.ndjson + loadgen-final.json BEFORE terminating if you
#  want the partial data.)
```
