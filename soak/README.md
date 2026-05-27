# 72-hour Soak Orchestration

Everything needed to run an unattended 72-hour soak on a real Linux
VM and turn the output into a committable SOAK-72H.md.

## What this directory contains

| File | Purpose |
|---|---|
| [`cloud-init.yaml`](cloud-init.yaml) | cloud-init config for an Ubuntu / Debian VM; installs stele, Prometheus, sets up the soak driver via systemd |
| [`stele-soak-setup`](stele-soak-setup) | First-boot script: provisions steled + 3 witnesses, registers them, enrolls a producer |
| [`stele-soak-run`](stele-soak-run) | Kicks off the long-running loadgen |
| [`stele-soak-snapshot`](stele-soak-snapshot) | Captures a metric snapshot every 30 minutes (cron-style) |
| [`report.py`](report.py) | Turns the snapshot timeline + final loadgen output into a Markdown report |

The whole soak is **unattended**. You provision the VM, walk away,
come back in three days, scp the timeline + loadgen json, run
`report.py`, commit the result.

## Quick start — AWS

```sh
aws ec2 run-instances \
    --instance-type c7i.large \
    --image-id ami-0e95a5e2743ec9ec9 \  # Ubuntu 24.04 LTS in us-east-1
    --key-name $YOUR_KEY \
    --user-data file://soak/cloud-init.yaml \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=100,VolumeType=gp3}' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=stele-soak-72h}]'
```

After ~3 minutes:

- `steled` + 3 witnesses are running and registered with each other
- A producer is enrolled
- `stele-loadgen` is driving 500 RPS at 256B payloads
- Prometheus is scraping every 15s
- A 30-minute snapshot timer is recording soak/timeline.ndjson

72 hours later:

```sh
# Pull artifacts back.
scp -i $YOUR_KEY ubuntu@$VM_IP:/var/lib/stele-soak/timeline.ndjson .
scp -i $YOUR_KEY ubuntu@$VM_IP:/var/lib/stele-soak/loadgen-final.json .

# Generate the report.
python3 soak/report.py timeline.ndjson loadgen-final.json > SOAK-72H.md

# Sanity check before committing.
head -40 SOAK-72H.md

# Tear down the VM.
aws ec2 terminate-instances --instance-ids $INSTANCE_ID
```

Cost on AWS c7i.large for 72 hours: roughly **$6**.

## Quick start — GCE

```sh
gcloud compute instances create stele-soak-72h \
    --machine-type=e2-standard-2 \
    --image-family=ubuntu-2404-lts \
    --image-project=ubuntu-os-cloud \
    --metadata-from-file=user-data=soak/cloud-init.yaml \
    --boot-disk-size=100GB \
    --boot-disk-type=pd-balanced \
    --zone=us-central1-a
```

## Quick start — Hetzner / Linode / DigitalOcean / OVH

Anywhere with cloud-init support, paste `cloud-init.yaml` as the
user-data and you're done. Roughly $4-$8 for a 72-hour run on
commodity providers.

## Defaults you can tune

In [`cloud-init.yaml`](cloud-init.yaml), the `/etc/stele/soak.env`
file is written with these tunables:

```sh
STELE_VERSION=v0.1.1
STELE_ORIGIN=soak.local/log
SOAK_DURATION=72h
SOAK_RPS=500
SOAK_PRODUCERS=16
SOAK_PAYLOAD=256
SOAK_REPORT_DIR=/var/lib/stele-soak
```

Override these before launching to vary the workload (e.g.
`SOAK_RPS=2000` for a stress run, `SOAK_DURATION=24h` for a shorter
sanity).

## What the report tells you

Run `report.py` against the timeline + final loadgen JSON. Output:

- Headline counts: appends accepted, error rate, tripwire trips,
  honeypot triggers, rotations, achieved RPS
- Stability signals: did `/readyz` ever drop to 503? when?
- Memory growth: every 30-minute snapshot's RSS, in a chronological
  table
- Loadgen p50 / p99 / p99.9 latency at the end of the run

A clean soak has:
- 0 tripwire trips
- 0 honeypot triggers
- 0 errors (or, if errors, they're explained by witness chaos)
- `/readyz` 200 in every snapshot
- Memory growth tracking the entry-count growth (predictable, not
  super-linear)

A finding (e.g. memory grew super-linearly, p99 climbed steadily,
witness mesh degraded) goes straight into a follow-up CHANGELOG line
+ a fix branch.

## What this does NOT cover

- **No chaos injection during the soak.** This is a pure-soak; for
  "soak + chaos" combine the loadgen here with toxiproxy from the
  chaos rig. See [chaos/README.md](../chaos/README.md).
- **No real HSM.** Production should swap `--hsm-module` in once you
  have the hardware. The protocol path is the same; only the signing
  RPS ceiling changes.
- **Single-host only.** Multi-region soak needs more orchestration
  than cloud-init can express. Run multiple VMs in different regions
  with cross-witness gossip wired between them.

## Maintaining

When wire formats / metrics change, refresh:

1. `METRICS_TO_PARSE` in `report.py` if a metric was added that
   matters for the soak signal.
2. The flag set in `stele-soak-setup` if a flag changed semantics.
3. The systemd unit text in cloud-init.yaml if the bundled hardening
   defaults shift.

Commit the refreshed files; the next launched VM picks them up
automatically.
