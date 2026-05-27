# Stele — 15-minute deployment quickstart

Three paths, listed by what your environment already has. Pick one.

| Path | Best for | Time to first append |
|---|---|---|
| [Docker](#1-docker) | Single host, dev/eval | ~2 min |
| [Helm](#2-helm) | Existing k8s cluster | ~5 min |
| [systemd](#3-systemd) | Bare metal / VMs, no container runtime | ~10 min |

All paths assume the operator + 3 witnesses + 1 mirror topology that
THREATMODEL.md treats as the standard production shape.

---

## 1. Docker

```sh
docker pull ghcr.io/desledishant10/stele:latest

# operator
docker run -d --name stele-operator \
    -p 8080:8080 \
    -v stele-data:/var/lib/stele \
    ghcr.io/desledishant10/stele:latest \
    steled --addr :8080 --dir /var/lib/stele --init \
           --origin local.test/log --require-enrollment \
           --checkpoint-every 30s --anchor-every 30s \
           --watch-keys=false --beacon=

# witnesses (run on independent hosts in production)
for w in a b c; do
    docker run -d --name stele-witness-$w \
        -p 909$([ "$w" = "a" ] && echo 0 || ([ "$w" = "b" ] && echo 1 || echo 2)):9090 \
        -v stele-witness-$w:/var/lib/stele \
        ghcr.io/desledishant10/stele:latest \
        stele-witness --addr :9090 --dir /var/lib/stele --id witness-$w
done

# mirror (optional; auditors hit this instead of the operator)
docker run -d --name stele-mirror \
    -p 8444:8444 \
    -v stele-mirror:/var/lib/stele \
    --link stele-operator \
    ghcr.io/desledishant10/stele:latest \
    stele-mirror --addr :8444 --dir /var/lib/stele \
                 --upstream http://stele-operator:8080
```

Verify with the operator's local `stele` client:

```sh
alias stele='docker run --rm --link stele-operator ghcr.io/desledishant10/stele:latest stele --server http://stele-operator:8080'

stele producer-init --id alice --out /tmp/alice.priv
stele enroll-producer --id alice --key /tmp/alice.priv --scope "logs:audit"
stele log --producer alice --key /tmp/alice.priv --source "test" "first entry"
stele size
```

Trade-offs: single-host topology means a failure of that host takes
the whole stack down. Use **Helm** or **systemd** with witnesses on
independent infrastructure for anything beyond eval.

---

## 2. Helm

Requirements: a Kubernetes cluster (1.27+), `kubectl`, `helm` (3.x or
4.x), and a `StorageClass` capable of `ReadWriteOnce` PVCs.

```sh
# Render with defaults to see what will be applied.
helm template stele ./deploy/helm/stele/ | less

# Install — opinionated defaults: 1 operator, 3 witnesses, 1 mirror.
helm install stele ./deploy/helm/stele/ \
    --namespace stele \
    --create-namespace \
    --set operator.origin=my-company.io/audit \
    --set operator.requireEnrollment=true
```

Watch the rollout:

```sh
kubectl -n stele get pods -w
# When everything is Running:
kubectl -n stele port-forward svc/stele-stele-operator 8080:8080 &
curl -fsS http://localhost:8080/readyz
```

Production options worth setting via `--values your-overrides.yaml`:

| Option | Why |
|---|---|
| `image.tag: v0.1.0` | Pin to a tagged release (default = chart appVersion) |
| `operator.pqMode: hybrid` | Ed25519 + Dilithium3 across every signature site |
| `operator.tls.enabled: true` | Required for mTLS — see `operator.tls.*` |
| `operator.beacon.endpoint: ...` | drand beacon for clock-skew defence |
| `operator.rekor.endpoint: ...` | Sigstore Rekor anchoring |
| `serviceMonitor.enabled: true` | If you run prometheus-operator |
| `networkPolicy.enabled: true` | Default-deny + explicit allow list |
| `cosigners.enabled: true` | Switch to t-of-N threshold mode |

The chart deploys witnesses as a 3-replica StatefulSet with a
`topologySpreadConstraint` so they land on different nodes — the
whole point of a witness mesh is independent failure domains.

After install, register the witnesses with the operator:

```sh
for i in 0 1 2; do
    POD=stele-stele-witness-$i
    kubectl -n stele exec deploy/stele-stele-operator -- \
        stele witness-add \
            --server http://stele-stele-operator:8080 \
            --id $POD \
            --url http://${POD}.stele-stele-witness:9090
done
```

---

## 3. systemd

For a single VM / bare-metal host without Docker. Run as root.

```sh
# 1. Get the binaries.
# Option A: download a signed release.
curl -fsSL -o /tmp/steled https://github.com/desledishant10/stele/releases/download/v0.1.0/steled-linux-amd64
# (verify with cosign — see HARDENING.md)
install -m 0755 /tmp/steled /usr/local/bin/
# Repeat for stele, stele-witness, stele-mirror.

# Option B: build from source.
git clone https://github.com/desledishant10/stele && cd stele
go build -o /usr/local/bin/steled ./cmd/steled
# Repeat for the other binaries.

# 2. Install systemd units + env templates.
sudo ./deploy/systemd/install.sh all

# 3. Edit config.
sudoedit /etc/stele/steled.env       # set STELE_ORIGIN, flags
sudoedit /etc/stele/witness.env      # set STELE_WITNESS_ID
sudoedit /etc/stele/mirror.env       # set STELE_MIRROR_UPSTREAM

# 4. Start.
systemctl enable --now steled
systemctl enable --now stele-witness
systemctl enable --now stele-mirror

# 5. Check.
systemctl status steled
journalctl -u steled -f -o json
curl -fsS http://localhost:8080/readyz
```

`install.sh` is idempotent — re-run it to refresh the unit files
without touching the env files.

The shipped units include systemd hardening that matches what the
threat model expects (NoNewPrivileges, ProtectSystem=strict,
MemoryDenyWriteExecute, SystemCallFilter, CAP_IPC_LOCK for the mlock
defence). `systemd-analyze security steled` should report a
satisfactory score on a normal Linux host.

---

## After any path

```sh
# Confirm health
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz

# Inspect metrics
curl -fsS http://localhost:8080/metrics | grep '^stele_'

# Look at logs (JSON output for parsers)
docker logs stele-operator                       # docker
kubectl -n stele logs sts/stele-stele-operator   # helm
journalctl -u steled -o json                     # systemd
```

For day-2 operations (rotation, recovery, drills) see
[RECOVERY.md](../RECOVERY.md).

For what stele defends against and what it doesn't, see
[THREATMODEL.md](../THREATMODEL.md).
