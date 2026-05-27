# Stele Platform Support Matrix

Stele is **pure Go (no CGO required for any binary by default)**, so
every binary cross-compiles cleanly to every platform Go supports. The
release workflow ships binaries for the cells marked **release**;
others are buildable from source.

| OS / Arch | linux/amd64 | linux/arm64 | darwin/amd64 | darwin/arm64 | windows/amd64 | windows/arm64 | freebsd/amd64 |
|---|---|---|---|---|---|---|---|
| Binaries built | **release** | **release** | **release** | **release** | **release** | **release** | **release** |
| `steled` (operator) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `stele-witness` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `stele-mirror` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `stele-cosigner` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `stele` (CLI) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `stele-backup` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `stele-export-chain` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `stele-watcher` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `stele-loadgen` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

## Feature support per platform

Some hardening features depend on OS facilities. Where a feature
isn't available, stele falls back to a documented no-op rather than
refusing to start — your security posture is reduced, never broken.

| Feature | Linux | macOS | Windows | FreeBSD | Notes |
|---|---|---|---|---|---|
| Core protocol (Merkle, fwdsec, witnesses, threshold, hybrid PQ, mirror, anchoring, tripwire, enrollment) | ✅ | ✅ | ✅ | ✅ | Pure-Go; identical on every OS |
| `mlock` private keys ([pkg/keyguard](pkg/keyguard/)) | ✅ | ✅ | ⚠️ no-op | ⚠️ no-op | Windows: VirtualLock is available but not yet wired; mlock returns ErrUnsupported |
| `MADV_DONTDUMP` (exclude keys from core dumps) | ✅ | ⚠️ no-op | ⚠️ no-op | ⚠️ no-op | Linux only; macOS uses `ulimit -c 0` instead |
| fsnotify key-tamper detection ([pkg/watchdog](pkg/watchdog/)) | ✅ | ✅ | ✅ | ✅ | fsnotify supports all four |
| systemd hardening (NoNewPrivileges, ProtectSystem, etc.) | ✅ | n/a | n/a | n/a | systemd is Linux-only |
| HSM via PKCS#11 ([pkg/hsm](pkg/hsm/)) | ⚙️ CGO | ⚙️ CGO | ⚙️ CGO | ⚙️ CGO | Requires `CGO_ENABLED=1` rebuild — default binaries are CGO-off and HSM-disabled. Build with `go build` (CGO defaults to on with a C toolchain present) for HSM. |
| Distroless OCI image | ✅ amd64+arm64 | n/a | n/a | n/a | linux/amd64 + linux/arm64 multi-arch image at `ghcr.io/desledishant10/stele` |
| Helm chart | ✅ | ✅ | ✅ | ✅ | Targets are Kubernetes pods (which are usually Linux); the chart itself is cross-platform |
| Docker container | ✅ | ✅ via Docker Desktop | ✅ via Docker Desktop | n/a | The image is linux/amd64 + linux/arm64 |

## Building from source on each platform

All paths assume Go 1.25+.

### Linux / macOS / FreeBSD

```sh
git clone https://github.com/desledishant10/stele && cd stele
go build ./cmd/steled
go build ./cmd/stele
# ...etc
```

### Windows (PowerShell)

```powershell
git clone https://github.com/desledishant10/stele
cd stele
go build .\cmd\steled
go build .\cmd\stele
# Output: steled.exe, stele.exe in the current dir
```

### Cross-compile (from any host)

```sh
# Example: build a Windows arm64 binary from a Linux x86_64 host.
GOOS=windows GOARCH=arm64 go build ./cmd/steled
```

The release workflow does exactly this for every target on every
tag push.

## What's intentionally NOT cross-platform

- **systemd units** ([deploy/systemd/](deploy/systemd/)): Linux only.
  Windows uses `sc.exe` services or NSSM; macOS uses `launchd`. Both
  are operator-side packaging — port the unit's flag set to whatever
  service supervisor your platform uses.
- **HSM examples in HARDENING.md**: assume PKCS#11 module paths
  (`/opt/cloudhsm/lib/...`). Windows HSM clients are typically DLLs
  at `C:\Program Files\...`; the path is the only change.
- **deploy/Dockerfile**: produces a Linux image, since the OCI
  ecosystem is Linux-centric. The binaries inside cross-compile to
  every platform; the image only runs on Linux container runtimes.

## Per-platform operator notes

### Linux (preferred for the operator role)

- Run as a systemd service via [deploy/systemd/install.sh](deploy/systemd/install.sh).
- Grant `CAP_IPC_LOCK` (already in the unit) so `mlock` works without root.
- Set `ulimit -l` to at least 4 MiB if you raise the operator's key budget.
- Hardening recipe: see "1. systemd" path in [QUICKSTART](deploy/QUICKSTART.md).

### macOS (good for the operator's CLI + producer side)

- The producer/auditor `stele` binary is fully native on Apple Silicon.
- Don't run a production operator on macOS — `mlock` works but the OS
  doesn't honour `MADV_DONTDUMP`. Use `launchctl limit core 0 0` to
  disable core dumps process-wide.
- Use Homebrew (recipe TBD) to install once releases are public.

### Windows (operator role supported, hardening reduced)

- All binaries build and run cleanly on Windows.
- Memory protection: `mlock` is a no-op (Windows uses `VirtualLock`;
  wiring it up is a future task — current build returns ErrUnsupported
  and logs a warning, then proceeds).
- Run as a Windows Service via NSSM or sc.exe. The flag set is the
  same as the systemd unit's `STELE_FLAGS`.
- Don't store the operator's signing key on a network share; the
  watchdog's fsnotify watcher behaves differently on SMB.

### FreeBSD (supported)

- Builds and runs the full feature set except `MADV_DONTDUMP`.
- Use `rc.d` scripts as the service supervisor.

## Architecture notes

- **arm64**: fully supported. Apple Silicon, AWS Graviton, Raspberry Pi 4+, modern Android servers.
- **amd64**: fully supported.
- **arm (32-bit)**: not built by default; should build via `GOARCH=arm GOARM=7` if you need it.
- **riscv64**: untested but should build (Go supports it).
- **mips / mips64**: untested.

## Compatibility guarantee

Stele commits to:

1. **Wire format stability** across the same major version. A v0.1
   client can talk to a v0.2 operator. Wire format changes are
   additive (new optional fields) until the next major version.
2. **CLI flag stability**: flags don't disappear without a deprecation
   notice in the previous minor version.
3. **Persistence format stability**: a database written by v0.1.x can
   be opened by v0.2.x. Migrations are forward-only and one-way.

What's NOT covered:

- Internal Go package APIs are not stable; tooling that imports
  `github.com/desledishant10/stele/pkg/...` may break across minor
  versions. The HTTP API + CLI is the stable interface.
