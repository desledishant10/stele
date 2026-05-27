#!/usr/bin/env bash
# build-deb.sh — assemble a .deb package for stele.
#
# Run AFTER the release workflow has produced the linux/<arch>
# binaries under dist/. This script lays them out in the canonical
# /usr/local/bin + /etc/stele + /lib/systemd/system structure that
# Debian/Ubuntu deployments expect, then invokes dpkg-deb.
#
# Usage:
#   ARCH=amd64 VERSION=0.1.0 ./deploy/deb/build-deb.sh
#   ARCH=arm64 VERSION=0.1.0 ./deploy/deb/build-deb.sh
#
# Output: dist/stele_${VERSION}_${ARCH}.deb
#
# Requires: dpkg-deb (apt-get install dpkg-dev on Debian/Ubuntu).

set -euo pipefail

ARCH="${ARCH:?ARCH required (amd64|arm64)}"
VERSION="${VERSION:?VERSION required (e.g. 0.1.0)}"
WORKDIR="$(cd "$(dirname "$0")/../.." && pwd)"
SRCDIR="${WORKDIR}/dist"
PKGDIR="$(mktemp -d -t stele-deb-XXXXXX)"
trap 'rm -rf "$PKGDIR"' EXIT

mkdir -p "$PKGDIR/DEBIAN"
mkdir -p "$PKGDIR/usr/local/bin"
mkdir -p "$PKGDIR/lib/systemd/system"
mkdir -p "$PKGDIR/etc/stele"
mkdir -p "$PKGDIR/var/lib/stele"
mkdir -p "$PKGDIR/usr/share/doc/stele"

# Copy binaries.
for cmd in steled stele stele-witness stele-mirror stele-cosigner \
           stele-backup stele-export-chain stele-watcher stele-loadgen; do
    src="${SRCDIR}/${cmd}-linux-${ARCH}"
    if [ ! -f "$src" ]; then
        echo "build-deb: missing binary $src" >&2
        exit 1
    fi
    install -m 0755 "$src" "$PKGDIR/usr/local/bin/$cmd"
done

# systemd units + env templates.
install -m 0644 "${WORKDIR}/deploy/systemd/steled.service"        "$PKGDIR/lib/systemd/system/"
install -m 0644 "${WORKDIR}/deploy/systemd/stele-witness.service" "$PKGDIR/lib/systemd/system/"
install -m 0644 "${WORKDIR}/deploy/systemd/stele-mirror.service"  "$PKGDIR/lib/systemd/system/"
install -m 0644 "${WORKDIR}/deploy/systemd/steled.env.example"    "$PKGDIR/etc/stele/"
install -m 0644 "${WORKDIR}/deploy/systemd/witness.env.example"   "$PKGDIR/etc/stele/"
install -m 0644 "${WORKDIR}/deploy/systemd/mirror.env.example"    "$PKGDIR/etc/stele/"

# Documentation.
install -m 0644 "${WORKDIR}/README.md"      "$PKGDIR/usr/share/doc/stele/"
install -m 0644 "${WORKDIR}/PLAYBOOK.md"    "$PKGDIR/usr/share/doc/stele/"
install -m 0644 "${WORKDIR}/RECOVERY.md"    "$PKGDIR/usr/share/doc/stele/"
install -m 0644 "${WORKDIR}/THREATMODEL.md" "$PKGDIR/usr/share/doc/stele/"
install -m 0644 "${WORKDIR}/LICENSE"        "$PKGDIR/usr/share/doc/stele/copyright"

# Control file.
cat > "$PKGDIR/DEBIAN/control" <<EOF
Package: stele
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: stele <desledishant10@users.noreply.github.com>
Homepage: https://github.com/desledishant10/stele
Description: Provenance-anchored audit log
 stele is a tamper-evident append-only log. Producers sign their
 entries, the operator chains them, witnesses cosign checkpoints,
 and external anchors (Sigstore Rekor, drand) bind everything to
 public ground truth. Designed for compliance audit trails,
 release provenance, security event logs, and any record-keeping
 where "the log is the contract."
EOF

cat > "$PKGDIR/DEBIAN/conffiles" <<EOF
/etc/stele/steled.env.example
/etc/stele/witness.env.example
/etc/stele/mirror.env.example
EOF

# postinst: create the stele user + reload systemd. Idempotent.
cat > "$PKGDIR/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! id -u stele >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --home-dir /var/lib/stele stele
fi
chown -R stele:stele /var/lib/stele
chmod 0750 /var/lib/stele
systemctl daemon-reload || true
echo
echo "stele installed. Next steps:"
echo "  1. Copy /etc/stele/*.env.example to /etc/stele/<name>.env"
echo "  2. Edit the env files with your origin, witness URLs, etc."
echo "  3. systemctl enable --now steled"
echo
echo "See /usr/share/doc/stele/PLAYBOOK.md for full operator guidance."
EOF
chmod 0755 "$PKGDIR/DEBIAN/postinst"

# prerm: stop services before removal.
cat > "$PKGDIR/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
for svc in steled stele-witness stele-mirror; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc" || true
    fi
done
EOF
chmod 0755 "$PKGDIR/DEBIAN/prerm"

# postrm: reload systemd on uninstall.
cat > "$PKGDIR/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload || true
EOF
chmod 0755 "$PKGDIR/DEBIAN/postrm"

# Build the deb.
mkdir -p "${SRCDIR}"
out="${SRCDIR}/stele_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$PKGDIR" "$out"
echo "built $out"
