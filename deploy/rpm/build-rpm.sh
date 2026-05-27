#!/usr/bin/env bash
# build-rpm.sh — assemble an .rpm package for stele.
#
# Run AFTER the release workflow has produced the linux/<arch>
# binaries under dist/. This script stages binaries + systemd units
# + docs into rpmbuild's expected source layout, then invokes
# `rpmbuild -bb`.
#
# Usage:
#   ARCH=x86_64  VERSION=0.1.0 ./deploy/rpm/build-rpm.sh
#   ARCH=aarch64 VERSION=0.1.0 ./deploy/rpm/build-rpm.sh
#
# Output: dist/RPMS/<arch>/stele-<version>-1.<dist>.<arch>.rpm
#
# Requires: rpmbuild (dnf install rpm-build).

set -euo pipefail

ARCH="${ARCH:?ARCH required (x86_64|aarch64)}"
VERSION="${VERSION:?VERSION required (e.g. 0.1.0)}"

# rpmbuild expects x86_64 / aarch64 arch names. Translate from Go's
# amd64 / arm64 if a Go-style arch was passed.
case "$ARCH" in
    amd64) GO_ARCH=amd64; ARCH=x86_64 ;;
    arm64) GO_ARCH=arm64; ARCH=aarch64 ;;
    x86_64) GO_ARCH=amd64 ;;
    aarch64) GO_ARCH=arm64 ;;
    *) echo "build-rpm: unknown ARCH $ARCH"; exit 2 ;;
esac

WORKDIR="$(cd "$(dirname "$0")/../.." && pwd)"
SRCDIR="${WORKDIR}/dist"
RPMTOP="${WORKDIR}/dist/rpmbuild"
mkdir -p "$RPMTOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Stage every binary into SOURCES with the unsuffixed names the spec
# file expects.
for cmd in steled stele stele-witness stele-mirror stele-cosigner \
           stele-backup stele-export-chain stele-watcher stele-loadgen; do
    src="${SRCDIR}/${cmd}-linux-${GO_ARCH}"
    if [ ! -f "$src" ]; then
        echo "build-rpm: missing binary $src" >&2
        exit 1
    fi
    install -m 0755 "$src" "$RPMTOP/SOURCES/${cmd}"
done

# Stage systemd units + envs + docs.
install -m 0644 "${WORKDIR}/deploy/systemd/steled.service"        "$RPMTOP/SOURCES/"
install -m 0644 "${WORKDIR}/deploy/systemd/stele-witness.service" "$RPMTOP/SOURCES/"
install -m 0644 "${WORKDIR}/deploy/systemd/stele-mirror.service"  "$RPMTOP/SOURCES/"
install -m 0644 "${WORKDIR}/deploy/systemd/steled.env.example"    "$RPMTOP/SOURCES/"
install -m 0644 "${WORKDIR}/deploy/systemd/witness.env.example"   "$RPMTOP/SOURCES/"
install -m 0644 "${WORKDIR}/deploy/systemd/mirror.env.example"    "$RPMTOP/SOURCES/"
install -m 0644 "${WORKDIR}/README.md"      "$RPMTOP/SOURCES/"
install -m 0644 "${WORKDIR}/PLAYBOOK.md"    "$RPMTOP/SOURCES/"
install -m 0644 "${WORKDIR}/RECOVERY.md"    "$RPMTOP/SOURCES/"
install -m 0644 "${WORKDIR}/THREATMODEL.md" "$RPMTOP/SOURCES/"
install -m 0644 "${WORKDIR}/LICENSE"        "$RPMTOP/SOURCES/"

cp "${WORKDIR}/deploy/rpm/stele.spec" "$RPMTOP/SPECS/stele.spec"

rpmbuild \
    --define "_topdir $RPMTOP" \
    --define "_stele_version $VERSION" \
    --define "_target_cpu $ARCH" \
    --target "$ARCH" \
    -bb "$RPMTOP/SPECS/stele.spec"

# Surface the built RPM at a predictable path.
out="${SRCDIR}/stele-${VERSION}-1.${ARCH}.rpm"
src=$(find "$RPMTOP/RPMS" -name "stele-${VERSION}-*.${ARCH}.rpm" | head -1)
cp "$src" "$out"
echo "built $out"
