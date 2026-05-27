#!/usr/bin/env bash
# install.sh — install stele as a systemd service on a single host.
#
# Idempotent: re-running is safe. Run as root.
#
# What this does:
#   1. Create the `stele` system user/group.
#   2. Create /var/lib/stele{,-witness,-mirror} dirs with 0750 perms.
#   3. Install /etc/stele/{steled,witness,mirror}.env from the
#      .example files IF they don't already exist (so re-runs don't
#      stomp configured values).
#   4. Install the unit files into /etc/systemd/system/.
#   5. systemctl daemon-reload.
#
# It does NOT:
#   - copy the binaries (you do that: `cp steled /usr/local/bin/`).
#   - enable or start the services (you do that after editing
#     the env files).
#
# Usage:
#   sudo ./install.sh                 # full operator + witness + mirror
#   sudo ./install.sh operator        # operator only
#   sudo ./install.sh witness         # witness only
#   sudo ./install.sh mirror          # mirror only

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "install.sh: must be run as root" >&2
    exit 1
fi

THIS_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGETS=("${@:-all}")

create_user() {
    if ! id -u stele >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin \
            --home-dir /var/lib/stele stele
        echo "  created system user 'stele'"
    fi
}

install_env() {
    local name="$1"   # steled / witness / mirror
    local src="$THIS_DIR/${name}.env.example"
    local dst="/etc/stele/${name}.env"
    if [ ! -f "$src" ]; then
        echo "  $src missing, skipping"
        return
    fi
    if [ ! -f "$dst" ]; then
        install -d -m 0750 -o root -g stele /etc/stele
        install -m 0640 -o root -g stele "$src" "$dst"
        echo "  installed $dst (edit before starting)"
    else
        echo "  $dst already exists; left untouched"
    fi
}

install_unit() {
    local name="$1"
    local src="$THIS_DIR/${name}.service"
    local dst="/etc/systemd/system/${name}.service"
    install -m 0644 -o root -g root "$src" "$dst"
    echo "  installed $dst"
}

install_operator() {
    echo "==> stele operator"
    create_user
    install -d -m 0750 -o stele -g stele /var/lib/stele
    install -d -m 0750 -o stele -g stele /var/log/stele
    install_env steled
    install_unit steled
}

install_witness() {
    echo "==> stele witness"
    create_user
    install -d -m 0750 -o stele -g stele /var/lib/stele-witness
    install_env witness
    install_unit stele-witness
}

install_mirror() {
    echo "==> stele mirror"
    create_user
    install -d -m 0750 -o stele -g stele /var/lib/stele-mirror
    install_env mirror
    install_unit stele-mirror
}

for tgt in "${TARGETS[@]}"; do
    case "$tgt" in
        all)
            install_operator
            install_witness
            install_mirror
            ;;
        operator) install_operator ;;
        witness)  install_witness  ;;
        mirror)   install_mirror   ;;
        *)
            echo "install.sh: unknown target '$tgt' (expected: all|operator|witness|mirror)" >&2
            exit 2
            ;;
    esac
done

systemctl daemon-reload
echo
echo "Next steps:"
echo "  1. Copy the binaries: cp steled stele stele-witness stele-mirror /usr/local/bin/"
echo "  2. Edit /etc/stele/*.env"
echo "  3. systemctl enable --now steled         (and/or stele-witness, stele-mirror)"
echo "  4. Check: systemctl status steled; journalctl -u steled -f"
