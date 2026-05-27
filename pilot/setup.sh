#!/usr/bin/env bash
# pilot/setup.sh — bootstrap the stele pilot on macOS.
#
# Idempotent. Safe to re-run after partial failures. On success, leaves
# you with:
#
#   - steled running as a launchd user agent on 127.0.0.1:18080
#   - one stele-witness running on 127.0.0.1:19090, registered with
#     the operator and watching this operator
#   - a producer keypair + enrollment minted for the git-watcher
#   - the launchd watcher schedule installed (fires every 30 min)
#
# Run:    pilot/setup.sh
# Status: pilot/status.sh
# Stop:   pilot/teardown.sh
#
# Requires: macOS with launchd; bash 4+; Go (to build) OR prebuilt
# binaries already in ./bin; the Python SDK installed in
# sdk/python/.venv (pip install -e sdk/python).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# Source the user's config if present, otherwise fall back to defaults.
if [[ -f "$HERE/config.sh" ]]; then
    # shellcheck disable=SC1091
    source "$HERE/config.sh"
else
    echo "==> pilot/config.sh not found; using defaults from config.example.sh"
    echo "    (cp pilot/config.example.sh pilot/config.sh and edit if you want different paths)"
    # shellcheck disable=SC1091
    source "$HERE/config.example.sh"
fi

LAUNCHD_DIR="$HOME/Library/LaunchAgents"
PLIST_OPERATOR="$LAUNCHD_DIR/com.stele.pilot.operator.plist"
PLIST_WITNESS="$LAUNCHD_DIR/com.stele.pilot.witness.plist"
PLIST_WATCHER="$LAUNCHD_DIR/com.stele.pilot.watcher.plist"

log() { printf "==> %s\n" "$*"; }
die() { printf "ERROR: %s\n" "$*" >&2; exit 1; }

require_macos() {
    [[ "$(uname -s)" == "Darwin" ]] || die "pilot/setup.sh currently supports macOS only (launchd-based). Linux users: see pilot/README.md for the systemd recipe."
}

build_binaries() {
    if [[ -x "$PILOT_BIN_DIR/steled" && -x "$PILOT_BIN_DIR/stele" && -x "$PILOT_BIN_DIR/stele-witness" ]]; then
        log "binaries already built ($PILOT_BIN_DIR)"
        return
    fi
    log "building stele binaries (one-time)..."
    ( cd "$ROOT" && make build )
    [[ -x "$PILOT_BIN_DIR/steled" ]] || die "make build did not produce $PILOT_BIN_DIR/steled"
}

ensure_python_sdk() {
    if [[ ! -x "$PILOT_PYTHON" ]]; then
        log "Python SDK venv missing at $PILOT_PYTHON"
        log "creating it now..."
        ( cd "$ROOT/sdk/python" && \
          python3 -m venv .venv && \
          .venv/bin/pip install --upgrade pip setuptools wheel >/dev/null && \
          .venv/bin/pip install -e . >/dev/null )
    fi
    [[ -x "$PILOT_PYTHON" ]] || die "Python SDK venv still missing at $PILOT_PYTHON"
    "$PILOT_PYTHON" -c "import stele" 2>/dev/null || die "stele not importable from $PILOT_PYTHON; try: rm -rf sdk/python/.venv && pilot/setup.sh"
}

mint_data_dirs() {
    mkdir -p "$PILOT_DATA_DIR"/{operator,witness,producer,watcher,logs}
    chmod 700 "$PILOT_DATA_DIR"
    log "data dir: $PILOT_DATA_DIR"
}

write_operator_plist() {
    cat > "$PLIST_OPERATOR" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.stele.pilot.operator</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PILOT_BIN_DIR/steled</string>
    <string>--addr</string>
    <string>$PILOT_OPERATOR_ADDR</string>
    <string>--dir</string>
    <string>$PILOT_DATA_DIR/operator</string>
    <string>--origin</string>
    <string>$PILOT_ORIGIN</string>
    <string>--init</string>
    <string>--require-enrollment</string>
    <string>--beacon</string>
    <string></string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$PILOT_DATA_DIR/logs/operator.log</string>
  <key>StandardErrorPath</key>
  <string>$PILOT_DATA_DIR/logs/operator.err</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>STELE_LOG_FORMAT</key>
    <string>json</string>
    <key>STELE_LOG_LEVEL</key>
    <string>info</string>
  </dict>
</dict>
</plist>
EOF
    log "wrote $PLIST_OPERATOR"
}

write_witness_plist() {
    cat > "$PLIST_WITNESS" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.stele.pilot.witness</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PILOT_BIN_DIR/stele-witness</string>
    <string>--addr</string>
    <string>$PILOT_WITNESS_ADDR</string>
    <string>--dir</string>
    <string>$PILOT_DATA_DIR/witness</string>
    <string>--id</string>
    <string>witness-local-1</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$PILOT_DATA_DIR/logs/witness.log</string>
  <key>StandardErrorPath</key>
  <string>$PILOT_DATA_DIR/logs/witness.err</string>
</dict>
</plist>
EOF
    log "wrote $PLIST_WITNESS"
}

write_watcher_plist() {
    cat > "$PLIST_WATCHER" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.stele.pilot.watcher</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PILOT_PYTHON</string>
    <string>$HERE/git_watcher.py</string>
  </array>
  <key>StartInterval</key>
  <integer>$PILOT_SCAN_INTERVAL</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PILOT_CONFIG</key>
    <string>$HERE/config.sh</string>
  </dict>
  <key>StandardOutPath</key>
  <string>$PILOT_DATA_DIR/logs/watcher.log</string>
  <key>StandardErrorPath</key>
  <string>$PILOT_DATA_DIR/logs/watcher.err</string>
</dict>
</plist>
EOF
    log "wrote $PLIST_WATCHER (fires every ${PILOT_SCAN_INTERVAL}s)"
}

# Bootstrap (or restart) a launchd agent. Tolerates the agent already
# being loaded.
load_agent() {
    local label="$1" plist="$2"
    if launchctl list | awk '{print $3}' | grep -qx "$label"; then
        log "$label already loaded; bootout + reload to pick up plist changes"
        launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
        sleep 0.5
    fi
    launchctl bootstrap "gui/$(id -u)" "$plist"
    launchctl enable "gui/$(id -u)/$label"
}

wait_ready() {
    local url="$1" what="$2"
    log "waiting for $what at $url ..."
    for _ in $(seq 1 60); do
        if curl -fsS --max-time 1 "$url" >/dev/null 2>&1; then
            log "$what ready"
            return
        fi
        sleep 0.5
    done
    die "$what never became ready at $url (check $PILOT_DATA_DIR/logs/)"
}

register_witness() {
    # /api/v0/witnesses is idempotent on (id, pubkey, url); a duplicate
    # registration just refreshes the record.
    log "registering witness with operator..."
    "$PILOT_BIN_DIR/stele" witness-add \
        --server "http://$PILOT_OPERATOR_ADDR" \
        --url "http://$PILOT_WITNESS_ADDR" \
        --id "witness-local-1" \
        --desc "pilot local witness" \
        || die "witness-add failed; see $PILOT_DATA_DIR/logs/"
}

enroll_producer() {
    local keyfile="$PILOT_DATA_DIR/producer/${PILOT_PRODUCER_ID}.priv"
    if [[ -f "$keyfile" ]]; then
        log "producer key already exists at $keyfile"
        # Confirm the producer is enrolled on the operator side.
        if "$PILOT_BIN_DIR/stele" producer-list --server "http://$PILOT_OPERATOR_ADDR" 2>/dev/null \
              | grep -q "$PILOT_PRODUCER_ID"; then
            log "producer $PILOT_PRODUCER_ID already enrolled"
            return
        fi
        log "key exists but producer not on operator; will re-enroll"
    else
        log "minting producer keypair for $PILOT_PRODUCER_ID"
        "$PILOT_BIN_DIR/stele" producer-init \
            --id "$PILOT_PRODUCER_ID" \
            --out "$keyfile"
    fi
    log "running proof-of-possession enrollment ceremony"
    "$PILOT_BIN_DIR/stele" enroll-producer \
        --server "http://$PILOT_OPERATOR_ADDR" \
        --id "$PILOT_PRODUCER_ID" \
        --key "$keyfile" \
        --scope "logs:git-commits" \
        --validity 2160h   # 90 days
}

print_anchor() {
    log ""
    log "------------------------------------------------------------"
    log "trust anchor (auditors verify against this):"
    "$PILOT_BIN_DIR/stele" pubkey --server "http://$PILOT_OPERATOR_ADDR" || true
    log "------------------------------------------------------------"
    log "pilot is up. next steps:"
    log "  pilot/status.sh        — check health"
    log "  tail -f $PILOT_DATA_DIR/logs/watcher.log"
    log "  pilot/review.sh        — end-of-week audit PDF"
}

main() {
    require_macos
    build_binaries
    ensure_python_sdk
    mkdir -p "$LAUNCHD_DIR"
    mint_data_dirs

    write_operator_plist
    write_witness_plist
    write_watcher_plist

    load_agent "com.stele.pilot.operator" "$PLIST_OPERATOR"
    wait_ready "http://$PILOT_OPERATOR_ADDR/readyz" "operator"

    load_agent "com.stele.pilot.witness" "$PLIST_WITNESS"
    wait_ready "http://$PILOT_WITNESS_ADDR/witness/v0/pubkey" "witness"

    register_witness
    enroll_producer

    load_agent "com.stele.pilot.watcher" "$PLIST_WATCHER"

    print_anchor
}

main "$@"
