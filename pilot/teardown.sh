#!/usr/bin/env bash
# pilot/teardown.sh — stop and uninstall the pilot.
#
# By default this:
#   - stops + unloads the three launchd agents
#   - removes the plists from ~/Library/LaunchAgents
#
# By default it KEEPS the data directory ($PILOT_DATA_DIR) so you can
# still produce one last audit report or hand the log to an auditor.
# Pass `--purge` to also delete that directory (irreversible).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$HERE/config.sh" ]]; then
    # shellcheck disable=SC1091
    source "$HERE/config.sh"
else
    # shellcheck disable=SC1091
    source "$HERE/config.example.sh"
fi

PURGE=0
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        -h|--help)
            cat <<EOF
pilot/teardown.sh — stop + uninstall the stele pilot

  (default)   stop services, remove plists, KEEP data
  --purge     also delete $PILOT_DATA_DIR (irreversible)
EOF
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

LAUNCHD_DIR="$HOME/Library/LaunchAgents"
LABELS=(
    com.stele.pilot.watcher
    com.stele.pilot.witness
    com.stele.pilot.operator
)

log() { printf "==> %s\n" "$*"; }

for label in "${LABELS[@]}"; do
    plist="$LAUNCHD_DIR/${label}.plist"
    if launchctl list 2>/dev/null | awk '{print $3}' | grep -qx "$label"; then
        log "unloading $label"
        launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
    fi
    if [[ -f "$plist" ]]; then
        log "removing $plist"
        rm -f "$plist"
    fi
done

if [[ "$PURGE" -eq 1 ]]; then
    if [[ -d "$PILOT_DATA_DIR" ]]; then
        log "PURGE: deleting $PILOT_DATA_DIR"
        rm -rf "$PILOT_DATA_DIR"
    fi
else
    log "data dir preserved at: $PILOT_DATA_DIR"
    log "  (pilot/teardown.sh --purge to delete it)"
fi

log "done"
