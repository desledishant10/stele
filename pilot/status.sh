#!/usr/bin/env bash
# pilot/status.sh — one-screen health check for the running pilot.
#
# Tells you: are the services up, how many entries are in the log,
# when did the watcher last run, when's the most recent commit logged,
# and is /readyz green.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$HERE/config.sh" ]]; then
    # shellcheck disable=SC1091
    source "$HERE/config.sh"
else
    # shellcheck disable=SC1091
    source "$HERE/config.example.sh"
fi

OK="\033[32m✓\033[0m"
BAD="\033[31m✗\033[0m"
DIM="\033[2m"
RST="\033[0m"

agent_state() {
    # Returns "running PID", "loaded but not running", or "not loaded".
    local label="$1"
    local line
    line=$(launchctl list 2>/dev/null | awk -v l="$label" '$3 == l {print}')
    if [[ -z "$line" ]]; then
        echo "not loaded"
        return
    fi
    local pid status
    pid=$(echo "$line" | awk '{print $1}')
    status=$(echo "$line" | awk '{print $2}')
    if [[ "$pid" == "-" ]]; then
        echo "loaded (status=$status, not running)"
    else
        echo "running (pid=$pid)"
    fi
}

check_endpoint() {
    local url="$1" name="$2"
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
        printf "  $OK %-12s %s\n" "$name" "$url"
    else
        printf "  $BAD %-12s %s${DIM} (unreachable)${RST}\n" "$name" "$url"
    fi
}

section() { printf "\n${DIM}── %s ──${RST}\n" "$1"; }

section "launchd agents"
printf "  operator: %s\n" "$(agent_state com.stele.pilot.operator)"
printf "  witness : %s\n" "$(agent_state com.stele.pilot.witness)"
printf "  watcher : %s\n" "$(agent_state com.stele.pilot.watcher)"

section "endpoints"
check_endpoint "http://$PILOT_OPERATOR_ADDR/readyz"             "operator"
check_endpoint "http://$PILOT_WITNESS_ADDR/witness/v0/pubkey"  "witness"

section "log state"
if size_json=$(curl -fsS --max-time 2 "http://$PILOT_OPERATOR_ADDR/api/v0/size" 2>/dev/null); then
    parsed=$(echo "$size_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('size','?'), d.get('root_hash',''))" 2>/dev/null)
    n="${parsed%% *}"
    root="${parsed#* }"
    printf "  entries logged : %s\n" "${n:-?}"
    if [[ -n "$root" ]]; then
        printf "  current root   : %s...\n" "${root:0:24}"
    fi
else
    printf "  ${BAD} could not query operator\n"
fi

section "watcher"
state_file="$PILOT_DATA_DIR/watcher/state.json"
if [[ -f "$state_file" ]]; then
    repos=$(python3 -c "import json,sys; print(len(json.load(open('$state_file'))))" 2>/dev/null || echo "?")
    last_modified=$(stat -f "%Sm" "$state_file" 2>/dev/null || stat -c "%y" "$state_file" 2>/dev/null || echo "?")
    printf "  repos tracked  : %s\n" "$repos"
    printf "  state updated  : %s\n" "$last_modified"
else
    printf "  ${DIM}state.json not yet written (watcher hasn't run successfully)${RST}\n"
fi

watcher_log="$PILOT_DATA_DIR/logs/watcher.log"
if [[ -f "$watcher_log" ]]; then
    last_run=$(grep -E "scan complete|FATAL" "$watcher_log" | tail -1 || true)
    if [[ -n "$last_run" ]]; then
        printf "  last scan      : %s\n" "$last_run"
    fi
    # Count entries logged in the last 24h from the log file.
    last24=$(grep "logged " "$watcher_log" 2>/dev/null | wc -l | tr -d ' ')
    printf "  commits logged : %s (all-time, from watcher.log)\n" "$last24"
fi

section "recent entries"
if curl -fsS --max-time 2 "http://$PILOT_OPERATOR_ADDR/api/v0/size" >/dev/null 2>&1; then
    size_val=$(curl -fsS "http://$PILOT_OPERATOR_ADDR/api/v0/size" | sed -n 's/.*"size":[[:space:]]*\([0-9]*\).*/\1/p')
    if [[ -n "$size_val" && "$size_val" -gt 0 ]]; then
        start=$(( size_val > 5 ? size_val - 5 : 0 ))
        for i in $(seq $start $((size_val - 1))); do
            entry=$(curl -fsS --max-time 2 "http://$PILOT_OPERATOR_ADDR/api/v0/entries/$i" 2>/dev/null) || continue
            src=$(echo "$entry" | sed -n 's/.*"source":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
            # Decode the entry data (base64'd JSON) to grab the subject.
            data_b64=$(echo "$entry" | python3 -c "import sys,json; e=json.load(sys.stdin); print(e.get('entry',{}).get('envelope',{}).get('data',''))" 2>/dev/null || true)
            subject=""
            if [[ -n "$data_b64" ]]; then
                subject=$(echo "$data_b64" | base64 -d 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('subject',''))" 2>/dev/null | cut -c1-50)
            fi
            printf "  [%4d] %-32s %s\n" "$i" "$src" "$subject"
        done
    else
        printf "  ${DIM}no entries yet${RST}\n"
    fi
fi

echo
