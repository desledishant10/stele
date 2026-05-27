#!/usr/bin/env bash
# pilot/review.sh — end-of-period audit report for the pilot.
#
# Runs `stele audit --pdf` against the pilot operator, prints the
# verdict, and tells you where the PDF + summary live. Safe to run
# at any point (mid-week sanity checks are encouraged).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$HERE/config.sh" ]]; then
    # shellcheck disable=SC1091
    source "$HERE/config.sh"
else
    # shellcheck disable=SC1091
    source "$HERE/config.example.sh"
fi

log() { printf "==> %s\n" "$*"; }

stamp=$(date +%Y%m%d-%H%M%S)
out_dir="$PILOT_DATA_DIR/reviews/$stamp"
mkdir -p "$out_dir"

pdf="$out_dir/audit.pdf"

# Out-of-band trust anchor: captured on first review, then reused.
# This gives the audit a higher confidence grade ("compared anchor we
# saved at setup time" vs. "trusted whatever the server said").
anchor_file="$PILOT_DATA_DIR/trust-anchor.b64"
if [[ ! -f "$anchor_file" ]]; then
    log "first review: capturing trust anchor for future verifications"
    curl -fsS "http://$PILOT_OPERATOR_ADDR/api/v0/pubkey" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['root_public_key'])" \
        > "$anchor_file"
fi

anchor_args=()
if [[ -s "$anchor_file" ]]; then
    anchor_args=(--root "$(cat "$anchor_file")" --root-source self-fetched)
fi

log "running full audit against http://$PILOT_OPERATOR_ADDR ..."
"$PILOT_BIN_DIR/stele" audit \
    --server "http://$PILOT_OPERATOR_ADDR" \
    --pdf "$pdf" \
    "${anchor_args[@]}" \
    | tee "$out_dir/audit.txt"

log ""
log "PDF: $pdf"
log "log: $out_dir/audit.txt"

# Quick numerical summary: how many entries, how many distinct repos.
size_json=$(curl -fsS "http://$PILOT_OPERATOR_ADDR/api/v0/size")
size=$(echo "$size_json" | sed -n 's/.*"size":[[:space:]]*\([0-9]*\).*/\1/p')

log ""
log "summary:"
log "  entries logged     : $size"

state="$PILOT_DATA_DIR/watcher/state.json"
if [[ -f "$state" ]]; then
    repos=$(python3 -c "import json; print(len(json.load(open('$state'))))" 2>/dev/null || echo "?")
    log "  repos tracked      : $repos"
fi

# Verdict line: stele audit --pdf reports "status=PASS|WARN|FAIL"
# on the PDF-written line near the end of stdout.
verdict=$(grep -oE "status=(PASS|WARN|FAIL)" "$out_dir/audit.txt" | tail -1 | cut -d= -f2)
log "  audit verdict      : ${verdict:-UNKNOWN (see $out_dir/audit.txt)}"

log ""
log "trust anchor (auditors verify against this):"
"$PILOT_BIN_DIR/stele" pubkey --server "http://$PILOT_OPERATOR_ADDR" | sed 's/^/    /'

if command -v open >/dev/null 2>&1 && [[ -t 1 ]]; then
    log ""
    log "opening PDF..."
    open "$pdf"
fi
