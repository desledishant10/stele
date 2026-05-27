#!/usr/bin/env bash
# check_bench_regression.sh
#
# Fail with non-zero exit if benchstat output (passed via $1) shows any
# benchmark slowed down by more than the configured threshold.
#
# Usage:
#   ./scripts/check_bench_regression.sh bench/diff.txt [threshold_pct]
#
# threshold_pct defaults to 100 (>100% slower == >2x). Override via:
#   THRESHOLD_PCT=50 ./scripts/check_bench_regression.sh bench/diff.txt
#
# Assumes benchstat's default text output. Lines with a percent delta
# like "+150.00%" are scanned; matches > THRESHOLD_PCT trigger failure.

set -euo pipefail

FILE="${1:-bench/diff.txt}"
THRESHOLD="${2:-${THRESHOLD_PCT:-100}}"

if [ ! -f "$FILE" ]; then
    echo "check_bench_regression: $FILE not found" >&2
    exit 2
fi

# Extract every "+NN.NN%" change (positive = slower) from benchstat
# output and bail if any exceeds THRESHOLD.
worst=0
while IFS= read -r pct; do
    pct_int=$(printf '%.0f' "$pct")
    if [ "$pct_int" -gt "$worst" ]; then
        worst="$pct_int"
    fi
done < <(grep -oE '\+[0-9]+\.[0-9]+%' "$FILE" | tr -d '+%' || true)

echo "check_bench_regression: worst regression observed = ${worst}%"
echo "check_bench_regression: threshold = ${THRESHOLD}%"
if [ "$worst" -gt "$THRESHOLD" ]; then
    echo "FAIL: benchmark regressed by more than ${THRESHOLD}%" >&2
    exit 1
fi
echo "OK: no benchmark regressed beyond threshold."
