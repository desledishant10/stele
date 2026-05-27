#!/usr/bin/env bash
# try-stele.sh — the 60-second demo. Runs from a fresh Codespace
# (or any host with the Go binaries built into ./bin/).
#
# Spawns: an operator + a producer + an audit. Cleans up on exit.

set -euo pipefail

cd "$(dirname "$0")/.."

DEMO=/tmp/stele-demo-$$
mkdir -p "$DEMO"

cleanup() {
    if [ -n "${STELED_PID:-}" ]; then
        kill "$STELED_PID" 2>/dev/null || true
    fi
    rm -rf "$DEMO"
}
trap cleanup EXIT

say() {
    printf "\n\033[1;36m==>\033[0m %s\n" "$*"
}

say "1. Starting steled on :8080 (data dir: $DEMO)"
./bin/steled \
    --addr :8080 \
    --dir "$DEMO/data" \
    --origin demo.local/log \
    --init \
    --checkpoint-every 5s \
    --anchor-every 5s \
    --beacon '' \
    --rotate-every 0 \
    --watch-keys=false \
    --watch-rate=false \
    --read-log=false \
    --tripwire-every 0 \
    > "$DEMO/operator.log" 2>&1 &
STELED_PID=$!

# Wait for readiness.
for i in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8080/readyz > /dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
curl -fsS http://127.0.0.1:8080/readyz
echo

say "2. Generating + enrolling a producer 'alice'"
./bin/stele producer-init --id alice --out "$DEMO/alice.priv" > /dev/null
./bin/stele enroll-producer \
    --server http://127.0.0.1:8080 \
    --id alice \
    --key "$DEMO/alice.priv" \
    --scope "demo" \
    --validity 24h \
    | tail -5

say "3. Logging 5 entries"
for i in 1 2 3 4 5; do
    ./bin/stele log \
        --server http://127.0.0.1:8080 \
        --producer alice \
        --key "$DEMO/alice.priv" \
        --source codespace \
        "demo entry $i" | head -1
done

say "4. Forcing a checkpoint"
curl -fsS -X POST http://127.0.0.1:8080/api/v0/checkpoint > /dev/null
echo "  checkpoint signed"

say "5. Running stele audit (text + PDF)"
ROOT=$(curl -fsS http://127.0.0.1:8080/api/v0/pubkey | python3 -c "import sys, json; print(json.load(sys.stdin)['root_public_key'])")
./bin/stele audit \
    --server http://127.0.0.1:8080 \
    --root "$ROOT" --root-source paper \
    --sample-n 3 \
    --pdf "$DEMO/audit.pdf" \
    --json "$DEMO/audit.json"

echo
echo "PDF report: $DEMO/audit.pdf"
ls -la "$DEMO/audit.pdf"
echo
echo "JSON report verdict:"
python3 -c "
import json
d = json.load(open('$DEMO/audit.json'))
print('  status:', d['status'])
print('  size:', d['size'])
print('  chain epochs:', d['chain']['epochs'])
print('  inclusion samples passed:',
      sum(1 for s in d.get('samples', []) if s['verified']),
      '/', len(d.get('samples', [])))
"

say "Demo complete. Read PLAYBOOK.md + ADOPTING.md to go further."
