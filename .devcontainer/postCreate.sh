#!/usr/bin/env bash
# postCreate.sh — runs once when a GitHub Codespace / devcontainer
# is first opened. Builds the Go binaries, installs the Python +
# TypeScript SDKs, prints how to try stele in 60 seconds.

set -euo pipefail

# Make output a bit nicer.
say() {
    printf "\n\033[1;36m==>\033[0m %s\n" "$*"
}

cd "$(dirname "$0")/.."

say "Building Go binaries into ./bin/"
make build > /dev/null

say "Installing Python SDK (incl. test deps)"
cd sdk/python
python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip setuptools wheel
.venv/bin/pip install --quiet -e '.[test]'
cd ../..

say "Installing + building TypeScript SDK"
cd sdk/typescript
npm install --silent
npm run build > /dev/null
cd ../..

say "Done!"

cat <<'EOF'

┌─────────────────────────────────────────────────────────────────┐
│  Stele Codespace ready                                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Try the demo in 60 seconds:                                    │
│                                                                 │
│    .devcontainer/try-stele.sh                                   │
│                                                                 │
│  Or step through it manually:                                   │
│                                                                 │
│    # 1. Run an operator on :8080                                │
│    ./bin/steled --addr :8080 --dir /tmp/stele-demo \            │
│        --origin demo.local/log --init \                         │
│        --checkpoint-every 5s --anchor-every 5s --beacon '' &    │
│                                                                 │
│    # 2. Enroll a producer (proof-of-possession)                 │
│    ./bin/stele producer-init --id alice --out /tmp/alice.priv   │
│    ./bin/stele enroll-producer --server http://localhost:8080 \ │
│        --id alice --key /tmp/alice.priv --scope demo            │
│                                                                 │
│    # 3. Log entries                                             │
│    ./bin/stele log --server http://localhost:8080 \             │
│        --producer alice --key /tmp/alice.priv \                 │
│        --source codespace "hello stele"                         │
│                                                                 │
│    # 4. Audit                                                   │
│    ./bin/stele audit --server http://localhost:8080 \           │
│        --pdf /tmp/audit.pdf --sample-n 5                        │
│                                                                 │
│  Documentation:                                                 │
│    PLAYBOOK.md       — full operator manual                     │
│    ADOPTING.md       — 90-day adoption playbook                 │
│    deploy/QUICKSTART.md — three production deployment paths     │
│    sdk/python/README.md, sdk/typescript/README.md               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

EOF
