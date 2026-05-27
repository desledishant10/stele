# pilot/config.example.sh — pilot configuration. Copy to config.sh and
# edit before running setup.sh.
#
# This file is sourced by every pilot/ script. Restart of any
# launchd service is required after edits.

# ----------------------------------------------------------------------
# Stele binaries (built into ./bin/ by `make build`).
PILOT_BIN_DIR="${PILOT_BIN_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin}"

# Data dir for the pilot (kept OUT of $HOME root to avoid backup tools).
PILOT_DATA_DIR="${PILOT_DATA_DIR:-$HOME/.stele-pilot}"

# Network — bind to loopback only; the pilot is local.
PILOT_OPERATOR_ADDR="${PILOT_OPERATOR_ADDR:-127.0.0.1:18080}"
PILOT_WITNESS_ADDR="${PILOT_WITNESS_ADDR:-127.0.0.1:19090}"

# Log identity — shows up in audits + the trust anchor.
PILOT_ORIGIN="${PILOT_ORIGIN:-pilot.local/git-commits}"

# Producer identity for the git-watcher.
PILOT_PRODUCER_ID="${PILOT_PRODUCER_ID:-git-watcher}"

# How often the watcher scans for new commits (seconds). 1800 = 30 min.
PILOT_SCAN_INTERVAL="${PILOT_SCAN_INTERVAL:-1800}"

# Roots to scan. Recursive depth-limited search for .git dirs under each.
# Edit these. Comma- or newline-separated.
PILOT_WATCH_ROOTS="${PILOT_WATCH_ROOTS:-$HOME/Projects:$HOME/Documents/GitHub:$HOME/portfolio:$HOME/computer_security_fall_2025:$HOME/networking_fall_2025_didesle}"

# Substrings to skip when scanning (matched against the .git's parent path).
PILOT_SKIP_PATTERNS="${PILOT_SKIP_PATTERNS:-node_modules:vendor_imports:.venv:Library/:.Trash:.codex}"

# Python venv with the SDK installed (defaults to the SDK's own venv).
PILOT_PYTHON="${PILOT_PYTHON:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sdk/python/.venv/bin/python}"
