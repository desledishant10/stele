# Pilot — dogfood stele on your own git commits

This directory contains everything needed to run stele locally on
macOS as a personal pilot. The producer is a small Python script that
scans your local repos every 30 minutes and logs new commits via the
stele Python SDK. The operator runs as a launchd agent on the
loopback interface; one witness countersigns checkpoints. At end of
week, one command produces an audit PDF.

**Why this exists.** The "first adopter is the author" rule: before
shipping stele to anyone else, run it for a week on your own data.
Anything that hurts here would have hurt every future adopter.

## What you get

```
~/.stele-pilot/
├── operator/              # steled BadgerDB + hash chain + Merkle tree
├── witness/               # witness state + cosignature log
├── producer/git-watcher.priv  (mode 600)
├── watcher/state.json     # last-seen commit per (repo, branch)
├── reviews/<timestamp>/   # audit.pdf + audit.txt for each review
└── logs/                  # operator.log, witness.log, watcher.log
```

Three launchd agents:

| Label | Purpose | Cadence |
|---|---|---|
| `com.stele.pilot.operator` | `steled` on 127.0.0.1:18080 | always-on |
| `com.stele.pilot.witness`  | `stele-witness` on 127.0.0.1:19090 | always-on |
| `com.stele.pilot.watcher`  | scans repos, logs new commits | every 30 min |

## Quick start

```sh
# 1. (optional) personalise paths and watch roots
cp pilot/config.example.sh pilot/config.sh
$EDITOR pilot/config.sh

# 2. one-shot bootstrap (idempotent — safe to re-run)
pilot/setup.sh

# 3. check it's healthy
pilot/status.sh

# 4. trigger a scan right now instead of waiting 30 minutes
launchctl kickstart -k "gui/$(id -u)/com.stele.pilot.watcher"

# 5. tail the watcher
tail -f ~/.stele-pilot/logs/watcher.log
```

After a few commits land you should see lines like:

```
[watcher] logged stele@main 4a7c... "pilot: enroll producer..." → entry 3
```

## Day-of-week 7: produce the audit report

```sh
pilot/review.sh
```

This runs `stele audit --pdf` against the operator and saves the PDF
under `~/.stele-pilot/reviews/<timestamp>/`. The script will `open(1)`
the PDF if you ran it from an interactive terminal.

A clean review has:
- Audit verdict: PASS
- Inclusion proofs verified for the random sample
- Operator + witness signatures consistent
- No tripwire trips in `operator.log`

## What's actually being protected

For each commit on a watched branch, the watcher submits an envelope
whose `data` is the JSON:

```json
{
  "repo": "stele",
  "repo_path": "/Users/you/Tools/stele",
  "branch": "main",
  "oid": "4a7c...",
  "author_name": "Dishant Desle",
  "author_email": "...",
  "author_date": "2026-05-17T14:23:45-04:00",
  "subject": "pilot: enroll producer + audit PDF"
}
```

The envelope is signed by the watcher's Ed25519 key. The operator
appends it to the hash chain, builds it into the Merkle tree, signs
checkpoints, and pushes them to the witness. The auditor (you, end of
week) can verify any commit's inclusion against the trust anchor that
`pilot/setup.sh` printed at the end.

### What this catches that ordinary `git` doesn't

`git` is already a hash-chain, so why bother? Two reasons:

1. **History rewrites.** `git rebase`, `filter-branch`, or just
   force-pushing over a deleted branch erases history. The stele log
   records what existed at the time it was observed; nobody can
   silently rewrite it later, including you.
2. **Independent witness.** A second process (the witness) cosigned
   each checkpoint and you have a public-key trust anchor. A future
   auditor doesn't have to trust your local git, your filesystem, or
   your account — only the Ed25519 signature chain rooted at that
   anchor.

This isn't a replacement for git; it's a tamper-evident overlay.

## Daily operations

```sh
# health snapshot
pilot/status.sh

# tail the live log
tail -f ~/.stele-pilot/logs/watcher.log

# force a scan without waiting 30 min
launchctl kickstart -k "gui/$(id -u)/com.stele.pilot.watcher"

# look at a specific entry
curl -s http://127.0.0.1:18080/api/v0/entries/42 | jq .

# the trust anchor (give this to an auditor)
./bin/stele pubkey --server http://127.0.0.1:18080
```

## End of pilot

```sh
# generate final report first
pilot/review.sh

# then stop the services (KEEPS data so you can still audit)
pilot/teardown.sh

# OR: stop and wipe everything
pilot/teardown.sh --purge
```

## Anatomy

| File | What it does |
|---|---|
| [`config.example.sh`](config.example.sh) | All tunables; copy to `config.sh` to override |
| [`setup.sh`](setup.sh) | Idempotent bootstrap (binaries, dirs, plists, witness add, producer enrollment) |
| [`git_watcher.py`](git_watcher.py) | The producer — scans `$PILOT_WATCH_ROOTS`, logs new commits |
| [`status.sh`](status.sh) | One-screen health view |
| [`review.sh`](review.sh) | Audit PDF + summary |
| [`teardown.sh`](teardown.sh) | Stop + uninstall (with `--purge` to wipe data) |

## Tuning

Edit `pilot/config.sh` (created on first `setup.sh` run by copying
`config.example.sh`). All scripts source it. After changes:

```sh
pilot/setup.sh         # idempotent — re-renders plists with new values
```

The most common edits:

- `PILOT_WATCH_ROOTS` — colon-separated list of dirs to scan for repos
- `PILOT_SKIP_PATTERNS` — substring filters (skip `node_modules`, etc.)
- `PILOT_SCAN_INTERVAL` — seconds between scans (default 1800 = 30 min)

## Linux notes

This pilot ships only the macOS launchd recipe. The equivalent on
Linux is one systemd `.service` unit per agent + one systemd `.timer`
unit for the watcher. The shell + Python pieces all work unchanged.
We'll add `pilot/linux/` if/when somebody pilots on Linux. PRs welcome.

## Troubleshooting

| Symptom | Check |
|---|---|
| `pilot/setup.sh` says "make build failed" | `make build` standalone — Go installed? `bin/` writeable? |
| `operator never became ready` | `cat ~/.stele-pilot/logs/operator.err` — port collision? perms? |
| `witness-add failed` | `~/.stele-pilot/logs/witness.err` — witness still booting? |
| `FATAL: producer key not found` | re-run `pilot/setup.sh` (idempotent) |
| No commits being logged | `tail -f ~/.stele-pilot/logs/watcher.log`; is the scan finding repos under `PILOT_WATCH_ROOTS`? |
| Watcher fails with `import stele` error | `sdk/python/.venv` got nuked; `pilot/setup.sh` recreates it |

## What this pilot does NOT do

- **No remote witness.** One local witness only. For a real
  deployment, register witnesses on independent infrastructure (a
  different cloud account / region / org). See
  [`PLAYBOOK.md`](../PLAYBOOK.md).
- **No HSM.** The producer key is on disk under your home dir.
- **No anchor-to-Rekor.** `--rekor` is unset; the pilot runs fully
  offline.
- **No threshold cosigning.** A single witness signature gates each
  checkpoint.

All of these are knobs you turn on in
[`ADOPTING.md`](../ADOPTING.md) when you graduate from "pilot" to
"production".
