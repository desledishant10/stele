#!/usr/bin/env python3
"""pilot/git_watcher.py — scan known repos and log new commits.

This is the pilot's only producer. It dogfoods the stele Python SDK
on the user's own git history. Each scan iteration:

  1. Discover .git directories under PILOT_WATCH_ROOTS (depth-limited
     so we never walk all of $HOME).
  2. For each repo, ``git log`` since the last seen commit per branch
     (state persisted in $PILOT_DATA_DIR/watcher/state.json).
  3. For each new commit, build an envelope describing the commit
     (oid, author, date, subject, repo, branch) and submit via the
     Producer SDK.
  4. Persist new state ONLY after a successful submit, so a transient
     failure causes us to re-attempt on the next run.

The launchd plist invokes this every PILOT_SCAN_INTERVAL seconds with
PILOT_CONFIG pointing at pilot/config.sh. Failures here do NOT crash
launchd; we log them to stderr (which goes to watcher.err).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


# ---------- config plumbing ----------

def _read_config(path: Path) -> Dict[str, str]:
    """Source a bash-style 'KEY="value"' config and return a dict.

    We don't actually invoke bash because launchd may strip PATH; we
    parse the small whitelist of keys we care about directly.
    """
    out: Dict[str, str] = {}
    pat = re.compile(r'^([A-Z_][A-Z0-9_]*)\s*=\s*"?\$\{\1:-(.*?)\}"?\s*$')
    plain = re.compile(r'^([A-Z_][A-Z0-9_]*)\s*=\s*"?(.*?)"?\s*$')
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = pat.match(line) or plain.match(line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        # Resolve $HOME and command substitutions we know about.
        val = val.replace("$HOME", os.environ.get("HOME", ""))
        # Skip lines we can't statically resolve (command substitutions).
        if "$(" in val:
            continue
        out[key] = val
    return out


def _resolve(cfg: Dict[str, str], key: str, default: str) -> str:
    return os.environ.get(key, cfg.get(key, default))


# ---------- repo discovery ----------

def _split_list(raw: str) -> List[str]:
    """Split a colon-or-newline-separated string, drop empties."""
    parts: List[str] = []
    for chunk in raw.replace("\n", ":").split(":"):
        chunk = chunk.strip()
        if chunk:
            parts.append(chunk)
    return parts


def discover_repos(
    roots: Iterable[str],
    skip_patterns: Iterable[str],
    max_depth: int = 4,
) -> List[Path]:
    """Return absolute paths of every .git dir under roots, depth-limited.

    A 'repo' is the parent directory of a `.git/` entry (whether dir
    or, for worktrees, a regular file). We deduplicate.
    """
    skip = [s.strip() for s in skip_patterns if s.strip()]
    seen: set = set()
    repos: List[Path] = []
    for root in roots:
        root_path = Path(root).expanduser()
        if not root_path.exists():
            continue
        for path in _walk(root_path, max_depth):
            if path.name != ".git":
                continue
            repo = path.parent.resolve()
            if any(s in str(repo) for s in skip):
                continue
            if repo in seen:
                continue
            seen.add(repo)
            repos.append(repo)
    repos.sort()
    return repos


def _walk(root: Path, max_depth: int) -> Iterable[Path]:
    """Bounded-depth walk. Yields .git entries (dirs or files)."""
    stack: List[Tuple[Path, int]] = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        try:
            entries = list(cur.iterdir())
        except (PermissionError, OSError):
            continue
        for entry in entries:
            try:
                if entry.name == ".git":
                    yield entry
                    # Don't descend into a found repo; .git/objects is huge.
                    continue
                if entry.is_dir() and not entry.is_symlink() and depth < max_depth:
                    stack.append((entry, depth + 1))
            except OSError:
                continue


# ---------- git plumbing ----------

def _git(repo: Path, *args: str) -> str:
    """Run a git command in `repo` and return stdout (str). Errors → ''."""
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""
    return out.stdout


def list_branches(repo: Path) -> List[str]:
    """List local branches in `repo`. Skips detached HEAD."""
    raw = _git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads/")
    return [b.strip() for b in raw.splitlines() if b.strip()]


def new_commits(repo: Path, branch: str, since_oid: Optional[str]) -> List[Dict[str, str]]:
    """Return commits on `branch` newer than `since_oid` (exclusive).

    If since_oid is None, return only the HEAD commit (we don't want
    the FIRST run to dump every commit you've ever made — we want a
    clean "from now forward" baseline).
    """
    if since_oid is None:
        rev_arg = f"{branch} -1"
    else:
        rev_arg = f"{since_oid}..{branch}"

    fmt = "%H%x1f%an%x1f%ae%x1f%aI%x1f%s"
    raw = _git(
        repo, "log", *shlex.split(rev_arg),
        f"--pretty=format:{fmt}",
    )
    commits: List[Dict[str, str]] = []
    for line in raw.splitlines():
        parts = line.split("\x1f")
        if len(parts) != 5:
            continue
        commits.append({
            "oid": parts[0],
            "author_name": parts[1],
            "author_email": parts[2],
            "author_date": parts[3],
            "subject": parts[4],
        })
    # Reverse so oldest-first; we want to submit them in commit order.
    commits.reverse()
    return commits


# ---------- state ----------

def load_state(path: Path) -> Dict[str, Dict[str, str]]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(path: Path, state: Dict[str, Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    tmp.replace(path)


# ---------- main scan ----------

def scan(cfg: Dict[str, str]) -> int:
    """Returns 0 on success (even if no commits logged), nonzero on error."""
    data_dir = Path(_resolve(cfg, "PILOT_DATA_DIR", os.path.expanduser("~/.stele-pilot")))
    state_path = data_dir / "watcher" / "state.json"
    state = load_state(state_path)

    roots = _split_list(_resolve(cfg, "PILOT_WATCH_ROOTS", os.path.expanduser("~/Projects")))
    skips = _split_list(_resolve(cfg, "PILOT_SKIP_PATTERNS", "node_modules:vendor_imports:.venv"))
    repos = discover_repos(roots, skips)
    print(f"[watcher] found {len(repos)} repos under {len(roots)} roots", flush=True)

    operator_addr = _resolve(cfg, "PILOT_OPERATOR_ADDR", "127.0.0.1:18080")
    producer_id = _resolve(cfg, "PILOT_PRODUCER_ID", "git-watcher")
    keyfile = data_dir / "producer" / f"{producer_id}.priv"
    if not keyfile.exists():
        print(f"[watcher] FATAL: producer key not found at {keyfile}; run pilot/setup.sh first", file=sys.stderr)
        return 2

    # Lazy-import the SDK so this script can at least discover repos
    # under `python3 git_watcher.py --dry-run` even without the SDK.
    from stele import Producer, PrivateKey  # type: ignore

    priv = PrivateKey.from_file(str(keyfile))
    producer = Producer(
        id=producer_id,
        private_key=priv,
        server=f"http://{operator_addr}",
    )

    total_logged = 0
    for repo in repos:
        repo_key = str(repo)
        repo_state = state.setdefault(repo_key, {})
        for branch in list_branches(repo):
            since = repo_state.get(branch)
            commits = new_commits(repo, branch, since)
            if not commits:
                # First-time: anchor the current HEAD without logging
                # everything historical. Subsequent runs will pick up
                # only commits made after this baseline.
                if since is None:
                    head = _git(repo, "rev-parse", branch).strip()
                    if head:
                        repo_state[branch] = head
                continue

            for commit in commits:
                payload = {
                    "repo": repo.name,
                    "repo_path": str(repo),
                    "branch": branch,
                    **commit,
                }
                data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
                try:
                    resp = producer.log(
                        source=f"git-commit:{repo.name}:{branch}",
                        data=data,
                    )
                    idx = resp["entry"]["index"]
                    print(
                        f"[watcher] logged {repo.name}@{branch} {commit['oid'][:8]} "
                        f"\"{commit['subject'][:60]}\" → entry {idx}",
                        flush=True,
                    )
                    repo_state[branch] = commit["oid"]
                    total_logged += 1
                except Exception as exc:  # noqa: BLE001
                    print(
                        f"[watcher] FAILED to log {repo.name}@{branch} {commit['oid'][:8]}: {exc}",
                        file=sys.stderr,
                    )
                    # Don't advance state on failure; we'll retry next tick.
                    break

    save_state(state_path, state)
    print(f"[watcher] scan complete: {total_logged} new commit(s) logged", flush=True)
    return 0


def main() -> int:
    config_path = Path(os.environ.get("PILOT_CONFIG", ""))
    if not config_path or not config_path.exists():
        # Fall back to config.example.sh next to this script.
        config_path = Path(__file__).resolve().parent / "config.example.sh"
    cfg = _read_config(config_path)
    print(f"[watcher] config: {config_path} (loaded {len(cfg)} keys) at {time.strftime('%FT%TZ', time.gmtime())}", flush=True)
    try:
        return scan(cfg)
    except Exception as exc:  # noqa: BLE001
        print(f"[watcher] fatal: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
