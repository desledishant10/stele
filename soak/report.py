#!/usr/bin/env python3
"""report.py — turn a 72-hour soak's timeline.ndjson + loadgen-final.json
into a Markdown report suitable for committing into SOAK-72H.md.

Usage:
    scp soak-vm:/var/lib/stele-soak/timeline.ndjson .
    scp soak-vm:/var/lib/stele-soak/loadgen-final.json .
    python3 soak/report.py timeline.ndjson loadgen-final.json > SOAK-72H.md
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path


METRICS_TO_PARSE = {
    "stele_tree_size": "tree_size",
    "stele_active_epoch": "active_epoch",
    "stele_appends_total": "appends_total",
    "stele_tripwire_runs_total": "tripwire_runs",
    "stele_honeypots_total": "honeypots_total",
    "stele_checkpoints_total": "checkpoints_total",
    "stele_rotations_total": "rotations_total",
}


def parse_metrics_line(line: str) -> tuple[str | None, dict | None, float | None]:
    """Parse one Prometheus exposition line. Returns (metric, labels, value)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None, None, None
    # name{labels} value  OR  name value
    m = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(\{[^}]*\})?\s+([-+0-9.eE]+|NaN|\+Inf|-Inf)$", line)
    if not m:
        return None, None, None
    name = m.group(1)
    labels_raw = m.group(2)
    value = m.group(3)
    labels = {}
    if labels_raw:
        for kv in labels_raw[1:-1].split(","):
            if "=" in kv:
                k, v = kv.split("=", 1)
                labels[k.strip()] = v.strip().strip('"')
    try:
        v = float(value)
    except ValueError:
        v = float("nan")
    return name, labels, v


def parse_snapshot(snap: dict) -> dict:
    """Reduce a snapshot's raw Prometheus metrics into a flat dict."""
    out = {
        "ts": snap["ts"],
        "ts_unix": int(datetime.fromisoformat(snap["ts"].rstrip("Z")).timestamp()),
        "readyz_code": snap["readyz_code"],
        "operator_rss_mb": snap["operator_rss_kb"] / 1024 if snap["operator_rss_kb"] else 0,
        "operator_cpu_pct": snap["operator_cpu_pct"],
        "loadgen_running": snap["loadgen_running"],
    }
    counters = {k: 0 for k in METRICS_TO_PARSE.values()}
    counters["appends_ok"] = 0
    counters["appends_error"] = 0
    counters["tripwire_tamper"] = 0
    for line in snap.get("metrics", []):
        name, labels, value = parse_metrics_line(line)
        if name is None:
            continue
        if name == "stele_appends_total":
            outcome = labels.get("outcome", "")
            if outcome == "ok":
                counters["appends_ok"] = int(value)
            elif outcome == "error":
                counters["appends_error"] = int(value)
        elif name == "stele_tripwire_runs_total":
            outcome = labels.get("outcome", "")
            if outcome == "tamper":
                counters["tripwire_tamper"] = int(value)
        elif name in METRICS_TO_PARSE and not labels:
            counters[METRICS_TO_PARSE[name]] = int(value)
    out.update(counters)
    return out


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} timeline.ndjson loadgen-final.json", file=sys.stderr)
        return 2

    timeline_path = Path(sys.argv[1])
    loadgen_path = Path(sys.argv[2])

    snaps = []
    for line in timeline_path.read_text().splitlines():
        if not line.strip():
            continue
        snaps.append(parse_snapshot(json.loads(line)))

    if not snaps:
        print("ERROR: no snapshots in timeline.ndjson", file=sys.stderr)
        return 1

    first = snaps[0]
    last = snaps[-1]
    duration_h = (last["ts_unix"] - first["ts_unix"]) / 3600

    loadgen = json.loads(loadgen_path.read_text()) if loadgen_path.exists() else {}
    outcomes = loadgen.get("outcomes", {})
    achieved_rps = (
        outcomes.get("ok", {}).get("count", 0)
        / (loadgen.get("duration_ns", 1) / 1e9)
        if loadgen
        else 0
    )

    # Report.
    print(f"# Stele 72-hour soak report — {first['ts']} → {last['ts']}")
    print()
    print("## Configuration")
    print()
    if loadgen:
        print(f"- Target RPS: {loadgen.get('target_rps')}")
        print(f"- Producers: {loadgen.get('producers')}")
        print(f"- Payload: {loadgen.get('payload_bytes')} B")
        print(f"- Duration: {loadgen.get('duration_ns', 0) / 3600e9:.2f} hours wall clock")
    print(f"- Snapshots captured: {len(snaps)} (every 30 min by default)")
    print()
    print("## Headline results")
    print()
    print(f"| Metric | Value |")
    print(f"|---|---|")
    print(f"| Total appends accepted | **{last['appends_ok']:,}** |")
    print(f"| Append errors | {last['appends_error']:,} |")
    print(f"| Honeypot triggers | {last['honeypots_total']} |")
    print(f"| Tripwire `outcome=tamper` events | {last['tripwire_tamper']} |")
    print(f"| Checkpoints signed | {last['checkpoints_total']:,} |")
    print(f"| Operator rotations | {last['rotations_total']} |")
    print(f"| Achieved RPS (avg) | {achieved_rps:.1f} |")
    print(f"| Operator RSS at start | {first['operator_rss_mb']:.1f} MiB |")
    print(f"| Operator RSS at end | {last['operator_rss_mb']:.1f} MiB |")
    print(f"| Memory growth | {(last['operator_rss_mb'] - first['operator_rss_mb']):.1f} MiB over {duration_h:.1f} h |")
    print()
    print("## Stability signals")
    print()
    not_ready = [s for s in snaps if s["readyz_code"] != 200]
    if not_ready:
        print(f"### `/readyz` was NOT 200 in {len(not_ready)} snapshots")
        for s in not_ready[:5]:
            print(f"  - {s['ts']}: code={s['readyz_code']}")
    else:
        print(f"`/readyz` returned 200 in every snapshot ({len(snaps)} samples).")
    print()

    if last["tripwire_tamper"] > 0:
        print("**!!! TRIPWIRE FIRED !!! — this is a critical soak finding.**")
        print()

    if last["honeypots_total"] > 0:
        print(f"**Honeypot triggered {last['honeypots_total']}× — investigate.**")
        print()

    # Memory growth chart (text).
    print("## Memory growth over time")
    print()
    print("```")
    print(f"{'Time':<22} {'RSS (MiB)':>10}  {'Tree size':>11}")
    for s in snaps:
        print(f"{s['ts']:<22} {s['operator_rss_mb']:>10.1f}  {s['tree_size']:>11,}")
    print("```")
    print()
    print("## Loadgen latency percentiles (final)")
    print()
    if outcomes:
        for o, stats in outcomes.items():
            if isinstance(stats, dict) and "p50_ns" in stats:
                print(f"- `{o}`: count={stats['count']:,} p50={stats['p50_ns'] / 1e6:.1f}ms p99={stats['p99_ns'] / 1e6:.1f}ms p99.9={stats['p999_ns'] / 1e6:.1f}ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
