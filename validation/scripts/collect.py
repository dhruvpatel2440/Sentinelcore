#!/usr/bin/env python3
"""U08 §6.3 — collector.

Logs in through `/api/auth/login`, and for each run window recorded by
`run_attacks.sh` (`validation/runs/<attack>.jsonl`) queries `/api/events`,
`/api/incidents`, and `/api/correlation/candidates`, then writes
`validation/out/<attack>-<run>.json` with: counts of raw alerts, incidents,
first-alert latency, severities seen, and signature names.

Every list endpoint here is paged with the platform's own keyset cursor
(`next_cursor`/`has_more`) — no `OFFSET`-style unbounded page, and a hard
ceiling (`MAX_ITEMS`) stops the collector even if a window is pathologically
large. Does not modify platform code or state — read-only GETs plus the one
POST /auth/login every run needs anyway.

Usage:
    python3 collect.py --runs-dir ../runs --out-dir ../out \\
        [--base-url http://localhost/api] [--username t_admin] [--password ...]

Credentials default to the SENTINELCORE_USER / SENTINELCORE_PASSWORD env
vars so they never need to appear on a command line/shell history.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

PAGE_LIMIT = 500
MAX_ITEMS = 200_000  # a hard ceiling — never truly unbounded, even on a huge window
DEFAULT_STATUSES = ["new", "triage", "investigating", "contained", "resolved", "false_positive"]


def _request(base_url: str, method: str, path: str, *, token: str | None = None, body: dict | None = None):
    url = f"{base_url}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        raise RuntimeError(f"{method} {path} -> {exc.code}: {detail}") from exc


def login(base_url: str, username: str, password: str) -> str:
    result = _request(base_url, "POST", "/auth/login", body={"username": username, "password": password})
    return result["access_token"]


def paginate_events(base_url: str, token: str, from_ts: str, to_ts: str) -> list[dict]:
    items: list[dict] = []
    cursor = None
    while True:
        params = {"from": from_ts, "to": to_ts, "limit": PAGE_LIMIT, "sort": "ts_asc"}
        if cursor:
            params["cursor"] = cursor
        page = _request(base_url, "GET", f"/events?{urlencode(params)}", token=token)
        items.extend(page["items"])
        if not page.get("has_more") or not page.get("next_cursor") or len(items) >= MAX_ITEMS:
            break
        cursor = page["next_cursor"]
    return items


def paginate_incidents(base_url: str, token: str, from_ts: str, to_ts: str) -> list[dict]:
    items: list[dict] = []
    cursor = None
    while True:
        params = [("from", from_ts), ("to", to_ts), ("limit", PAGE_LIMIT), ("sort", "opened_at"), ("order", "asc")]
        for s in DEFAULT_STATUSES:
            params.append(("status", s))
        if cursor:
            params.append(("cursor", cursor))
        page = _request(base_url, "GET", f"/incidents?{urlencode(params)}", token=token)
        items.extend(page["items"])
        if not page.get("has_more") or not page.get("next_cursor") or len(items) >= MAX_ITEMS:
            break
        cursor = page["next_cursor"]
    return items


def fetch_candidates(base_url: str, token: str, from_ts: str, to_ts: str) -> list[dict]:
    """Offset-paged (the endpoint has no keyset cursor), but still bounded:
    the time window plus MAX_ITEMS keep this from ever running away."""
    items: list[dict] = []
    offset = 0
    while True:
        params = {"from": from_ts, "to": to_ts, "limit": PAGE_LIMIT, "offset": offset}
        page = _request(base_url, "GET", f"/correlation/candidates?{urlencode(params)}", token=token)
        if not page:
            break
        items.extend(page)
        if len(page) < PAGE_LIMIT or len(items) >= MAX_ITEMS:
            break
        offset += PAGE_LIMIT
    return items


def _first_alert_latency_seconds(attack_start: str, events: list[dict]) -> float | None:
    if not events:
        return None
    start = datetime.fromisoformat(attack_start.replace("Z", "+00:00"))
    first_ts = min(datetime.fromisoformat(e["ts"].replace("Z", "+00:00")) for e in events)
    return (first_ts - start).total_seconds()


def collect_run(base_url: str, token: str, run: dict) -> dict:
    events = paginate_events(base_url, token, run["start_ts"], run["end_ts"])
    incidents = paginate_incidents(base_url, token, run["start_ts"], run["end_ts"])
    candidates = fetch_candidates(base_url, token, run["start_ts"], run["end_ts"])

    severities = Counter(e["severity"] for e in events)
    signatures = Counter(e["signature"] for e in events if e.get("signature"))

    return {
        "attack_id": run["attack_id"],
        "run_no": run["run_no"],
        "start_ts": run["start_ts"],
        "end_ts": run["end_ts"],
        "target": run.get("target"),
        "raw_alert_count": len(events),
        "incident_count": len(incidents),
        "candidate_count": len(candidates),
        "first_alert_latency_seconds": _first_alert_latency_seconds(run["start_ts"], events),
        "severities": dict(severities),
        "top_signatures": signatures.most_common(10),
        "incident_ids": [i["id"] for i in incidents],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", default="validation/runs")
    parser.add_argument("--out-dir", default="validation/out")
    parser.add_argument("--base-url", default=os.environ.get("SENTINELCORE_BASE_URL", "http://localhost/api"))
    parser.add_argument("--username", default=os.environ.get("SENTINELCORE_USER"))
    parser.add_argument("--password", default=os.environ.get("SENTINELCORE_PASSWORD"))
    args = parser.parse_args()

    if not args.username or not args.password:
        print("SENTINELCORE_USER / SENTINELCORE_PASSWORD (or --username/--password) are required", file=sys.stderr)
        return 1

    runs_dir = Path(args.runs_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    token = login(args.base_url, args.username, args.password)

    run_files = sorted(runs_dir.glob("*.jsonl"))
    if not run_files:
        print(f"no run files found in {runs_dir}", file=sys.stderr)
        return 1

    total = 0
    for run_file in run_files:
        for line in run_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            run = json.loads(line)
            result = collect_run(args.base_url, token, run)
            out_path = out_dir / f"{run['attack_id']}-{run['run_no']}.json"
            out_path.write_text(json.dumps(result, indent=2))
            print(f"wrote {out_path}")
            total += 1

    print(f"collected {total} run(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
