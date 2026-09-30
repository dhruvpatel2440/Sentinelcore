#!/usr/bin/env python3
"""U09 §4.4 — authenticates once, then hits a fixed list of read endpoints
with N concurrent users for T seconds. Outputs p50/p95/p99 latency and the
error rate. Stdlib only (urllib + threads) — no new HTTP client dependency
for a one-off measurement script.

    python3 api_load.py --base-url http://localhost/api --users 20 --duration 60 \\
        --username t_admin --password ...
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

DEFAULT_ENDPOINTS = [
    "/events?limit=50",
    "/events/facets",
    "/incidents?limit=50",
    "/stats/top-talkers?window=24h&limit=10",
]


def _request(base_url: str, path: str, token: str) -> tuple[int, float]:
    url = f"{base_url}{path}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        exc.read()
        status = exc.code
    except urllib.error.URLError:
        status = 0
    return status, time.monotonic() - start


def login(base_url: str, username: str, password: str) -> str:
    url = f"{base_url}/auth/login"
    body = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["access_token"]


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * pct
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def compute_latency_stats(results: list[tuple[int, float]]) -> dict:
    """Pure aggregation over (status, latency_seconds) pairs — the unit
    tests exercise this directly with fixture tuples, no network involved."""
    if not results:
        return {"count": 0, "error_rate": None, "p50_ms": None, "p95_ms": None, "p99_ms": None}

    latencies_ms = [lat * 1000 for _, lat in results]
    errors = sum(1 for status, _ in results if status == 0 or status >= 400)
    return {
        "count": len(results),
        "error_rate": errors / len(results),
        "p50_ms": _percentile(latencies_ms, 0.50),
        "p95_ms": _percentile(latencies_ms, 0.95),
        "p99_ms": _percentile(latencies_ms, 0.99),
    }


def _worker(base_url: str, token: str, endpoints: list[str], end_at: float, results: list, lock: threading.Lock) -> None:
    local: list[tuple[int, float]] = []
    i = 0
    while time.monotonic() < end_at:
        path = endpoints[i % len(endpoints)]
        local.append(_request(base_url, path, token))
        i += 1
    with lock:
        results.extend(local)


def run_load(base_url: str, token: str, endpoints: list[str], users: int, duration_s: int) -> list[tuple[int, float]]:
    results: list[tuple[int, float]] = []
    lock = threading.Lock()
    end_at = time.monotonic() + duration_s
    threads = [
        threading.Thread(target=_worker, args=(base_url, token, endpoints, end_at, results, lock))
        for _ in range(users)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("SENTINELCORE_BASE_URL", "http://localhost/api"))
    parser.add_argument("--username", default=os.environ.get("SENTINELCORE_USER"))
    parser.add_argument("--password", default=os.environ.get("SENTINELCORE_PASSWORD"))
    parser.add_argument("--users", type=int, default=20)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--endpoint", action="append", dest="endpoints", default=None)
    parser.add_argument("--out", default="api_load.json")
    args = parser.parse_args()

    if not args.username or not args.password:
        print("--username/--password or SENTINELCORE_USER/SENTINELCORE_PASSWORD required", file=sys.stderr)
        return 1

    endpoints = args.endpoints or DEFAULT_ENDPOINTS
    token = login(args.base_url, args.username, args.password)
    results = run_load(args.base_url, token, endpoints, args.users, args.duration)
    stats = compute_latency_stats(results)
    stats["users"] = args.users
    stats["duration_s"] = args.duration
    stats["endpoints"] = endpoints

    with open(args.out, "w") as f:
        json.dump(stats, f, indent=2)
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
