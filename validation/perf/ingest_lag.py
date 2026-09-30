#!/usr/bin/env python3
"""U09 §4.3 — pushes N synthetic EVE-format records/s onto the Redis stream
(same shape and stream key the real M5 pipeline consumes — see
`scripts/e2e_test.py::test_m5_pipeline`), then polls the DB until each
appears, recording ingestion lag. Also samples stream length and pending
count while pushing.

Refuses to run against anything but a stack whose environment has
`ENV=lab` set — this pushes thousands of synthetic alert rows and is not
something to run against a real deployment by accident.

    ENV=lab python3 ingest_lag.py --rate 500 --duration 30 \\
        --redis-url redis://localhost:6379/0 \\
        --database-url postgresql://sentinelcore:...@localhost:5433/sentinelcore

Run from the host against the loopback-published Postgres port, or inside
the backend/worker container where both URLs are already in the environment.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

STREAM_KEY = "stream:events"
GROUP_NAME = "events-writer"


def require_lab_env() -> None:
    if os.environ.get("ENV") != "lab":
        print(
            f"Refusing to run: this pushes synthetic events onto the live pipeline. "
            f"Set ENV=lab to confirm this is a lab stack (got ENV={os.environ.get('ENV')!r}).",
            file=sys.stderr,
        )
        raise SystemExit(1)


def build_eve_record(marker: str, seq: int) -> dict:
    ts = datetime.now(timezone.utc)
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "event_type": "alert",
        "src_ip": "203.0.113.9",
        "dest_ip": "198.51.100.9",
        "src_port": 40000 + (seq % 20000),
        "dest_port": 80,
        "proto": "TCP",
        "flow_id": 900_000_000 + seq,
        "alert": {
            "signature": f"PERFTEST {marker}",
            "signature_id": 9_500_000 + (seq % 400_000),
            "rev": 1,
            "category": "perf-test",
            "severity": 3,
        },
    }


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * pct
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def lag_stats(sent_at: dict[str, float], seen_at: dict[str, float]) -> dict:
    """Pure function over two marker->epoch-seconds maps — unit-tested
    directly with fixture dicts, no Redis/Postgres involved."""
    lags = [seen_at[m] - sent for m, sent in sent_at.items() if m in seen_at]
    missing = len(sent_at) - len(lags)
    return {
        "sent": len(sent_at),
        "seen": len(lags),
        "missing": missing,
        "p50_s": _percentile(lags, 0.5),
        "p95_s": _percentile(lags, 0.95),
        "max_s": max(lags) if lags else None,
    }


async def push_records(redis, rate_per_sec: int, duration_s: int, marker_prefix: str, sample_stream) -> dict[str, float]:
    sent_at: dict[str, float] = {}
    seq = 0
    interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0
    end = time.monotonic() + duration_s
    next_sample = time.monotonic()

    while time.monotonic() < end:
        marker = f"{marker_prefix}-{seq}"
        rec = build_eve_record(marker, seq)
        sent_at[marker] = time.time()
        await redis.xadd(STREAM_KEY, {"record": json.dumps(rec)}, maxlen=500_000, approximate=True)
        seq += 1

        if time.monotonic() >= next_sample:
            await sample_stream(redis)
            next_sample = time.monotonic() + 5

        if interval:
            await asyncio.sleep(interval)

    return sent_at


async def poll_db(conn, markers: set[str], timeout_s: int) -> dict[str, float]:
    seen_at: dict[str, float] = {}
    remaining = set(markers)
    deadline = time.monotonic() + timeout_s

    while remaining and time.monotonic() < deadline:
        signatures = [f"PERFTEST {m}" for m in remaining]
        rows = await conn.fetch("SELECT signature FROM events WHERE signature = ANY($1::text[])", signatures)
        now = time.time()
        for row in rows:
            sig = row["signature"]
            marker = sig[len("PERFTEST ") :]
            if marker in remaining:
                seen_at[marker] = now
                remaining.discard(marker)
        if remaining:
            await asyncio.sleep(0.5)

    return seen_at


async def run(args) -> dict:
    import asyncpg
    import redis.asyncio as aioredis

    redis = aioredis.from_url(args.redis_url, decode_responses=False)
    stream_samples: list[dict] = []

    async def sample_stream(r):
        length = await r.xlen(STREAM_KEY)
        try:
            pending = await r.xpending(STREAM_KEY, GROUP_NAME)
            pending_count = pending.get("pending", 0) if isinstance(pending, dict) else 0
        except Exception:
            pending_count = None
        stream_samples.append({"t": time.time(), "stream_length": length, "pending": pending_count})

    marker_prefix = uuid.uuid4().hex[:8]
    sent_at = await push_records(redis, args.rate, args.duration, marker_prefix, sample_stream)

    dsn = args.database_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(dsn)
    try:
        seen_at = await poll_db(conn, set(sent_at.keys()), args.poll_timeout)
    finally:
        await conn.close()
    await redis.aclose()

    stats = lag_stats(sent_at, seen_at)
    stats["stream_samples"] = stream_samples
    stats["rate_per_sec"] = args.rate
    stats["duration_s"] = args.duration
    return stats


def main() -> int:
    require_lab_env()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rate", type=int, default=100, help="synthetic events/s")
    parser.add_argument("--duration", type=int, default=30, help="seconds to push for")
    parser.add_argument("--poll-timeout", type=int, default=120, help="max seconds to wait for the last record to land")
    parser.add_argument("--redis-url", default=os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument("--out", default="ingest_lag.json")
    args = parser.parse_args()

    if not args.database_url:
        print("--database-url or DATABASE_URL is required", file=sys.stderr)
        return 1

    result = asyncio.run(run(args))
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
