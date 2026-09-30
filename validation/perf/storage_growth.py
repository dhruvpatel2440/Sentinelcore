#!/usr/bin/env python3
"""U09 §4.5 — records `pg_database_size`, per-partition sizes for the
`events` table, and directory sizes for Suricata logs, PCAP storage, and
report storage, at fixed intervals. Appends one JSON line per sample to
the output file so a run can be left going across the 0/1/6/24h checkpoints
U09 asks for without losing earlier samples if it's interrupted.

    python3 storage_growth.py --database-url postgresql://... \\
        --suricata-logs /var/log/suricata --pcap-dir /var/lib/sentinelcore/pcap \\
        --reports-dir /var/lib/sentinelcore/reports \\
        --duration 86400 --interval 3600 --out storage_growth.jsonl

Run inside the backend or worker container, where all three directories are
already mounted (see docker-compose.yml) and DATABASE_URL is already set.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path


def dir_size_bytes(path: Path) -> int:
    """Pure filesystem walk — unit-tested against a tmp_path fixture tree."""
    if not path.exists():
        return 0
    total = 0
    for entry in path.rglob("*"):
        if entry.is_file() and not entry.is_symlink():
            try:
                total += entry.stat().st_size
            except OSError:
                continue
    return total


async def partition_sizes(conn) -> dict[str, int]:
    rows = await conn.fetch(
        """
        SELECT c.relname AS name, pg_total_relation_size(c.oid) AS bytes
        FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'events'
        ORDER BY c.relname
        """
    )
    return {row["name"]: row["bytes"] for row in rows}


async def sample_once(dsn: str, suricata_logs: Path, pcap_dir: Path, reports_dir: Path) -> dict:
    import asyncpg

    conn = await asyncpg.connect(dsn)
    try:
        db_size = await conn.fetchval("SELECT pg_database_size(current_database())")
        events_partitions = await partition_sizes(conn)
    finally:
        await conn.close()

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db_size_bytes": db_size,
        "events_total_bytes": sum(events_partitions.values()),
        "events_partitions": events_partitions,
        "suricata_logs_bytes": dir_size_bytes(suricata_logs),
        "pcap_bytes": dir_size_bytes(pcap_dir),
        "reports_bytes": dir_size_bytes(reports_dir),
    }


async def run(args) -> None:
    dsn = args.database_url.replace("postgresql+asyncpg://", "postgresql://")
    with open(args.out, "a") as f:
        elapsed = 0
        while elapsed <= args.duration:
            sample = await sample_once(dsn, Path(args.suricata_logs), Path(args.pcap_dir), Path(args.reports_dir))
            f.write(json.dumps(sample) + "\n")
            f.flush()
            print(f"t={elapsed}s: db={sample['db_size_bytes']} events={sample['events_total_bytes']} "
                  f"suricata_logs={sample['suricata_logs_bytes']} pcap={sample['pcap_bytes']} reports={sample['reports_bytes']}")
            if elapsed >= args.duration:
                break
            time.sleep(min(args.interval, args.duration - elapsed))
            elapsed += args.interval


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument("--suricata-logs", default="/var/log/suricata")
    parser.add_argument("--pcap-dir", default="/var/lib/sentinelcore/pcap")
    parser.add_argument("--reports-dir", default="/var/lib/sentinelcore/reports")
    parser.add_argument("--duration", type=int, default=0, help="0 = single sample, then exit")
    parser.add_argument("--interval", type=int, default=3600)
    parser.add_argument("--out", default="storage_growth.jsonl")
    args = parser.parse_args()

    if not args.database_url:
        print("--database-url or DATABASE_URL is required")
        return 1

    asyncio.run(run(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
