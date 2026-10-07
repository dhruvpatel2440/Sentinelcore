#!/usr/bin/env python3
"""U09 §4.1 — samples `docker stats --no-stream --format json` every 10s for
a given duration and writes a CSV (timestamp, container, cpu_pct,
mem_bytes, mem_limit_bytes, net_rx_bytes, net_tx_bytes, block_read_bytes,
block_write_bytes).

Run on the HOST (needs the Docker CLI and socket — containers in this
platform deliberately do not have either, see CLAUDE.md/T16 in
docs/threat-model.md).

    python3 sample_stats.py --duration 1800 --interval 10 --out idle.csv

No shell is ever used: the docker CLI is invoked as an argv list.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

_UNIT_MULTIPLIERS = {
    "B": 1,
    "kB": 1000,
    "KB": 1000,
    "KiB": 1024,
    "MB": 1000**2,
    "MiB": 1024**2,
    "GB": 1000**3,
    "GiB": 1024**3,
    "TB": 1000**4,
    "TiB": 1024**4,
}

CSV_FIELDS = [
    "timestamp",
    "container",
    "cpu_pct",
    "mem_bytes",
    "mem_limit_bytes",
    "net_rx_bytes",
    "net_tx_bytes",
    "block_read_bytes",
    "block_write_bytes",
]


def parse_size(text: str) -> float:
    """'145.9MiB' -> 152997396.6 bytes. Docker's `stats` format has no space
    between the number and unit, unlike the '145.9MiB / 11.22GiB' pair it's
    extracted from."""
    text = text.strip()
    for unit in sorted(_UNIT_MULTIPLIERS, key=len, reverse=True):
        if text.endswith(unit):
            number = text[: -len(unit)].strip()
            return float(number) * _UNIT_MULTIPLIERS[unit]
    raise ValueError(f"unrecognised size unit in {text!r}")


def parse_pair(text: str) -> tuple[float, float]:
    """'2.91MB / 2.99MB' -> (2910000.0, 2990000.0) bytes."""
    left, _, right = text.partition("/")
    return parse_size(left), parse_size(right)


def parse_cpu_pct(text: str) -> float:
    return float(text.strip().rstrip("%"))


def parse_docker_stats_line(line: dict) -> dict:
    """Parse one `docker stats --format json` record into normalised,
    numeric fields. Pure function — the unit tests exercise this directly
    without invoking Docker."""
    mem_bytes, mem_limit_bytes = parse_pair(line["MemUsage"])
    net_rx, net_tx = parse_pair(line["NetIO"])
    block_read, block_write = parse_pair(line["BlockIO"])
    return {
        "container": line["Name"],
        "cpu_pct": parse_cpu_pct(line["CPUPerc"]),
        "mem_bytes": mem_bytes,
        "mem_limit_bytes": mem_limit_bytes,
        "net_rx_bytes": net_rx,
        "net_tx_bytes": net_tx,
        "block_read_bytes": block_read,
        "block_write_bytes": block_write,
    }


def sample_once() -> list[dict]:
    result = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    rows = []
    ts = datetime.now(timezone.utc).isoformat()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = parse_docker_stats_line(json.loads(line))
        parsed["timestamp"] = ts
        rows.append(parsed)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=1800, help="seconds to sample for")
    parser.add_argument("--interval", type=int, default=10, help="seconds between samples")
    parser.add_argument("--out", default="sample_stats.csv")
    args = parser.parse_args()

    out_path = Path(args.out)
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()

        elapsed = 0
        while elapsed <= args.duration:
            for row in sample_once():
                writer.writerow({k: row[k] for k in CSV_FIELDS})
            f.flush()
            print(f"sampled at t={elapsed}s")
            time.sleep(args.interval)
            elapsed += args.interval

    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
