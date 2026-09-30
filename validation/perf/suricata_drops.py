#!/usr/bin/env python3
"""U09 §4.2 — reads Suricata's EVE `stats` events and reports kernel packet
drops (count and percentage) between two timestamps.

`stats.enabled: yes` with `interval: 30` and the `stats` EVE output type
(`totals: yes`) are **already configured** in `docker/suricata/suricata.yaml`
(lines 37-40 and 76-79) — no change was needed for this deliverable. Those
counters are cumulative since Suricata start (`deltas: no`), so the drop
rate over a window is `(drops_end - drops_start) / (packets_end -
packets_start)`, using the stats record nearest each boundary — not the
raw counter value at either end.

    python3 suricata_drops.py --eve /var/log/suricata/eve.json \\
        --from 2026-01-01T00:00:00Z --to 2026-01-01T00:30:00Z
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path


def _parse_ts(value: str) -> datetime:
    # Suricata EVE timestamps look like "2026-09-24T10:01:12.352113+0000".
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    elif len(value) >= 5 and value[-5] in "+-" and value[-4:].isdigit():
        value = value[:-5] + value[-5:-2] + ":" + value[-2:]
    return datetime.fromisoformat(value)


def iter_stats_events(eve_path: Path):
    """Yields (timestamp, kernel_packets, kernel_drops) for every EVE
    `stats` line. Skips malformed lines rather than aborting — the EVE file
    can be mid-write while this reads it."""
    with eve_path.open(errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("event_type") != "stats":
                continue
            capture = record.get("stats", {}).get("capture", {})
            if "kernel_packets" not in capture:
                continue
            yield _parse_ts(record["timestamp"]), capture.get("kernel_packets", 0), capture.get("kernel_drops", 0)


def drops_between(events: list[tuple[datetime, int, int]], from_ts: datetime, to_ts: datetime) -> dict:
    """Pure aggregation over an already-parsed event list — the unit tests
    exercise this directly with fixture tuples, no real EVE file needed."""
    in_window = [e for e in events if from_ts <= e[0] <= to_ts]
    if len(in_window) < 2:
        return {
            "packets": 0,
            "drops": 0,
            "drop_pct": None,
            "samples": len(in_window),
            "note": "fewer than 2 stats samples in window — cannot compute a delta",
        }

    in_window.sort(key=lambda e: e[0])
    start, end = in_window[0], in_window[-1]
    packets_delta = max(end[1] - start[1], 0)
    drops_delta = max(end[2] - start[2], 0)
    drop_pct = (drops_delta / packets_delta * 100.0) if packets_delta else 0.0

    return {
        "packets": packets_delta,
        "drops": drops_delta,
        "drop_pct": drop_pct,
        "samples": len(in_window),
        "note": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eve", default="/var/log/suricata/eve.json")
    parser.add_argument("--from", dest="from_ts", required=True)
    parser.add_argument("--to", dest="to_ts", required=True)
    args = parser.parse_args()

    events = list(iter_stats_events(Path(args.eve)))
    result = drops_between(events, _parse_ts(args.from_ts), _parse_ts(args.to_ts))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
