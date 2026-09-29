"""Read Suricata `stats` events from eve.json.

M5 owns the alert pipeline; stats are consumed here because they are sensor
health, not detections. Reads the tail of the file only — eve.json can be
gigabytes and the newest stats record is all that matters.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger("sentinelcore.sensor_stats")

TAIL_BYTES = 512 * 1024
MAX_HISTORY = 30


def _read_tail_lines(path: Path, size: int = TAIL_BYTES) -> list[bytes]:
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            start = max(0, handle.tell() - size)
            handle.seek(start)
            data = handle.read()
    except (OSError, FileNotFoundError):
        return []

    lines = data.split(b"\n")
    # The first line is probably a fragment from mid-record; drop it.
    return lines[1:] if start > 0 and len(lines) > 1 else lines


def read_stats() -> dict:
    """Latest stats record plus a short history for the throughput sparkline."""
    path = Path(settings.suricata_eve_log)
    history: list[dict] = []

    for raw in _read_tail_lines(path):
        if not raw.strip() or b'"event_type":"stats"' not in raw.replace(b" ", b""):
            continue
        try:
            record = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue  # a partial line is expected at a boundary
        if record.get("event_type") != "stats":
            continue

        stats = record.get("stats", {})
        capture = stats.get("capture", {})
        decoder = stats.get("decoder", {})

        packets = int(decoder.get("pkts", 0) or 0)
        kernel_packets = int(capture.get("kernel_packets", 0) or 0)
        kernel_drops = int(capture.get("kernel_drops", 0) or 0)

        # Drop rate is the number that matters: a sensor dropping packets is
        # silently missing attacks, which looks identical to "no attacks".
        denominator = kernel_packets or packets
        drop_rate = (kernel_drops / denominator * 100.0) if denominator else 0.0

        history.append(
            {
                "timestamp": record.get("timestamp"),
                "packets": packets,
                "kernel_packets": kernel_packets,
                "kernel_drops": kernel_drops,
                "drop_rate": round(drop_rate, 4),
                "uptime_seconds": stats.get("uptime"),
            }
        )

    history = history[-MAX_HISTORY:]
    if not history:
        return {
            "packets": 0,
            "drops": 0,
            "drop_rate": 0.0,
            "kernel_packets": 0,
            "kernel_drops": 0,
            "uptime_seconds": None,
            "captured_at": None,
            "history": [],
        }

    latest = history[-1]
    captured_at = None
    if latest.get("timestamp"):
        try:
            captured_at = datetime.fromisoformat(latest["timestamp"])
        except ValueError:
            captured_at = None

    return {
        "packets": latest["packets"],
        "drops": latest["kernel_drops"],
        "drop_rate": latest["drop_rate"],
        "kernel_packets": latest["kernel_packets"],
        "kernel_drops": latest["kernel_drops"],
        "uptime_seconds": latest.get("uptime_seconds"),
        "captured_at": captured_at,
        "history": history,
    }
