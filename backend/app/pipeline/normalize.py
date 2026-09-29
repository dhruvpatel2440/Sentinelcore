"""Map an EVE JSON record onto the `events` schema.

Everything about how Suricata's output becomes a platform event is decided
here, so there is one place to look when M6/M7/M9 disagree about a field.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.models.event import EventType, Severity

logger = logging.getLogger("sentinelcore.normalize")

# --------------------------------------------------------------------------
# THE severity mapping. Single source of truth.
#
# Suricata priority is 1 (highest) to 4. M2's Badge colours, M7's correlation
# scoring and M9's reports all key off these names — change this table and you
# change the meaning of "high" across the whole platform.
# --------------------------------------------------------------------------
SEVERITY_BY_SURICATA_PRIORITY: dict[int, Severity] = {
    1: Severity.CRITICAL,
    2: Severity.HIGH,
    3: Severity.MEDIUM,
    4: Severity.LOW,
}

# Non-alert records carry no priority; they are context, not detections.
DEFAULT_SEVERITY = Severity.INFO

# `stats` is consumed by M4 for sensor health, not stored as an event.
IGNORED_EVENT_TYPES = frozenset({"stats"})

SUPPORTED_EVENT_TYPES = {t.value for t in EventType}


class NormalizeError(Exception):
    pass


@dataclass
class NormalizedEvent:
    ts: datetime
    event_type: str
    severity: str
    dedup_key: bytes
    raw: dict[str, Any]

    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    proto: str | None = None

    signature: str | None = None
    signature_id: int | None = None
    rev: int | None = None
    category: str | None = None
    flow_id: int | None = None

    def as_row(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "event_type": self.event_type,
            "severity": self.severity,
            "dedup_key": self.dedup_key,
            "raw": self.raw,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "signature": self.signature,
            "signature_id": self.signature_id,
            "rev": self.rev,
            "category": self.category,
            "flow_id": self.flow_id,
        }


def parse_timestamp(value: Any) -> datetime:
    """EVE emits ISO 8601 with an offset, e.g. 2026-09-14T16:42:26.123456+0000.

    Always returned timezone-aware in UTC. A naive timestamp in a security
    timeline is a correctness bug waiting to happen during an investigation.
    """
    if not isinstance(value, str) or not value:
        raise NormalizeError("record has no timestamp")

    text = value.strip()
    # Python <3.11 cannot parse "+0000"; normalise to "+00:00".
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        text = f"{text[:-2]}:{text[-2:]}"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise NormalizeError(f"unparseable timestamp: {value!r}") from exc

    if parsed.tzinfo is None:
        # Suricata should always emit an offset; assume UTC rather than drop.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def compute_dedup_key(
    ts: datetime,
    signature_id: int | None,
    src_ip: str | None,
    src_port: int | None,
    dst_ip: str | None,
    dst_port: int | None,
    proto: str | None,
    event_type: str = "alert",
) -> bytes:
    """Stable identity for a record.

    Truncated to the second: Suricata can re-emit the same alert across a
    ruleset reload with microsecond jitter, and those are duplicates, not two
    separate detections.
    """
    parts = [
        str(int(ts.replace(microsecond=0).timestamp())),
        str(signature_id if signature_id is not None else ""),
        src_ip or "",
        str(src_port if src_port is not None else ""),
        dst_ip or "",
        str(dst_port if dst_port is not None else ""),
        (proto or "").lower(),
        event_type,
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).digest()


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_port(value: Any) -> int | None:
    port = _as_int(value)
    return port if port is not None and 0 <= port <= 65535 else None


def severity_for(record: dict[str, Any], event_type: str) -> Severity:
    if event_type != EventType.ALERT.value:
        return DEFAULT_SEVERITY
    priority = _as_int((record.get("alert") or {}).get("severity"))
    return SEVERITY_BY_SURICATA_PRIORITY.get(priority, DEFAULT_SEVERITY)


def normalize(record: dict[str, Any]) -> NormalizedEvent | None:
    """Return a NormalizedEvent, or None when the record is deliberately skipped.

    Raises NormalizeError only for records that *should* have been usable —
    those get counted as parse errors. Ignored types return None silently.
    """
    if not isinstance(record, dict):
        raise NormalizeError("record is not a JSON object")

    event_type = record.get("event_type")
    if not isinstance(event_type, str):
        raise NormalizeError("record has no event_type")
    if event_type in IGNORED_EVENT_TYPES:
        return None
    if event_type not in SUPPORTED_EVENT_TYPES:
        # Suricata can emit types we have not modelled (fileinfo, anomaly...).
        # Not an error; just not ours.
        return None

    ts = parse_timestamp(record.get("timestamp"))

    src_ip = record.get("src_ip") or None
    dst_ip = record.get("dest_ip") or None
    src_port = _as_port(record.get("src_port"))
    dst_port = _as_port(record.get("dest_port"))
    proto = record.get("proto")
    proto = proto.lower()[:8] if isinstance(proto, str) else None

    alert = record.get("alert") or {}
    signature = alert.get("signature") if isinstance(alert, dict) else None
    signature_id = _as_int(alert.get("signature_id")) if isinstance(alert, dict) else None
    rev = _as_int(alert.get("rev")) if isinstance(alert, dict) else None
    category = alert.get("category") if isinstance(alert, dict) else None

    return NormalizedEvent(
        ts=ts,
        event_type=event_type,
        severity=severity_for(record, event_type).value,
        dedup_key=compute_dedup_key(
            ts, signature_id, src_ip, src_port, dst_ip, dst_port, proto, event_type
        ),
        raw=record,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        signature=signature if isinstance(signature, str) else None,
        signature_id=signature_id,
        rev=rev,
        category=category[:128] if isinstance(category, str) else None,
        flow_id=_as_int(record.get("flow_id")),
    )
