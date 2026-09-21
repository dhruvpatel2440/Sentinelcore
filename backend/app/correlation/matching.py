"""Shared `match` filtering and group-key derivation for every evaluator.

Cheap first, expensive second: every evaluator starts from this indexed
filter (severity, event_type, signature_id, ts) before doing any grouping.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Select, cast
from sqlalchemy.dialects.postgresql import INET

from app.models.event import Event

GROUP_FIELD_COLUMNS = {
    "src_ip": Event.src_ip,
    "dst_ip": Event.dst_ip,
    "signature_id": Event.signature_id,
    "dst_port": Event.dst_port,
    "src_port": Event.src_port,
    "proto": Event.proto,
}


def apply_match(stmt: Select[Any], match: dict[str, Any]) -> Select[Any]:
    if match.get("severity"):
        stmt = stmt.where(Event.severity.in_(match["severity"]))
    if match.get("event_type"):
        stmt = stmt.where(Event.event_type.in_(match["event_type"]))
    if match.get("signature_id"):
        stmt = stmt.where(Event.signature_id.in_(match["signature_id"]))
    if match.get("category_regex"):
        stmt = stmt.where(Event.category.op("~")(match["category_regex"]))
    if match.get("src_cidr"):
        stmt = stmt.where(Event.src_ip.op("<<=")(cast(match["src_cidr"], INET)))
    if match.get("dst_cidr"):
        stmt = stmt.where(Event.dst_ip.op("<<=")(cast(match["dst_cidr"], INET)))
    return stmt


def group_key_for(event: Event, group_by: list[str]) -> str:
    parts = []
    for field in group_by:
        value = getattr(event, field, None)
        parts.append(f"{field}={value}")
    return "|".join(parts)
