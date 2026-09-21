"""M6 event search: keyset pagination and shared filter application.

Cursor encoding/pagination notes:

`OFFSET n` makes PostgreSQL walk n rows on every page and shifts under
concurrent inserts. Instead the cursor is base64 of a small JSON tuple
`[ts_iso, id]`, and paging filters with a row-value comparison
`WHERE (ts, id) < (:ts, :id)` (descending) — that comparison, combined with
`ORDER BY ts DESC, id DESC`, is satisfied by the `ix_events_ts_id` index, so
paging to page 20 costs the same as page 1 and no row is skipped or repeated
while new events are still arriving.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_network
from typing import Any

from sqlalchemy import Select, String, cast, func, or_, select, tuple_
from sqlalchemy.dialects.postgresql import INET

from app.models.event import Event, EventType, Severity


class CursorError(ValueError):
    pass


def encode_cursor(ts: datetime, id_: int) -> str:
    payload = json.dumps([ts.isoformat(), id_]).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        payload = base64.urlsafe_b64decode(cursor.encode("ascii"))
        ts_iso, id_ = json.loads(payload)
        return datetime.fromisoformat(ts_iso), int(id_)
    except (ValueError, TypeError, json.JSONDecodeError, binascii.Error) as exc:
        raise CursorError("cursor is malformed") from exc


@dataclass
class EventFilters:
    """Every field an M6 search request can constrain by.

    Shared between the list endpoint and the facets endpoint so the two never
    drift — facets must always describe the same result set the list is
    paging through.
    """

    from_ts: datetime
    to_ts: datetime
    severity: list[Severity] = field(default_factory=list)
    event_type: list[EventType] = field(default_factory=list)
    src_ip: str | None = None
    dst_ip: str | None = None
    ip: str | None = None
    port: int | None = None
    proto: str | None = None
    signature_id: list[int] = field(default_factory=list)
    q: str | None = None
    asset_id: str | None = None

    def cache_key(self) -> str:
        payload = {
            "from": self.from_ts.isoformat(),
            "to": self.to_ts.isoformat(),
            "severity": sorted(s.value for s in self.severity),
            "event_type": sorted(t.value for t in self.event_type),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ip": self.ip,
            "port": self.port,
            "proto": self.proto,
            "signature_id": sorted(self.signature_id),
            "q": self.q,
            "asset_id": self.asset_id,
        }
        return json.dumps(payload, sort_keys=True)


def apply_filters(stmt: Select[Any], filters: EventFilters) -> Select[Any]:
    """Apply every filter, always including the ts window so partition
    pruning applies even if a caller's window is the only constraint."""
    stmt = stmt.where(Event.ts >= filters.from_ts, Event.ts < filters.to_ts)

    if filters.severity:
        stmt = stmt.where(Event.severity.in_(filters.severity))
    if filters.event_type:
        stmt = stmt.where(Event.event_type.in_(filters.event_type))
    if filters.src_ip:
        stmt = stmt.where(Event.src_ip.op("<<=")(cast(filters.src_ip, INET)))
    if filters.dst_ip:
        stmt = stmt.where(Event.dst_ip.op("<<=")(cast(filters.dst_ip, INET)))
    if filters.ip:
        net = cast(filters.ip, INET)
        stmt = stmt.where(or_(Event.src_ip.op("<<=")(net), Event.dst_ip.op("<<=")(net)))
    if filters.port is not None:
        stmt = stmt.where(or_(Event.src_port == filters.port, Event.dst_port == filters.port))
    if filters.proto:
        stmt = stmt.where(Event.proto == filters.proto)
    if filters.signature_id:
        stmt = stmt.where(Event.signature_id.in_(filters.signature_id))
    if filters.q:
        pattern = f"%{filters.q}%"
        stmt = stmt.where(
            or_(Event.signature.ilike(pattern), Event.category.ilike(pattern))
        )
    if filters.asset_id:
        stmt = stmt.where(
            or_(
                cast(Event.src_asset_id, String) == filters.asset_id,
                cast(Event.dst_asset_id, String) == filters.asset_id,
            )
        )
    return stmt


def apply_cursor(stmt: Select[Any], *, cursor: str | None, sort_desc: bool) -> Select[Any]:
    if not cursor:
        return stmt
    ts, id_ = decode_cursor(cursor)
    row = tuple_(Event.ts, Event.id)
    if sort_desc:
        return stmt.where(row < (ts, id_))
    return stmt.where(row > (ts, id_))


def validate_cidr(value: str) -> str:
    try:
        ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"not a valid IP address or CIDR: {value!r}") from exc
    return value.strip()


def top_n_subquery(column, filters: EventFilters, limit: int = 10):
    """Build a `SELECT value, count(*) ... GROUP BY value ORDER BY count DESC LIMIT n`
    for a facet column, reusing the exact same filter set as the list query."""
    stmt = select(column.label("value"), func.count().label("count")).select_from(Event)
    stmt = apply_filters(stmt, filters)
    stmt = stmt.where(column.is_not(None)).group_by(column).order_by(func.count().desc()).limit(limit)
    return stmt
