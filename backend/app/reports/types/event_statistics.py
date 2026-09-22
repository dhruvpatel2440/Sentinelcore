from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event
from app.schemas.report import EventStatisticsParams
from app.services import sensor_stats

TOP_N = 10


async def build(params: dict[str, Any], db: AsyncSession) -> dict[str, Any]:
    p = EventStatisticsParams.model_validate(params)
    window = p.to - p.from_
    prev_from, prev_to = p.from_ - window, p.from_

    def _base(from_ts, to_ts):
        stmt = select(Event).where(Event.ts >= from_ts, Event.ts < to_ts)
        if p.severity:
            stmt = stmt.where(Event.severity.in_(p.severity))
        if p.event_type:
            stmt = stmt.where(Event.event_type.in_(p.event_type))
        return stmt

    async def _bucket(column, from_ts, to_ts, limit: int | None = None):
        stmt = (
            select(column.label("value"), func.count().label("n"))
            .select_from(Event)
            .where(Event.ts >= from_ts, Event.ts < to_ts)
        )
        if p.severity:
            stmt = stmt.where(Event.severity.in_(p.severity))
        if p.event_type:
            stmt = stmt.where(Event.event_type.in_(p.event_type))
        stmt = stmt.where(column.is_not(None)).group_by(column).order_by(func.count().desc())
        if limit:
            stmt = stmt.limit(limit)
        rows = (await db.execute(stmt)).all()
        return {(v.value if hasattr(v, "value") else str(v)): n for v, n in rows}

    total_events = int(await db.scalar(select(func.count()).select_from(_base(p.from_, p.to).subquery())) or 0)

    severity_counts = await _bucket(Event.severity, p.from_, p.to)
    event_type_counts = await _bucket(Event.event_type, p.from_, p.to)
    proto_counts = await _bucket(Event.proto, p.from_, p.to)
    sig_counts = await _bucket(Event.signature, p.from_, p.to, limit=TOP_N)
    prev_sig_counts = await _bucket(Event.signature, prev_from, prev_to, limit=None)
    src_counts = await _bucket(Event.src_ip, p.from_, p.to, limit=TOP_N)
    dst_counts = await _bucket(Event.dst_ip, p.from_, p.to, limit=TOP_N)

    day_stmt = (
        select(func.date_trunc("day", Event.ts).label("day"), Event.severity, func.count())
        .select_from(Event)
        .where(Event.ts >= p.from_, Event.ts < p.to)
    )
    if p.severity:
        day_stmt = day_stmt.where(Event.severity.in_(p.severity))
    if p.event_type:
        day_stmt = day_stmt.where(Event.event_type.in_(p.event_type))
    day_stmt = day_stmt.group_by("day", Event.severity).order_by("day")
    day_rows = (await db.execute(day_stmt)).all()

    volume_over_time: dict[str, dict[str, int]] = {}
    for day, severity, n in day_rows:
        key = day.date().isoformat()
        volume_over_time.setdefault(key, {})[severity.value] = n

    top_signatures = [
        {"signature": sig, "count": n, "previous_count": prev_sig_counts.get(sig, 0)}
        for sig, n in sig_counts.items()
    ]

    drop_rate = None
    try:
        drop_rate = sensor_stats.read_stats().get("drop_rate")
    except Exception:  # noqa: BLE001 — a stats-read failure must not fail the whole report
        drop_rate = None

    return {
        "report_type": "event_statistics",
        "params": {
            "from": p.from_.isoformat(), "to": p.to.isoformat(),
            "severity": [s.value for s in p.severity], "event_type": [t.value for t in p.event_type],
        },
        "sensor_drop_rate": drop_rate,
        "total_events": total_events,
        "severity_counts": severity_counts,
        "event_type_counts": event_type_counts,
        "protocol_counts": proto_counts,
        "top_signatures": top_signatures,
        "top_src_ips": [{"ip": k, "count": v} for k, v in src_counts.items()],
        "top_dst_ips": [{"ip": k, "count": v} for k, v in dst_counts.items()],
        "volume_over_time": volume_over_time,
    }
