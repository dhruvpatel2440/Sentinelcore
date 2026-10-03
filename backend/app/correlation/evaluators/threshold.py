"""The workhorse evaluator: count matching events per `group_by` key in the
window, fire when the count (or a distinct-field count) meets the threshold.

Covers port scans (many distinct dst_port from one src_ip), brute force
(repeated auth-failure signature to one dst_ip), and scanning sweeps (one
src_ip, many distinct dst_ip).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.matching import apply_match, group_key_for
from app.models.correlation import CorrelationRule
from app.models.event import Event

from .base import Candidate


async def evaluate(
    rule: CorrelationRule, window_start: datetime, window_end: datetime, db: AsyncSession
) -> tuple[list[Candidate], int]:
    stmt = select(Event).where(Event.ts >= window_start, Event.ts < window_end)
    stmt = apply_match(stmt, rule.match)
    stmt = stmt.order_by(Event.ts.asc())

    rows = (await db.execute(stmt)).scalars().all()

    distinct_field = rule.params.get("count_distinct_field")

    groups: dict[str, list[Event]] = {}
    for event in rows:
        key = group_key_for(event, rule.group_by)
        groups.setdefault(key, []).append(event)

    candidates: list[Candidate] = []
    for key, events in groups.items():
        if distinct_field:
            distinct_values = {getattr(e, distinct_field) for e in events if getattr(e, distinct_field) is not None}
            metric = len(distinct_values)
        else:
            metric = len(events)

        if metric < rule.threshold:
            continue

        summary = (
            f"{rule.name}: {metric} "
            f"{'distinct ' + distinct_field if distinct_field else 'event(s)'} "
            f"for {key} (threshold {rule.threshold})"
        )
        candidates.append(
            Candidate(
                group_key=key,
                first_event_ts=events[0].ts,
                last_event_ts=events[-1].ts,
                event_count=len(events),
                summary=summary,
                event_ids=[e.id for e in events],
                extra_evidence={"metric": metric, "distinct_field": distinct_field},
                src_ip=events[0].src_ip,
                dst_ip=events[0].dst_ip,
            )
        )

    return candidates, len(rows)
