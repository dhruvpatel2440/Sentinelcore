"""Beacon detection: regular callback intervals for a group (typically
`src_ip`+`dst_ip`) — catches C2 that no signature covers, by looking at
*timing* rather than content.

Fires when the coefficient of variation (stdev / mean) of inter-arrival
deltas is below `params.max_cv` with at least `params.min_samples` deltas.
"""

from __future__ import annotations

import statistics
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

    groups: dict[str, list[Event]] = {}
    for event in rows:
        key = group_key_for(event, rule.group_by)
        groups.setdefault(key, []).append(event)

    max_cv = rule.params["max_cv"]
    min_samples = rule.params["min_samples"]

    candidates: list[Candidate] = []
    for key, events in groups.items():
        timestamps = sorted(e.ts for e in events)
        deltas = [
            (timestamps[i + 1] - timestamps[i]).total_seconds() for i in range(len(timestamps) - 1)
        ]
        if len(deltas) < min_samples:
            continue

        mean = statistics.mean(deltas)
        if mean <= 0:
            continue
        stdev = statistics.pstdev(deltas)
        cv = stdev / mean

        if cv > max_cv:
            continue

        candidates.append(
            Candidate(
                group_key=key,
                first_event_ts=events[0].ts,
                last_event_ts=events[-1].ts,
                event_count=len(events),
                summary=(
                    f"{rule.name}: {key} beacons every ~{mean:.1f}s "
                    f"(cv={cv:.3f}, {len(deltas)} samples)"
                ),
                event_ids=[e.id for e in events],
                extra_evidence={"mean_interval_seconds": mean, "cv": cv, "samples": len(deltas)},
                src_ip=events[0].src_ip,
                dst_ip=events[0].dst_ip,
            )
        )

    return candidates, len(rows)
