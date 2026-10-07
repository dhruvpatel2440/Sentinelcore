"""Statistical rarity evaluator: fire when a group's occurrences over a
trailing baseline are below a frequency floor — a signature or destination
that almost never appears is worth a look the one time it does, even though
raw volume never crosses a `threshold` rule's bar.

Deliberately simple counting, not a learned model.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select

from app.core.config import settings
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.matching import GROUP_FIELD_COLUMNS, apply_match, group_key_for
from app.models.correlation import CorrelationRule
from app.models.event import Event

from .base import Candidate


async def evaluate(
    rule: CorrelationRule, window_start: datetime, window_end: datetime, db: AsyncSession
) -> tuple[list[Candidate], int]:
    stmt = select(Event).where(Event.ts >= window_start, Event.ts < window_end)
    stmt = apply_match(stmt, rule.match)
    stmt = stmt.order_by(Event.ts.asc()).limit(settings.correlation_max_events_per_rule)

    rows = (await db.execute(stmt)).scalars().all()

    groups: dict[str, list[Event]] = {}
    for event in rows:
        key = group_key_for(event, rule.group_by)
        groups.setdefault(key, []).append(event)

    baseline_days = rule.params["baseline_days"]
    frequency_floor = rule.params["frequency_floor"]
    baseline_start = window_end - timedelta(days=baseline_days)

    # ONE grouped query for every group's baseline, instead of one COUNT per
    # group (which scaled with the number of distinct sources in the window).
    group_cols = [GROUP_FIELD_COLUMNS[f] for f in rule.group_by]
    baseline_stmt = (
        select(*group_cols, func.count())
        .select_from(Event)
        .where(Event.ts >= baseline_start, Event.ts < window_end)
        .group_by(*group_cols)
    )
    baseline_stmt = apply_match(baseline_stmt, rule.match)
    baseline_counts: dict[str, int] = {}
    for *values, count in (await db.execute(baseline_stmt)).all():
        k = "|".join(f"{f}={v}" for f, v in zip(rule.group_by, values))
        baseline_counts[k] = int(count)

    candidates: list[Candidate] = []
    for key, events in groups.items():
        baseline_count = baseline_counts.get(key, 0)

        if baseline_count > frequency_floor:
            continue

        candidates.append(
            Candidate(
                group_key=key,
                first_event_ts=events[0].ts,
                last_event_ts=events[-1].ts,
                event_count=len(events),
                summary=(
                    f"{rule.name}: {key} seen only {baseline_count} time(s) in the last "
                    f"{baseline_days}d (floor {frequency_floor}) — rare occurrence in this window"
                ),
                event_ids=[e.id for e in events],
                extra_evidence={"baseline_count": baseline_count, "baseline_days": baseline_days},
                src_ip=events[0].src_ip,
                dst_ip=events[0].dst_ip,
            )
        )

    return candidates, len(rows)
