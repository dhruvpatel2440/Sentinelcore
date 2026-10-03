"""Ordered-stage evaluator: `params.steps` must occur in order for the same
group key within the window — this is what catches recon -> exploit -> callback.

The state machine is a pure function of the events in the evaluation window
rather than externally persisted: the window already spans `window_seconds`
(plus the engine's lookback grace), so a sequence that is supposed to
complete within that window does so within a single pass. That keeps
evaluation idempotent by construction (re-running the same window replays the
same events in the same order) and side-effect free, which the dry-run test
endpoint depends on.
"""

from __future__ import annotations

import re
from datetime import datetime
from ipaddress import ip_address, ip_network

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.matching import apply_match, group_key_for
from app.models.correlation import CorrelationRule
from app.models.event import Event

from .base import Candidate


def _event_matches_step(event: Event, step: dict) -> bool:
    if step.get("severity") and event.severity.value not in step["severity"]:
        return False
    if step.get("event_type") and event.event_type.value not in step["event_type"]:
        return False
    if step.get("signature_id") and event.signature_id not in step["signature_id"]:
        return False
    if step.get("category_regex"):
        if not event.category or not re.search(step["category_regex"], event.category):
            return False
    if step.get("src_cidr"):
        if not event.src_ip or ip_address(event.src_ip) not in ip_network(step["src_cidr"], strict=False):
            return False
    if step.get("dst_cidr"):
        if not event.dst_ip or ip_address(event.dst_ip) not in ip_network(step["dst_cidr"], strict=False):
            return False
    return True


async def evaluate(
    rule: CorrelationRule, window_start: datetime, window_end: datetime, db: AsyncSession
) -> tuple[list[Candidate], int]:
    stmt = select(Event).where(Event.ts >= window_start, Event.ts < window_end)
    stmt = apply_match(stmt, rule.match)
    stmt = stmt.order_by(Event.ts.asc())

    rows = (await db.execute(stmt)).scalars().all()
    steps: list[dict] = rule.params["steps"]

    # group_key -> (stage_index, [matched events for the in-progress attempt])
    progress: dict[str, tuple[int, list[Event]]] = {}
    candidates: list[Candidate] = []

    for event in rows:
        key = group_key_for(event, rule.group_by)
        stage_index, matched = progress.get(key, (0, []))

        if _event_matches_step(event, steps[stage_index]):
            matched = [*matched, event]
            stage_index += 1

            if stage_index == len(steps):
                candidates.append(
                    Candidate(
                        group_key=key,
                        first_event_ts=matched[0].ts,
                        last_event_ts=matched[-1].ts,
                        event_count=len(matched),
                        summary=f"{rule.name}: full {len(steps)}-stage sequence completed for {key}",
                        event_ids=[e.id for e in matched],
                        src_ip=matched[0].src_ip,
                        dst_ip=matched[0].dst_ip,
                    )
                )
                progress[key] = (0, [])
                continue

        progress[key] = (stage_index, matched)

    return candidates, len(rows)
