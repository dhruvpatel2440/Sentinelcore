"""M8 candidate promotion — subscribes to M7's Redis channel and decides,
for each new candidate, whether it becomes an incident, merges into an
existing one, or waits for a human. Runs in the worker container.

Merging before creating is the whole point: a fresh incident per candidate
recreates exactly the alert fatigue M7 exists to prevent.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import timedelta

import redis.asyncio as aioredis
from sqlalchemy import cast, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.models.correlation import CandidateStatus, CorrelationRule, IncidentCandidate
from app.models.incident import TERMINAL_STATUSES, HistoryAction, Incident, IncidentEvent, IncidentHistory
from app.services.incident_state import IncidentStatus

logger = logging.getLogger("sentinelcore.incidents.promotion")


def _group_field(group_key: str, field: str) -> str | None:
    for part in group_key.split("|"):
        key, _, value = part.partition("=")
        if key == field and value not in ("", "None"):
            return value
    return None


def _evidence_event_ids(evidence: dict) -> list[int]:
    ids = set(evidence.get("event_ids_first", [])) | set(evidence.get("event_ids_last", []))
    return sorted(ids)


async def _link_events(db: AsyncSession, incident_id, event_ids: list[int], linked_by=None) -> None:
    if not event_ids:
        return
    stmt = pg_insert(IncidentEvent).values(
        [{"incident_id": incident_id, "event_id": e, "linked_by": linked_by} for e in event_ids]
    )
    stmt = stmt.on_conflict_do_nothing(index_elements=["incident_id", "event_id"])
    await db.execute(stmt)


async def _write_history(db: AsyncSession, incident_id, *, action: HistoryAction, note: str | None = None,
                          from_value: str | None = None, to_value: str | None = None) -> None:
    db.add(
        IncidentHistory(
            incident_id=incident_id,
            user_id=None,  # system action
            action=action,
            from_value=from_value,
            to_value=to_value,
            note=note,
        )
    )


async def _find_mergeable_incident(
    db: AsyncSession, rule_id, src_ip: str | None, first_event_ts
) -> Incident | None:
    if src_ip is None:
        return None
    cutoff = first_event_ts - timedelta(minutes=settings.incident_merge_window_minutes)
    stmt = (
        select(Incident)
        .where(
            Incident.rule_id == rule_id,
            Incident.src_ip == cast(src_ip, INET),
            Incident.status.notin_(TERMINAL_STATUSES),
            Incident.last_event_ts >= cutoff,
        )
        .order_by(Incident.opened_at.desc())
        .limit(1)
    )
    return await db.scalar(stmt)


async def promote_candidate(candidate_id, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
    async with sessionmaker() as db:
        candidate = await db.get(IncidentCandidate, candidate_id)
        if candidate is None or candidate.status != CandidateStatus.NEW:
            return  # already handled, suppressed, or gone

        if candidate.score < settings.auto_promote_score:
            return  # stays visible in the candidates list for manual promotion

        rule = await db.get(CorrelationRule, candidate.rule_id)
        if rule is None:
            return

        src_ip = _group_field(candidate.group_key, "src_ip")
        dst_ip = _group_field(candidate.group_key, "dst_ip")
        event_ids = _evidence_event_ids(candidate.evidence)

        existing = await _find_mergeable_incident(db, rule.id, src_ip, candidate.first_event_ts)

        if existing is not None:
            existing.event_count += candidate.event_count
            if existing.last_event_ts is None or candidate.last_event_ts > existing.last_event_ts:
                existing.last_event_ts = candidate.last_event_ts
            if existing.first_event_ts is not None and candidate.first_event_ts < existing.first_event_ts:
                existing.first_event_ts = candidate.first_event_ts
            existing.version += 1

            await _link_events(db, existing.id, event_ids)
            await _write_history(
                db, existing.id, action=HistoryAction.EVENTS_LINKED,
                note=f"merged candidate {candidate.id} ({candidate.event_count} event(s))",
            )
            candidate.status = CandidateStatus.PROMOTED
            candidate.incident_id = existing.id
            await db.commit()
            logger.info("merged candidate %s into incident %s", candidate.id, existing.number)
            return

        incident = Incident(
            title=f"{rule.name} from {src_ip or 'unknown source'}",
            description=rule.description,
            status=IncidentStatus.NEW,
            severity=candidate.severity,
            score=candidate.score,
            src_ip=src_ip,
            dst_ip=dst_ip,
            rule_id=rule.id,
            candidate_id=candidate.id,
            event_count=candidate.event_count,
            first_event_ts=candidate.first_event_ts,
            last_event_ts=candidate.last_event_ts,
        )
        db.add(incident)
        await db.flush()

        await _link_events(db, incident.id, event_ids)
        await _write_history(db, incident.id, action=HistoryAction.CREATED, note=candidate.summary)

        candidate.status = CandidateStatus.PROMOTED
        candidate.incident_id = incident.id
        await db.commit()
        logger.info("promoted candidate %s to incident INC-%s", candidate.id, incident.number)


async def run_forever(
    sessionmaker: async_sessionmaker[AsyncSession], redis: aioredis.Redis, stop: asyncio.Event
) -> None:
    logger.info("incident promotion subscriber starting on %s", settings.correlation_candidates_channel)
    pubsub = redis.pubsub()
    await pubsub.subscribe(settings.correlation_candidates_channel)

    try:
        while not stop.is_set():
            try:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            except Exception as exc:  # noqa: BLE001
                logger.error("promotion pubsub read failed: %s", exc)
                await asyncio.sleep(1)
                continue

            if message is None:
                continue

            try:
                payload = json.loads(message["data"])
                await promote_candidate(payload["candidate_id"], sessionmaker)
            except Exception as exc:  # noqa: BLE001 — one bad message must not kill the subscriber
                logger.error("failed to process candidate message %r: %s", message, exc)
    finally:
        await pubsub.unsubscribe(settings.correlation_candidates_channel)
        await pubsub.aclose()
