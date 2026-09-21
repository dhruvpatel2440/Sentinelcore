"""M7 correlation engine — runs as a second task in the M5 worker container,
never in the API process.

Design principles carried into this module (see the M7 spec):
  - rules are data, tuned by an admin PATCH, never a redeploy
  - idempotent and restart-safe: reprocessing an overlapping window must not
    duplicate a candidate
  - cheap first, expensive second: evaluators filter on indexed columns
    before any grouping work
  - one pathological rule must not stall the others
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.correlation.evaluators import REGISTRY
from app.correlation.scoring import score_candidate
from app.core.config import settings
from app.models.correlation import CandidateStatus, CorrelationRule, IncidentCandidate, RuleRun

logger = logging.getLogger("sentinelcore.correlation.engine")


def dedup_key(rule_id, group_key: str) -> str:
    return f"corr:{rule_id}:{group_key}"


async def run_rule(
    rule: CorrelationRule,
    now: datetime,
    sessionmaker: async_sessionmaker[AsyncSession],
    redis: aioredis.Redis,
) -> None:
    window_end = now
    window_start = now - timedelta(seconds=rule.window_seconds + settings.correlation_lookback_grace_seconds)

    start_perf = time.perf_counter()
    events_scanned = 0
    candidates_created = 0
    error: str | None = None

    try:
        evaluator = REGISTRY[rule.rule_type]
        async with sessionmaker() as db:
            candidates, events_scanned = await asyncio.wait_for(
                evaluator.evaluate(rule, window_start, window_end, db),
                timeout=settings.correlation_rule_timeout_seconds,
            )

            for candidate in candidates:
                key = dedup_key(rule.id, candidate.group_key)
                if await redis.exists(key):
                    continue

                score = await score_candidate(candidate, rule.severity, rule.threshold, db)
                record = IncidentCandidate(
                    rule_id=rule.id,
                    group_key=candidate.group_key,
                    first_event_ts=candidate.first_event_ts,
                    last_event_ts=candidate.last_event_ts,
                    event_count=candidate.event_count,
                    severity=rule.severity,
                    score=score,
                    summary=candidate.summary,
                    evidence=candidate.evidence(),
                    status=CandidateStatus.NEW,
                )

                try:
                    # A savepoint: a duplicate from an overlapping window (the
                    # unique constraint firing) rolls back only this insert,
                    # not the whole tick's work.
                    async with db.begin_nested():
                        db.add(record)
                        await db.flush()
                except IntegrityError:
                    continue

                await redis.set(key, "1", ex=rule.dedup_window_seconds)
                candidates_created += 1
                await redis.publish(
                    settings.correlation_candidates_channel,
                    json.dumps({"candidate_id": str(record.id), "rule_id": str(rule.id), "score": score}),
                )

            await db.commit()
    except asyncio.TimeoutError:
        error = f"rule timed out after {settings.correlation_rule_timeout_seconds}s"
        logger.error("rule %s (%s) timed out", rule.id, rule.name)
    except Exception as exc:  # noqa: BLE001 — one bad rule must not stall the tick
        error = str(exc)
        logger.error("rule %s (%s) failed: %s", rule.id, rule.name, exc)

    duration_ms = int((time.perf_counter() - start_perf) * 1000)
    async with sessionmaker() as db:
        db.add(
            RuleRun(
                rule_id=rule.id,
                window_start=window_start,
                window_end=window_end,
                events_scanned=events_scanned,
                candidates_created=candidates_created,
                duration_ms=duration_ms,
                error=error,
            )
        )
        await db.commit()


async def tick(sessionmaker: async_sessionmaker[AsyncSession], redis: aioredis.Redis) -> None:
    now = datetime.now(timezone.utc)
    async with sessionmaker() as db:
        rules = (
            (await db.execute(select(CorrelationRule).where(CorrelationRule.enabled.is_(True))))
            .scalars()
            .all()
        )

    if not rules:
        return

    semaphore = asyncio.Semaphore(settings.correlation_max_concurrent_rules)

    async def _bounded(rule: CorrelationRule) -> None:
        async with semaphore:
            await run_rule(rule, now, sessionmaker, redis)

    await asyncio.gather(*(_bounded(r) for r in rules), return_exceptions=False)


async def run_forever(
    sessionmaker: async_sessionmaker[AsyncSession], redis: aioredis.Redis, stop: asyncio.Event
) -> None:
    logger.info("correlation engine starting (interval=%ds)", settings.correlation_interval_seconds)
    while not stop.is_set():
        try:
            await tick(sessionmaker, redis)
        except Exception as exc:  # noqa: BLE001
            logger.error("correlation tick failed: %s", exc)

        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.correlation_interval_seconds)
        except asyncio.TimeoutError:
            continue
