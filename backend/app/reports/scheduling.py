"""M9 scheduled reports — the worker checks due schedules once a minute and
enqueues them with a *relative* window resolved at run time (`last_7_days`),
never the absolute dates a schedule was created with, so the same schedule
run a week apart produces two different, correct windows.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from croniter import croniter
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.models.report import Report, ReportSchedule, ReportStatus
from app.reports.types import REGISTRY  # noqa: F401 — validates report_type coverage at import time

logger = logging.getLogger("sentinelcore.reports.scheduling")

RELATIVE_WINDOWS: dict[str, timedelta] = {
    "last_24_hours": timedelta(hours=24),
    "last_7_days": timedelta(days=7),
    "last_30_days": timedelta(days=30),
    "last_90_days": timedelta(days=90),
}

CHECK_INTERVAL_SECONDS = 60


def resolve_relative_window(params: dict, now: datetime) -> dict:
    """If `params` carries a `window` key, returns a copy with `from`/`to`
    set to concrete ISO timestamps for `now`. Params without a `window` key
    (e.g. incident_detail, which has no time window) pass through unchanged."""
    window_key = params.get("window")
    delta = RELATIVE_WINDOWS.get(window_key)
    if delta is None:
        return dict(params)
    resolved = dict(params)
    resolved["to"] = now.isoformat()
    resolved["from"] = (now - delta).isoformat()
    return resolved


async def run_due_schedules(sessionmaker: async_sessionmaker[AsyncSession], redis: Redis) -> int:
    now = datetime.now(timezone.utc)
    enqueued = 0

    async with sessionmaker() as db:
        due = (
            await db.execute(
                select(ReportSchedule).where(
                    ReportSchedule.enabled.is_(True),
                    (ReportSchedule.next_run_at.is_(None)) | (ReportSchedule.next_run_at <= now),
                )
            )
        ).scalars().all()

        for schedule in due:
            resolved_params = resolve_relative_window(schedule.params, now)
            report = Report(
                report_type=schedule.report_type,
                title=f"{schedule.report_type.value} (scheduled)",
                params=resolved_params,
                format=schedule.format,
                status=ReportStatus.QUEUED,
                requested_by=schedule.created_by,
            )
            db.add(report)
            await db.flush()
            await redis.lpush(settings.report_queue_key, str(report.id))
            enqueued += 1

            schedule.last_run_at = now
            try:
                schedule.next_run_at = croniter(schedule.cron, now).get_next(datetime)
            except (ValueError, KeyError) as exc:
                logger.error("schedule %s has an invalid cron %r: %s", schedule.id, schedule.cron, exc)
                schedule.enabled = False

        if due:
            await db.commit()

    return enqueued


async def run_forever(
    sessionmaker: async_sessionmaker[AsyncSession], redis: Redis, stop: asyncio.Event
) -> None:
    logger.info("report scheduler starting (interval=%ds)", CHECK_INTERVAL_SECONDS)
    while not stop.is_set():
        try:
            n = await run_due_schedules(sessionmaker, redis)
            if n:
                logger.info("enqueued %d scheduled report(s)", n)
        except Exception as exc:  # noqa: BLE001
            logger.error("schedule check failed: %s", exc)

        try:
            await asyncio.wait_for(stop.wait(), timeout=CHECK_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue
