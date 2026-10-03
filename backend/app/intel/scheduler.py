"""M12 worker-side scheduling: refresh each enabled source on its own
interval, and sweep expired IOCs out of the active set on a fixed cadence."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.intel.feeds import expire_stale_iocs, refresh_source
from app.models.ioc import IocSource

logger = logging.getLogger("sentinelcore.intel.scheduler")


async def run_due_refreshes(db: AsyncSession, redis: aioredis.Redis) -> int:
    now = datetime.now(timezone.utc)
    sources = (await db.execute(select(IocSource).where(IocSource.enabled.is_(True)))).scalars().all()

    refreshed = 0
    for source in sources:
        due = source.last_fetch_at is None or (
            now - source.last_fetch_at >= timedelta(hours=source.refresh_interval_hours)
        )
        if due:
            await refresh_source(db, source, redis)
            refreshed += 1
    return refreshed


async def run_forever(
    sessionmaker: async_sessionmaker[AsyncSession], redis: aioredis.Redis, stop: asyncio.Event
) -> None:
    logger.info(
        "intel scheduler starting (refresh check every %ss, expiry sweep every %ss)",
        settings.intel_feed_scheduler_interval_seconds, settings.intel_expiry_interval_seconds,
    )
    last_expiry_check = 0.0

    while not stop.is_set():
        try:
            async with sessionmaker() as db:
                await run_due_refreshes(db, redis)

            now = asyncio.get_event_loop().time()
            if now - last_expiry_check >= settings.intel_expiry_interval_seconds:
                last_expiry_check = now
                async with sessionmaker() as db:
                    expired = await expire_stale_iocs(db, redis)
                    if expired:
                        logger.info("expired %d stale ioc(s)", expired)
        except Exception:  # noqa: BLE001 — one broken pass must not kill the loop
            logger.exception("intel scheduler pass failed")

        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.intel_feed_scheduler_interval_seconds)
        except asyncio.TimeoutError:
            continue
