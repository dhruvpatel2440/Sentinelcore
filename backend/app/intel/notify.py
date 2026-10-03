"""E06 — threat-intel match email. Subscribes to M12's `ioc:hits` channel
(published by `app.pipeline.writer` on every match) and emails analysts/
admins when a hit lands on an event tied to a monitored asset and clears
the confidence floor. Runs in the worker container, mirroring M8's
`services.promotion` subscriber pattern.
"""

from __future__ import annotations

import asyncio
import json
import logging

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.email import recipients as email_recipients
from app.email.render import app_link, defang
from app.email.service import enqueue, resolve_recipients_from_users
from app.email.types import EmailType
from app.intel.matcher import HITS_CHANNEL
from app.models.asset import Asset
from app.models.event import Event
from app.models.ioc import Ioc, IocSource

logger = logging.getLogger("sentinelcore.intel.notify")


async def _notify_hit(db: AsyncSession, *, event_id: int, ioc_id: str, severity: str) -> None:
    ioc = await db.get(Ioc, ioc_id)
    if ioc is None or ioc.confidence < settings.intel_match_email_min_confidence:
        return

    event = await db.get(Event, event_id)
    if event is None:
        return

    asset = None
    for candidate_ip in (event.dst_ip, event.src_ip):
        if not candidate_ip:
            continue
        asset = await db.scalar(select(Asset).where(Asset.ip_address == candidate_ip))
        if asset is not None:
            break
    if asset is None:
        return  # spec: only emails when the hit is tied to a monitored asset

    feed = await db.get(IocSource, ioc.source_id) if ioc.source_id else None

    users = await email_recipients.analysts_and_admins(db)
    recips = await resolve_recipients_from_users(db, users)
    if not recips:
        return

    await enqueue(
        db,
        email_type=EmailType.E06_THREAT_INTEL_MATCH,
        recipients=recips,
        heading=f"Threat-intel match on {asset.hostname or asset.ip_address}",
        render_context={
            "ioc_type": ioc.ioc_type.value,
            "ioc_value_defanged": defang(ioc.indicator),
            "feed_name": feed.name if feed else "manual",
            "confidence": ioc.confidence,
            "first_seen": ioc.first_seen.isoformat(),
            "last_seen": ioc.last_seen.isoformat(),
            "asset": asset.hostname or str(asset.ip_address),
        },
        dedupe_key=lambda r, iid=ioc.id, aid=asset.id: f"E06:{iid}:{aid}",
        related_type="ioc", related_id=str(ioc.id),
        button_label="View IOC", button_url=app_link(f"/intel/ioc/{ioc.id}"),
        why_you_got_this="a threat-intel indicator matched traffic on a monitored asset.",
    )
    await db.commit()


async def run_forever(
    sessionmaker: async_sessionmaker[AsyncSession], redis: aioredis.Redis, stop: asyncio.Event
) -> None:
    logger.info("threat-intel match notifier starting on %s", HITS_CHANNEL)
    pubsub = redis.pubsub()
    await pubsub.subscribe(HITS_CHANNEL)

    try:
        while not stop.is_set():
            try:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            except Exception as exc:  # noqa: BLE001
                logger.error("intel notify pubsub read failed: %s", exc)
                await asyncio.sleep(1)
                continue
            if message is None:
                continue
            try:
                payload = json.loads(message["data"])
                async with sessionmaker() as db:
                    await _notify_hit(
                        db, event_id=payload["event_id"], ioc_id=payload["ioc_id"], severity=payload["severity"]
                    )
            except Exception as exc:  # noqa: BLE001 — one bad message must not kill the subscriber
                logger.error("failed to process ioc hit message %r: %s", message, exc)
    finally:
        await pubsub.unsubscribe(HITS_CHANNEL)
        await pubsub.aclose()
