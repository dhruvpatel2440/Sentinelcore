"""Event retention by partition drop.

Dropping a partition is instant and reclaims space immediately.
`DELETE FROM events WHERE ts < ...` on a large table locks and bloats, and then
needs a VACUUM FULL to give the space back.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.pipeline.partitions import month_start, partition_name

logger = logging.getLogger("sentinelcore.pipeline.retention")

_PARTITION_RE = re.compile(r"\Aevents_p(\d{4})(\d{2})\Z")


async def _partitions_older_than(db: AsyncSession, cutoff_month) -> list[str]:
    result = await db.execute(
        text(
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_inherits i ON i.inhrelid = c.oid
            JOIN pg_class p ON p.oid = i.inhparent
            WHERE p.relname = 'events'
            ORDER BY c.relname
            """
        )
    )

    stale: list[str] = []
    for (name,) in result.all():
        match = _PARTITION_RE.match(name)
        if not match:
            continue  # not one of ours; never touch it
        year, month = int(match.group(1)), int(match.group(2))
        if (year, month) < (cutoff_month.year, cutoff_month.month):
            stale.append(name)
    return stale


async def _has_incident_evidence(db: AsyncSession, partition: str) -> bool:
    """Never drop events referenced by an open incident — M8's evidence trail.

    Returns False when the incidents table does not exist yet (pre-M8).
    """
    exists = await db.scalar(text("SELECT to_regclass('public.incident_events')"))
    if exists is None:
        return False

    # Guard: the identifier is validated against _PARTITION_RE by the caller.
    referenced = await db.scalar(
        text(
            f"""
            SELECT EXISTS (
                SELECT 1
                FROM {partition} e
                JOIN incident_events ie ON ie.event_id = e.id
                JOIN incidents inc ON inc.id = ie.incident_id
                WHERE inc.status <> 'closed'
                LIMIT 1
            )
            """
        )
    )
    return bool(referenced)


async def enforce_retention(db: AsyncSession, retention_days: int | None = None) -> dict:
    """Drop whole partitions older than the retention window."""
    days = retention_days if retention_days is not None else settings.event_retention_days
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_month = month_start(cutoff.date())

    dropped: list[str] = []
    retained: list[str] = []

    for partition in await _partitions_older_than(db, cutoff_month):
        if not _PARTITION_RE.match(partition):
            continue  # belt and braces before it reaches a DDL string

        if await _has_incident_evidence(db, partition):
            logger.warning(
                "retaining %s past its retention window: referenced by an open incident",
                partition,
            )
            retained.append(partition)
            continue

        await db.execute(text(f"DROP TABLE IF EXISTS {partition}"))
        dropped.append(partition)
        logger.info("dropped partition %s (older than %d days)", partition, days)

    await db.commit()
    return {
        "retention_days": days,
        "cutoff_month": partition_name(cutoff_month),
        "dropped": dropped,
        "retained_for_incidents": retained,
    }
