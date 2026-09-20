"""Monthly partition management for `events`.

Partitions are pre-created ahead of time. A missing partition makes every
INSERT fail, so this runs on worker startup and then daily.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sentinelcore.pipeline.partitions")

# How many future months to keep ready. Two is enough that a stuck job has a
# full month of slack before inserts start failing.
MONTHS_AHEAD = 2


def month_start(value: date) -> date:
    return value.replace(day=1)


def next_month(value: date) -> date:
    return (month_start(value) + timedelta(days=32)).replace(day=1)


def partition_name(value: date) -> str:
    return f"events_p{value.year:04d}{value.month:02d}"


async def ensure_partition(db: AsyncSession, month: date) -> str:
    """Create one monthly partition if it does not exist. Idempotent."""
    start = month_start(month)
    end = next_month(start)
    name = partition_name(start)

    # Identifiers are derived from a date, never from user input, and the
    # bounds are bound parameters where PostgreSQL allows it. CREATE TABLE
    # cannot parameterise identifiers, hence the f-string on a computed name.
    await db.execute(
        text(
            f"""
            CREATE TABLE IF NOT EXISTS {name}
            PARTITION OF events
            FOR VALUES FROM ('{start.isoformat()}') TO ('{end.isoformat()}')
            """
        )
    )
    return name


async def ensure_partitions(db: AsyncSession, months_ahead: int = MONTHS_AHEAD) -> list[str]:
    """Ensure the current month plus `months_ahead` future months exist."""
    created: list[str] = []
    cursor = month_start(datetime.now(timezone.utc).date())

    for _ in range(months_ahead + 1):
        created.append(await ensure_partition(db, cursor))
        cursor = next_month(cursor)

    await db.commit()
    logger.info("partitions ready: %s", ", ".join(created))
    return created


async def list_partitions(db: AsyncSession) -> list[tuple[str, str, str]]:
    """(name, lower_bound, upper_bound) for every events partition."""
    result = await db.execute(
        text(
            """
            SELECT c.relname,
                   pg_get_expr(c.relpartbound, c.oid) AS bounds
            FROM pg_class c
            JOIN pg_inherits i ON i.inhrelid = c.oid
            JOIN pg_class p ON p.oid = i.inhparent
            WHERE p.relname = 'events'
            ORDER BY c.relname
            """
        )
    )
    return [(row[0], row[1], "") for row in result.all()]
