"""Pipeline observability.

The two signals that actually matter are **lag** (stream backlog) and **time
since the last event**. A pipeline can look healthy on throughput alone while
being an hour behind, or be at zero lag because nothing is arriving at all.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.config import settings
from app.core.redis import get_redis
from app.db.session import get_db
from app.models.event import Event
from app.models.user import User
from app.pipeline.partitions import list_partitions
from app.pipeline.retention import enforce_retention
from app.pipeline.tailer import METRICS_KEY, STREAM_KEY

logger = logging.getLogger("sentinelcore.pipeline.api")

router = APIRouter(prefix="/pipeline", tags=["pipeline"])

# Beyond this the pipeline is considered stalled by the UI.
STALL_LAG_THRESHOLD = 10_000
STALL_SECONDS_THRESHOLD = 300


class PipelineStatusOut(BaseModel):
    reader_offset: int = 0
    lines_read: int = 0
    parse_errors: int = 0
    rotations: int = 0

    events_written: int = 0
    duplicates_skipped: int = 0

    stream_length: int = 0
    pending: int = 0

    events_last_minute: int = 0
    events_per_second: float = 0.0

    last_event_ts: datetime | None = None
    seconds_since_last_event: float | None = None
    last_write_ts: datetime | None = None

    tailer_heartbeat: float | None = None
    writer_heartbeat: float | None = None

    stalled: bool = False
    stall_reason: str | None = None
    redis_available: bool = True

    total_events: int = 0
    partitions: list[str] = Field(default_factory=list)


def _as_int(mapping: dict, key: str) -> int:
    raw = mapping.get(key.encode()) or mapping.get(key)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _as_float(mapping: dict, key: str) -> float | None:
    raw = mapping.get(key.encode()) or mapping.get(key)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


@router.get("/status", response_model=PipelineStatusOut)
async def pipeline_status(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> PipelineStatusOut:
    """Viewer-readable. Degrades rather than failing when Redis is down."""
    out = PipelineStatusOut()

    try:
        redis = get_redis()
        metrics = await redis.hgetall(METRICS_KEY) or {}
        out.reader_offset = _as_int(metrics, "tailer_offset")
        out.lines_read = _as_int(metrics, "lines_read")
        out.parse_errors = _as_int(metrics, "parse_errors") + _as_int(
            metrics, "writer_parse_errors"
        )
        out.rotations = _as_int(metrics, "rotations")
        out.events_written = _as_int(metrics, "events_written")
        out.duplicates_skipped = _as_int(metrics, "duplicates_skipped")
        out.tailer_heartbeat = _as_float(metrics, "tailer_heartbeat")
        out.writer_heartbeat = _as_float(metrics, "writer_heartbeat")

        last_write = _as_float(metrics, "last_write_ts")
        if last_write:
            out.last_write_ts = datetime.fromtimestamp(last_write, tz=timezone.utc)

        out.stream_length = await redis.xlen(STREAM_KEY)
    except Exception as exc:  # noqa: BLE001
        logger.warning("pipeline metrics unavailable: %s", exc)
        out.redis_available = False

    now = datetime.now(timezone.utc)

    out.last_event_ts = await db.scalar(select(func.max(Event.ts)))
    if out.last_event_ts is not None:
        out.seconds_since_last_event = (now - out.last_event_ts).total_seconds()

    out.events_last_minute = int(
        await db.scalar(
            select(func.count()).select_from(Event).where(Event.ts >= now - timedelta(minutes=1))
        )
        or 0
    )
    out.events_per_second = round(out.events_last_minute / 60.0, 3)

    # Cheap estimate; an exact count on a partitioned table is a full scan.
    out.total_events = int(
        await db.scalar(
            text(
                "SELECT COALESCE(SUM(n_live_tup), 0) FROM pg_stat_user_tables "
                "WHERE relname LIKE 'events_p%'"
            )
        )
        or 0
    )

    out.partitions = [name for name, _bounds, _ in await list_partitions(db)]

    if out.stream_length > STALL_LAG_THRESHOLD:
        out.stalled = True
        out.stall_reason = f"Stream backlog is {out.stream_length} records"
    elif (
        out.seconds_since_last_event is not None
        and out.seconds_since_last_event > STALL_SECONDS_THRESHOLD
    ):
        out.stalled = True
        out.stall_reason = (
            f"No events for {int(out.seconds_since_last_event)}s — the sensor may be blind"
        )

    return out


@router.post("/retention/run")
async def run_retention(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> dict:
    """Manually trigger a retention pass. The worker also does this daily."""
    try:
        return await enforce_retention(db)
    except Exception as exc:  # noqa: BLE001
        logger.exception("retention run failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Retention pass failed",
        ) from exc


@router.get("/partitions")
async def get_partitions(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> dict:
    return {
        "retention_days": settings.event_retention_days,
        "partitions": [{"name": name, "bounds": bounds} for name, bounds, _ in await list_partitions(db)],
    }
