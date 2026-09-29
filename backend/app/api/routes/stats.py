"""U05 — dashboard stats: top talkers for the Overview page.

Deliberately reuses M6's filter/cache machinery (`app.services.event_search`)
rather than inventing a second query path: `top_n_subquery` is the exact
`GROUP BY ... ORDER BY count DESC LIMIT n` `/events/facets` already uses, and
the facet-cache key is built the same TTL-bucketed way (bug #4 in
TEST_REPORT.md was a cache key that embedded `datetime.now()` and therefore
never hit — see `EventFilters.cache_key`).
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from enum import Enum

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.redis import get_redis
from app.db.session import get_db
from app.models.asset import Asset
from app.models.event import Event
from app.models.user import User
from app.schemas.stats import TopTalkerBucket, TopTalkersOut
from app.services.event_search import EventFilters, apply_filters

router = APIRouter(prefix="/stats", tags=["stats"])

_MAX_LIMIT = 50
_DEFAULT_LIMIT = 10

_WINDOWS = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}


class TopTalkersBy(str, Enum):
    SRC = "src"
    DEST = "dest"
    SIGNATURE = "signature"


_COLUMN_BY = {
    TopTalkersBy.SRC: Event.src_ip,
    TopTalkersBy.DEST: Event.dst_ip,
    TopTalkersBy.SIGNATURE: Event.signature,
}


def _infra_ips() -> list[str]:
    """Gateway/DNS/self — the same set M10's protection guard refuses to
    ever block. Doubles as "the platform's own IPs" here."""
    return [str(ip) for ip in settings.protected_ips_parsed]


@router.get("/top-talkers", response_model=TopTalkersOut)
async def get_top_talkers(
    window: str = Query("24h", pattern="^(1h|24h|7d)$"),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    by: TopTalkersBy = Query(TopTalkersBy.SRC),
    exclude_infra: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> TopTalkersOut:
    to_ts = datetime.now(timezone.utc)
    from_ts = to_ts - _WINDOWS[window]
    filters = EventFilters(from_ts=from_ts, to_ts=to_ts)

    cache_payload = {
        **json.loads(filters.cache_key(bucket_seconds=settings.search_facet_cache_seconds)),
        "by": by.value,
        "limit": limit,
        "exclude_infra": exclude_infra,
    }
    cache_key = "stats:top-talkers:" + hashlib.sha256(
        json.dumps(cache_payload, sort_keys=True).encode()
    ).hexdigest()

    redis = get_redis()
    cached = await redis.get(cache_key)
    if cached:
        return TopTalkersOut.model_validate(json.loads(cached)).model_copy(update={"cached": True})

    start = time.perf_counter()
    column = _COLUMN_BY[by]

    stmt = (
        select(
            column.label("value"),
            func.count().label("count"),
            # Postgres enum comparison follows declaration order
            # (critical, high, medium, low, info) — MIN, not MAX, gives the
            # most severe value. See app/models/event.py::Severity.
            func.min(Event.severity).label("max_severity"),
            func.bool_or(Event.ioc_match).label("ioc_match"),
        )
        .select_from(Event)
    )
    stmt = apply_filters(stmt, filters)
    stmt = stmt.where(column.is_not(None))
    if exclude_infra and by in (TopTalkersBy.SRC, TopTalkersBy.DEST):
        infra = _infra_ips()
        if infra:
            # `host()` extracts just the address as text (no /mask), so this
            # compares like-for-like regardless of how the INET value or the
            # configured PROTECTED_IPS entries are formatted.
            stmt = stmt.where(func.host(column).not_in(infra))
    stmt = stmt.group_by(column).order_by(func.count().desc()).limit(limit)

    rows = (await db.execute(stmt)).all()
    # asyncpg returns INET columns as ipaddress.IPv4Address/IPv6Address, not
    # str — normalise to text once here so both the API response and the
    # hostname lookup below use a plain string key.
    values_as_text = [str(r.value) for r in rows]

    hostnames: dict[str, str] = {}
    if by in (TopTalkersBy.SRC, TopTalkersBy.DEST) and rows:
        asset_rows = await db.execute(
            select(Asset.ip_address, Asset.hostname).where(
                # `host()` avoids inet/varchar operator mismatch — same
                # technique as the exclude_infra filter above.
                func.host(Asset.ip_address).in_(values_as_text),
                Asset.hostname.is_not(None),
            )
        )
        hostnames = {str(ip): hostname for ip, hostname in asset_rows.all()}

    items = [
        TopTalkerBucket(
            value=value_text,
            count=r.count,
            max_severity=r.max_severity,
            ioc_match=bool(r.ioc_match),
            hostname=hostnames.get(value_text),
        )
        for r, value_text in zip(rows, values_as_text)
    ]

    result = TopTalkersOut(
        by=by.value, window=window, items=items, took_ms=int((time.perf_counter() - start) * 1000)
    )
    await redis.set(cache_key, result.model_dump_json(), ex=settings.search_facet_cache_seconds)
    return result
