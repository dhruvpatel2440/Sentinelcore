"""M6 — event search: query API, detail view, facets, saved searches."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.config import settings
from app.core.redis import get_redis
from app.db.session import get_db
from app.models.asset import Asset
from app.models.event import Event, EventType, Severity
from app.models.saved_search import SavedSearch
from app.models.user import User
from app.schemas.event import (
    AssetSummaryOut,
    EventDetailOut,
    EventFacetsOut,
    EventListOut,
    EventOut,
    FacetBucket,
    SavedSearchIn,
    SavedSearchOut,
    SavedSearchUpdate,
)
from app.services import audit
from app.services.event_search import (
    CursorError,
    EventFilters,
    apply_cursor,
    apply_filters,
    encode_cursor,
    top_n_subquery,
    validate_cidr,
)

router = APIRouter(prefix="/events", tags=["events"])

_DEFAULT_WINDOW = timedelta(hours=24)
_FACET_TOP_N = 10
_CAPPED_COUNT_LIMIT = 10_000


def _resolve_window(from_: datetime | None, to: datetime | None) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    to_ts = to or now
    from_ts = from_ or (to_ts - _DEFAULT_WINDOW)

    if from_ts.tzinfo is None:
        from_ts = from_ts.replace(tzinfo=timezone.utc)
    if to_ts.tzinfo is None:
        to_ts = to_ts.replace(tzinfo=timezone.utc)

    if to_ts <= from_ts:
        raise HTTPException(status_code=422, detail="'to' must be after 'from'")

    max_window = timedelta(days=settings.max_search_window_days)
    if to_ts - from_ts > max_window:
        raise HTTPException(
            status_code=422,
            detail=f"search window exceeds the {settings.max_search_window_days}-day maximum",
        )
    return from_ts, to_ts


def _validated_cidr(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    try:
        return validate_cidr(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{field}: {exc}") from exc


def _build_filters(
    from_: datetime | None,
    to: datetime | None,
    severity: list[Severity],
    event_type: list[EventType],
    src_ip: str | None,
    dst_ip: str | None,
    ip: str | None,
    port: int | None,
    proto: str | None,
    signature_id: list[int],
    q: str | None,
    asset_id: uuid.UUID | None,
) -> EventFilters:
    from_ts, to_ts = _resolve_window(from_, to)
    return EventFilters(
        from_ts=from_ts,
        to_ts=to_ts,
        severity=severity,
        event_type=event_type,
        src_ip=_validated_cidr(src_ip, "src_ip"),
        dst_ip=_validated_cidr(dst_ip, "dst_ip"),
        ip=_validated_cidr(ip, "ip"),
        port=port,
        proto=proto,
        signature_id=signature_id,
        q=q,
        asset_id=str(asset_id) if asset_id else None,
    )


# ---------------------------------------------------------------------------
# Saved searches — registered before /{id} so "searches" is never parsed as an
# event id.
# ---------------------------------------------------------------------------


@router.get("/searches", response_model=list[SavedSearchOut])
async def list_saved_searches(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[SavedSearchOut]:
    stmt = select(SavedSearch).where(
        (SavedSearch.user_id == user.id) | (SavedSearch.is_shared.is_(True))
    ).order_by(SavedSearch.name)
    result = await db.execute(stmt)
    items = result.scalars().all()
    return [
        SavedSearchOut.model_validate(s, from_attributes=True).model_copy(
            update={"is_owner": s.user_id == user.id}
        )
        for s in items
    ]


@router.post("/searches", response_model=SavedSearchOut, status_code=status.HTTP_201_CREATED)
async def create_saved_search(
    payload: SavedSearchIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> SavedSearchOut:
    saved = SavedSearch(
        user_id=user.id, name=payload.name, filters=payload.filters, is_shared=payload.is_shared
    )
    db.add(saved)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"you already have a saved search named {payload.name!r}",
        ) from exc

    await audit.record(
        db,
        action="event.saved_search_created",
        user=user,
        resource_type="saved_search",
        resource_id=saved.id,
        detail={"name": saved.name, "is_shared": saved.is_shared},
        request=request,
    )
    await db.commit()
    await db.refresh(saved)
    return SavedSearchOut.model_validate(saved, from_attributes=True).model_copy(
        update={"is_owner": True}
    )


async def _get_owned_saved_search(db: AsyncSession, search_id: uuid.UUID, user: User) -> SavedSearch:
    saved = await db.get(SavedSearch, search_id)
    if saved is None:
        raise HTTPException(status_code=404, detail="Saved search not found")
    if saved.user_id != user.id:
        raise HTTPException(status_code=403, detail="You can only modify your own saved searches")
    return saved


@router.patch("/searches/{search_id}", response_model=SavedSearchOut)
async def update_saved_search(
    search_id: uuid.UUID,
    payload: SavedSearchUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> SavedSearchOut:
    saved = await _get_owned_saved_search(db, search_id, user)

    changes = payload.model_dump(exclude_unset=True)
    for field_name, value in changes.items():
        setattr(saved, field_name, value)

    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"you already have a saved search named {payload.name!r}",
        ) from exc

    await audit.record(
        db,
        action="event.saved_search_updated",
        user=user,
        resource_type="saved_search",
        resource_id=saved.id,
        detail=changes,
        request=request,
    )
    await db.commit()
    await db.refresh(saved)
    return SavedSearchOut.model_validate(saved, from_attributes=True).model_copy(
        update={"is_owner": True}
    )


@router.delete("/searches/{search_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_saved_search(
    search_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    saved = await _get_owned_saved_search(db, search_id, user)
    await db.delete(saved)
    await audit.record(
        db,
        action="event.saved_search_deleted",
        user=user,
        resource_type="saved_search",
        resource_id=search_id,
        detail={"name": saved.name},
        request=request,
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Facets — also registered before /{id}.
# ---------------------------------------------------------------------------


@router.get("/facets", response_model=EventFacetsOut)
async def get_event_facets(
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    severity: list[Severity] = Query(default=[]),
    event_type: list[EventType] = Query(default=[]),
    src_ip: str | None = Query(default=None),
    dst_ip: str | None = Query(default=None),
    ip: str | None = Query(default=None),
    port: int | None = Query(default=None, ge=1, le=65535),
    proto: str | None = Query(default=None, max_length=8),
    signature_id: list[int] = Query(default=[]),
    q: str | None = Query(default=None, max_length=255),
    asset_id: uuid.UUID | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> EventFacetsOut:
    filters = _build_filters(
        from_, to, severity, event_type, src_ip, dst_ip, ip, port, proto, signature_id, q, asset_id
    )

    cache_key = "events:facets:" + hashlib.sha256(filters.cache_key().encode()).hexdigest()
    redis = get_redis()
    cached = await redis.get(cache_key)
    if cached:
        return EventFacetsOut.model_validate(json.loads(cached)).model_copy(update={"cached": True})

    start = time.perf_counter()

    async def _bucket(stmt) -> list[FacetBucket]:
        rows = await db.execute(stmt)
        return [
            FacetBucket(value=v.value if hasattr(v, "value") else str(v), count=c)
            for v, c in rows.all()
        ]

    severity_stmt = top_n_subquery(Event.severity, filters, limit=len(Severity))
    event_type_stmt = top_n_subquery(Event.event_type, filters, limit=len(EventType))
    sig_stmt = top_n_subquery(Event.signature, filters, limit=_FACET_TOP_N)
    src_stmt = top_n_subquery(Event.src_ip, filters, limit=_FACET_TOP_N)
    dst_stmt = top_n_subquery(Event.dst_ip, filters, limit=_FACET_TOP_N)

    result = EventFacetsOut(
        severity=await _bucket(severity_stmt),
        event_type=await _bucket(event_type_stmt),
        top_signatures=await _bucket(sig_stmt),
        top_src_ips=await _bucket(src_stmt),
        top_dst_ips=await _bucket(dst_stmt),
        took_ms=int((time.perf_counter() - start) * 1000),
    )

    await redis.set(cache_key, result.model_dump_json(), ex=settings.search_facet_cache_seconds)
    return result


# ---------------------------------------------------------------------------
# Core query API
# ---------------------------------------------------------------------------


@router.get("", response_model=EventListOut)
async def list_events(
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    severity: list[Severity] = Query(default=[]),
    event_type: list[EventType] = Query(default=[]),
    src_ip: str | None = Query(default=None),
    dst_ip: str | None = Query(default=None),
    ip: str | None = Query(default=None),
    port: int | None = Query(default=None, ge=1, le=65535),
    proto: str | None = Query(default=None, max_length=8),
    signature_id: list[int] = Query(default=[]),
    q: str | None = Query(default=None, max_length=255),
    asset_id: uuid.UUID | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    sort: str = Query(default="ts_desc", pattern="^(ts_desc|ts_asc)$"),
    count: bool = Query(default=False, description="Opt in to a capped result count"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> EventListOut:
    filters = _build_filters(
        from_, to, severity, event_type, src_ip, dst_ip, ip, port, proto, signature_id, q, asset_id
    )
    sort_desc = sort == "ts_desc"

    start = time.perf_counter()

    stmt = select(Event)
    stmt = apply_filters(stmt, filters)
    try:
        stmt = apply_cursor(stmt, cursor=cursor, sort_desc=sort_desc)
    except CursorError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    order = (Event.ts.desc(), Event.id.desc()) if sort_desc else (Event.ts.asc(), Event.id.asc())
    stmt = stmt.order_by(*order).limit(limit + 1)

    result = await db.execute(stmt)
    rows = result.scalars().all()

    has_more = len(rows) > limit
    rows = rows[:limit]

    next_cursor = encode_cursor(rows[-1].ts, rows[-1].id) if has_more and rows else None

    capped_count = None
    if count:
        count_stmt = select(func.count()).select_from(
            apply_filters(select(Event.id), filters).limit(_CAPPED_COUNT_LIMIT).subquery()
        )
        capped_count = int(await db.scalar(count_stmt) or 0)

    return EventListOut(
        items=[EventOut.model_validate(r, from_attributes=True) for r in rows],
        next_cursor=next_cursor,
        took_ms=int((time.perf_counter() - start) * 1000),
        has_more=has_more,
        capped_count=capped_count,
    )


@router.get("/{event_id}", response_model=EventDetailOut)
async def get_event(
    event_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> EventDetailOut:
    event = await db.scalar(select(Event).where(Event.id == event_id))
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")

    related: list[Event] = []
    if event.flow_id is not None:
        related_result = await db.execute(
            select(Event)
            .where(Event.flow_id == event.flow_id, Event.id != event.id)
            .order_by(Event.ts.asc())
            .limit(200)
        )
        related = list(related_result.scalars().all())

    src_asset = await db.get(Asset, event.src_asset_id) if event.src_asset_id else None
    dst_asset = await db.get(Asset, event.dst_asset_id) if event.dst_asset_id else None

    sig_count = 0
    if event.signature_id is not None:
        now = datetime.now(timezone.utc)
        sig_count = int(
            await db.scalar(
                select(func.count())
                .select_from(Event)
                .where(
                    Event.signature_id == event.signature_id,
                    Event.ts >= now - timedelta(hours=24),
                    Event.ts <= now,
                )
            )
            or 0
        )

    return EventDetailOut(
        **EventOut.model_validate(event, from_attributes=True).model_dump(),
        raw=event.raw,
        src_asset=AssetSummaryOut.model_validate(src_asset, from_attributes=True) if src_asset else None,
        dst_asset=AssetSummaryOut.model_validate(dst_asset, from_attributes=True) if dst_asset else None,
        related_flow_events=[EventOut.model_validate(r, from_attributes=True) for r in related],
        signature_24h_count=sig_count,
    )
