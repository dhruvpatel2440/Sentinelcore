"""M12 — threat intelligence: IOC CRUD, lookup, feed sources, matches, retro-hunt.

Feed-sourced IOCs can only be deactivated, never edited — an edit would be
silently reverted by the next scheduled refresh, which is worse than not
allowing the edit at all.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import cast, func, select
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.redis import get_redis
from app.db.session import SessionLocal, get_db
from app.intel import feeds
from app.intel.matcher import rebuild_index, retrohunt
from app.intel.normalize import NormalizationError, normalize
from app.models.ioc import Ioc, IocMatch, IocSeverity, IocSource, IocType
from app.models.user import User
from app.schemas.intel import (
    IntelStatsOut,
    IocBulkCreate,
    IocBulkResult,
    IocBulkResultLine,
    IocCreate,
    IocDetailOut,
    IocMatchOut,
    IocOut,
    IocSourceCreate,
    IocSourceOut,
    IocSourceUpdate,
    IocUpdate,
    LookupResult,
    RetrohuntAccepted,
    RetrohuntRequest,
)
from app.services import audit

router = APIRouter(prefix="/intel", tags=["intel"])


async def _match_counts(db: AsyncSession, ioc_ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
    if not ioc_ids:
        return {}
    rows = (
        await db.execute(
            select(IocMatch.ioc_id, func.count()).where(IocMatch.ioc_id.in_(ioc_ids)).group_by(IocMatch.ioc_id)
        )
    ).all()
    return {ioc_id: count for ioc_id, count in rows}


def _ioc_out(ioc: Ioc, match_count: int = 0, source_name: str | None = None) -> IocOut:
    out = IocOut.model_validate(ioc, from_attributes=True)
    out.match_count = match_count
    out.source_name = source_name
    return out


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------


@router.get("/iocs", response_model=list[IocOut])
async def list_iocs(
    ioc_type: IocType | None = Query(default=None),
    severity: IocSeverity | None = Query(default=None),
    source_id: uuid.UUID | None = Query(default=None),
    threat_type: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    q: str | None = Query(default=None),
    has_matches: bool | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[IocOut]:
    stmt = select(Ioc)
    if ioc_type:
        stmt = stmt.where(Ioc.ioc_type == ioc_type)
    if severity:
        stmt = stmt.where(Ioc.severity == severity)
    if source_id:
        stmt = stmt.where(Ioc.source_id == source_id)
    if threat_type:
        stmt = stmt.where(Ioc.threat_type == threat_type)
    if tag:
        stmt = stmt.where(Ioc.tags.op("@>")(cast([tag], JSONB)))
    if is_active is not None:
        stmt = stmt.where(Ioc.is_active == is_active)
    if q:
        stmt = stmt.where(Ioc.indicator.ilike(f"%{q}%"))

    stmt = stmt.order_by(Ioc.last_seen.desc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()

    counts = await _match_counts(db, [r.id for r in rows])
    if has_matches is not None:
        rows = [r for r in rows if bool(counts.get(r.id, 0)) == has_matches]

    source_ids = {r.source_id for r in rows if r.source_id}
    sources = {}
    if source_ids:
        sources = {
            s.id: s.name for s in (await db.execute(select(IocSource).where(IocSource.id.in_(source_ids)))).scalars()
        }

    return [_ioc_out(r, counts.get(r.id, 0), sources.get(r.source_id)) for r in rows]


@router.post("/iocs", response_model=IocOut, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    payload: IocCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> IocOut:
    try:
        normalized = normalize(payload.indicator, payload.ioc_type)
    except NormalizationError as exc:
        raise HTTPException(status_code=400, detail=exc.reason) from exc

    existing = (
        await db.execute(
            select(Ioc).where(Ioc.indicator == normalized.value, Ioc.ioc_type == normalized.ioc_type, Ioc.source_id.is_(None))
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="This indicator is already tracked manually")

    now = datetime.now(timezone.utc)
    ioc = Ioc(
        indicator=normalized.value, ioc_type=normalized.ioc_type, cidr_shadow=normalized.cidr_shadow,
        source_id=None, confidence=payload.confidence, severity=payload.severity, threat_type=payload.threat_type,
        description=payload.description, tags=payload.tags, first_seen=now, last_seen=now,
        expires_at=payload.expires_at, is_active=True, added_by=actor.id,
    )
    db.add(ioc)
    await db.flush()

    await audit.record(
        db, action="intel.ioc_created", user=actor, resource_type="ioc", resource_id=ioc.id,
        detail={"indicator": ioc.indicator, "ioc_type": ioc.ioc_type.value}, request=request,
    )
    await db.commit()
    await db.refresh(ioc)
    await rebuild_index(db, get_redis())
    return _ioc_out(ioc)


@router.post("/iocs/bulk", response_model=IocBulkResult)
async def bulk_create_iocs(
    payload: IocBulkCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> IocBulkResult:
    now = datetime.now(timezone.utc)
    results: list[IocBulkResultLine] = []

    for raw_line in payload.indicators:
        line = raw_line.strip()
        if not line:
            continue
        try:
            normalized = normalize(line, payload.ioc_type)
        except NormalizationError as exc:
            results.append(IocBulkResultLine(input=line, accepted=False, reason=exc.reason))
            continue

        existing = (
            await db.execute(
                select(Ioc).where(Ioc.indicator == normalized.value, Ioc.ioc_type == normalized.ioc_type, Ioc.source_id.is_(None))
            )
        ).scalar_one_or_none()
        if existing is not None:
            results.append(IocBulkResultLine(input=line, accepted=False, reason="already tracked", ioc_id=existing.id))
            continue

        ioc = Ioc(
            indicator=normalized.value, ioc_type=normalized.ioc_type, cidr_shadow=normalized.cidr_shadow,
            source_id=None, confidence=payload.confidence, severity=payload.severity, threat_type=payload.threat_type,
            description=payload.description, tags=payload.tags, first_seen=now, last_seen=now, is_active=True,
            added_by=actor.id,
        )
        db.add(ioc)
        await db.flush()
        results.append(IocBulkResultLine(input=line, accepted=True, ioc_id=ioc.id))

    accepted_count = sum(1 for r in results if r.accepted)
    await audit.record(
        db, action="intel.ioc_bulk_created", user=actor, resource_type="ioc",
        detail={"accepted": accepted_count, "rejected": len(results) - accepted_count}, request=request,
    )
    await db.commit()
    if accepted_count:
        await rebuild_index(db, get_redis())

    return IocBulkResult(results=results, accepted_count=accepted_count, rejected_count=len(results) - accepted_count)


async def _get_ioc(db: AsyncSession, ioc_id: uuid.UUID) -> Ioc:
    ioc = await db.get(Ioc, ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc


@router.get("/iocs/{ioc_id}", response_model=IocDetailOut)
async def get_ioc(
    ioc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> IocDetailOut:
    ioc = await _get_ioc(db, ioc_id)
    counts = await _match_counts(db, [ioc.id])
    source_name = None
    if ioc.source_id:
        source = await db.get(IocSource, ioc.source_id)
        source_name = source.name if source else None

    matches = (
        await db.execute(select(IocMatch).where(IocMatch.ioc_id == ioc.id).order_by(IocMatch.ts.desc()).limit(50))
    ).scalars().all()

    from app.models.event import Event

    event_ids = [m.event_id for m in matches if m.event_id]
    assets: set[str] = set()
    if event_ids:
        rows = (
            await db.execute(select(Event.src_ip, Event.dst_ip).where(Event.id.in_(event_ids)))
        ).all()
        for src_ip, dst_ip in rows:
            if src_ip:
                assets.add(str(src_ip))
            if dst_ip:
                assets.add(str(dst_ip))

    out = IocDetailOut.model_validate(ioc, from_attributes=True)
    out.match_count = counts.get(ioc.id, 0)
    out.source_name = source_name
    out.recent_matches = [IocMatchOut.model_validate(m, from_attributes=True) for m in matches]
    out.affected_assets = sorted(assets)
    return out


@router.patch("/iocs/{ioc_id}", response_model=IocOut)
async def update_ioc(
    ioc_id: uuid.UUID,
    payload: IocUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> IocOut:
    ioc = await _get_ioc(db, ioc_id)

    data = payload.model_dump(exclude_unset=True)
    if ioc.source_id is not None:
        # Feed-sourced IOCs can only be deactivated — any other edit would be
        # silently reverted by the next scheduled refresh.
        allowed = set(data.keys()) <= {"is_active"}
        if not allowed:
            raise HTTPException(
                status_code=403,
                detail="Feed-sourced IOCs can only be deactivated; edit the source's parser_config instead",
            )

    for field, value in data.items():
        setattr(ioc, field, value)

    await audit.record(
        db, action="intel.ioc_updated", user=actor, resource_type="ioc", resource_id=ioc.id, detail=data, request=request,
    )
    await db.commit()
    await db.refresh(ioc)
    await rebuild_index(db, get_redis())
    return _ioc_out(ioc)


@router.delete("/iocs/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_ioc(
    ioc_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> None:
    ioc = await _get_ioc(db, ioc_id)
    if ioc.source_id is not None:
        raise HTTPException(status_code=403, detail="Feed-sourced IOCs can only be deactivated, not deleted")

    await audit.record(
        db, action="intel.ioc_deleted", user=actor, resource_type="ioc", resource_id=ioc.id,
        detail={"indicator": ioc.indicator}, request=request,
    )
    await db.delete(ioc)
    await db.commit()
    await rebuild_index(db, get_redis())


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


@router.get("/lookup", response_model=LookupResult)
async def lookup(
    value: str = Query(min_length=1),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> LookupResult:
    try:
        normalized = normalize(value)
    except NormalizationError:
        return LookupResult(query=value, normalized=None, ioc_type=None, found=False)

    stmt = select(Ioc).where(Ioc.indicator == normalized.value, Ioc.ioc_type == normalized.ioc_type, Ioc.is_active.is_(True))
    matches = (await db.execute(stmt)).scalars().all()

    # CIDR containment for a plain IP query, not just exact hits.
    if normalized.ioc_type == IocType.IP:
        cidr_rows = (
            await db.execute(
                select(Ioc).where(Ioc.ioc_type == IocType.CIDR, Ioc.is_active.is_(True), Ioc.cidr_shadow.op(">>=")(cast(normalized.value, INET)))
            )
        ).scalars().all()
        matches = list(matches) + list(cidr_rows)

    counts = await _match_counts(db, [m.id for m in matches])
    return LookupResult(
        query=value, normalized=normalized.value, ioc_type=normalized.ioc_type, found=bool(matches),
        matches=[_ioc_out(m, counts.get(m.id, 0)) for m in matches],
    )


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


@router.get("/sources", response_model=list[IocSourceOut])
async def list_sources(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> list[IocSourceOut]:
    rows = (await db.execute(select(IocSource).order_by(IocSource.name))).scalars().all()
    return [IocSourceOut.model_validate(r, from_attributes=True) for r in rows]


@router.post("/sources", response_model=IocSourceOut, status_code=status.HTTP_201_CREATED)
async def create_source(
    payload: IocSourceCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> IocSourceOut:
    source = IocSource(**payload.model_dump())
    db.add(source)
    await db.flush()
    await audit.record(
        db, action="intel.source_created", user=actor, resource_type="ioc_source", resource_id=source.id,
        detail={"name": source.name, "url": source.url}, request=request,
    )
    await db.commit()
    await db.refresh(source)
    return IocSourceOut.model_validate(source, from_attributes=True)


async def _get_source(db: AsyncSession, source_id: uuid.UUID) -> IocSource:
    source = await db.get(IocSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    return source


@router.patch("/sources/{source_id}", response_model=IocSourceOut)
async def update_source(
    source_id: uuid.UUID,
    payload: IocSourceUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> IocSourceOut:
    source = await _get_source(db, source_id)
    data = payload.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(source, field, value)

    await audit.record(
        db, action="intel.source_updated", user=actor, resource_type="ioc_source", resource_id=source.id, detail=data, request=request,
    )
    await db.commit()
    await db.refresh(source)
    return IocSourceOut.model_validate(source, from_attributes=True)


@router.delete("/sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_source(
    source_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> None:
    source = await _get_source(db, source_id)
    await audit.record(
        db, action="intel.source_deleted", user=actor, resource_type="ioc_source", resource_id=source.id,
        detail={"name": source.name}, request=request,
    )
    await db.delete(source)
    await db.commit()
    await rebuild_index(db, get_redis())


async def _refresh_source_task(source_id: uuid.UUID) -> None:
    async with SessionLocal() as db:
        source = await db.get(IocSource, source_id)
        if source is not None:
            await feeds.refresh_source(db, source, get_redis())


@router.post("/sources/{source_id}/refresh", status_code=status.HTTP_202_ACCEPTED)
async def refresh_source_now(
    source_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> dict:
    source = await _get_source(db, source_id)
    await audit.record(
        db, action="intel.source_refresh_requested", user=actor, resource_type="ioc_source", resource_id=source.id, request=request,
    )
    await db.commit()
    background_tasks.add_task(_refresh_source_task, source.id)
    return {"accepted": True}


# ---------------------------------------------------------------------------
# Matches
# ---------------------------------------------------------------------------


@router.get("/matches", response_model=list[IocMatchOut])
async def list_matches(
    since: datetime | None = Query(default=None),
    severity: IocSeverity | None = Query(default=None),
    ioc_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[IocMatchOut]:
    stmt = select(IocMatch, Ioc.indicator, Ioc.severity).join(Ioc, Ioc.id == IocMatch.ioc_id)
    if since:
        stmt = stmt.where(IocMatch.ts >= since)
    if ioc_id:
        stmt = stmt.where(IocMatch.ioc_id == ioc_id)
    if severity:
        stmt = stmt.where(Ioc.severity == severity)
    stmt = stmt.order_by(IocMatch.ts.desc()).limit(limit).offset(offset)

    rows = (await db.execute(stmt)).all()
    out = []
    for match, indicator, sev in rows:
        item = IocMatchOut.model_validate(match, from_attributes=True)
        item.indicator = indicator
        item.severity = sev
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Retro-hunt
# ---------------------------------------------------------------------------


async def _retrohunt_task(ioc_id: uuid.UUID | None, source_id: uuid.UUID | None, days: int) -> None:
    async with SessionLocal() as db:
        await retrohunt(db, get_redis(), ioc_id=ioc_id, source_id=source_id, days=days)


@router.post("/retrohunt", response_model=RetrohuntAccepted, status_code=status.HTTP_202_ACCEPTED)
async def start_retrohunt(
    payload: RetrohuntRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> RetrohuntAccepted:
    if not payload.ioc_id and not payload.source_id:
        raise HTTPException(status_code=400, detail="ioc_id or source_id is required")

    await audit.record(
        db, action="intel.retrohunt_started", user=actor, resource_type="ioc",
        resource_id=payload.ioc_id, detail={"source_id": str(payload.source_id) if payload.source_id else None, "days": payload.days},
        request=request,
    )
    await db.commit()
    background_tasks.add_task(_retrohunt_task, payload.ioc_id, payload.source_id, payload.days)
    return RetrohuntAccepted(days=payload.days)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=IntelStatsOut)
async def stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> IntelStatsOut:
    now = datetime.now(timezone.utc)

    by_type_rows = (
        await db.execute(select(Ioc.ioc_type, func.count()).where(Ioc.is_active.is_(True)).group_by(Ioc.ioc_type))
    ).all()
    by_source_rows = (
        await db.execute(
            select(IocSource.name, func.count(Ioc.id))
            .join(Ioc, Ioc.source_id == IocSource.id)
            .where(Ioc.is_active.is_(True))
            .group_by(IocSource.name)
        )
    ).all()
    matches_24h = await db.scalar(select(func.count()).select_from(IocMatch).where(IocMatch.ts >= now - timedelta(hours=24))) or 0
    matches_7d = await db.scalar(select(func.count()).select_from(IocMatch).where(IocMatch.ts >= now - timedelta(days=7))) or 0

    top_matched_rows = (
        await db.execute(
            select(Ioc.indicator, Ioc.severity, func.count(IocMatch.id).label("n"))
            .join(IocMatch, IocMatch.ioc_id == Ioc.id)
            .group_by(Ioc.indicator, Ioc.severity)
            .order_by(func.count(IocMatch.id).desc())
            .limit(10)
        )
    ).all()

    sources = (await db.execute(select(IocSource).order_by(IocSource.name))).scalars().all()

    return IntelStatsOut(
        active_by_type={t.value: c for t, c in by_type_rows},
        active_by_source={n: c for n, c in by_source_rows},
        matches_last_24h=matches_24h,
        matches_last_7d=matches_7d,
        top_matched=[{"indicator": i, "severity": s.value, "count": n} for i, s, n in top_matched_rows],
        source_health=[IocSourceOut.model_validate(s, from_attributes=True) for s in sources],
    )
