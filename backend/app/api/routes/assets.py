"""Asset inventory and discovery scan control."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, require_role
from app.core.config import settings
from app.db.session import get_db
from app.models.asset import Asset, AssetPort, PortState
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.user import User
from app.schemas.asset import (
    AssetDetailOut,
    AssetListOut,
    AssetOut,
    AssetPortOut,
    AssetUpdate,
    ScanOut,
    ScanRequest,
)
from app.services import audit
from app.services.discovery import run_discovery

router = APIRouter(prefix="/assets", tags=["assets"])


def _open_port_subquery():
    return (
        select(func.count(AssetPort.id))
        .where(AssetPort.asset_id == Asset.id, AssetPort.state == PortState.OPEN)
        .correlate(Asset)
        .scalar_subquery()
    )


@router.post("/scan", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(
    payload: ScanRequest,
    request: Request,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> ScanOut:
    # One scan at a time — concurrent sweeps of the same segment produce
    # confusing results and the helper serialises them anyway.
    running = await db.scalar(
        select(func.count())
        .select_from(Scan)
        .where(Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]))
    )
    if running:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A discovery scan is already running. Wait for it to finish.",
        )

    targets = payload.targets or [str(settings.monitored_network_parsed)]

    scan = Scan(
        scan_type=ScanType.COMBINED,
        status=ScanStatus.QUEUED,
        targets=targets,
        ports=payload.ports,
        mode=payload.mode,
        requested_by=actor.id,
    )
    db.add(scan)
    await db.flush()

    await audit.record(
        db,
        action="asset.scan_started",
        user=actor,
        resource_type="scan",
        resource_id=str(scan.id),
        detail={"targets": targets, "ports": payload.ports, "mode": payload.mode},
        request=request,
    )
    await db.commit()
    await db.refresh(scan)

    background.add_task(run_discovery, scan.id)
    return ScanOut.model_validate(scan)


@router.get("/scans", response_model=list[ScanOut])
async def list_scans(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[ScanOut]:
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(limit))
    return [ScanOut.model_validate(s) for s in result.scalars().all()]


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ScanOut:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return ScanOut.model_validate(scan)


@router.get("", response_model=AssetListOut)
async def list_assets(
    q: str | None = Query(None, max_length=255, description="IP or hostname substring"),
    is_active: bool | None = Query(None),
    has_open_port: bool | None = Query(None),
    sort: str = Query("last_seen", pattern="^(last_seen|ip_address|first_seen)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AssetListOut:
    open_ports = _open_port_subquery()
    stmt = select(Asset, open_ports.label("open_port_count"))

    if is_active is not None:
        stmt = stmt.where(Asset.is_active.is_(is_active))

    if q:
        # Parameterised LIKE — the pattern is a bound parameter, never
        # concatenated into SQL. INET is cast to text so a substring of an
        # address ("192.168.10.") matches.
        pattern = f"%{q}%"
        stmt = stmt.where(
            or_(
                cast(Asset.ip_address, String).ilike(pattern),
                Asset.hostname.ilike(pattern),
                Asset.hostname_override.ilike(pattern),
                Asset.vendor.ilike(pattern),
            )
        )

    if has_open_port is not None:
        stmt = stmt.where(open_ports > 0 if has_open_port else open_ports == 0)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = int(await db.scalar(count_stmt) or 0)

    sort_column = {
        "last_seen": Asset.last_seen,
        "first_seen": Asset.first_seen,
        "ip_address": Asset.ip_address,
    }[sort]
    stmt = stmt.order_by(sort_column.asc() if order == "asc" else sort_column.desc())
    stmt = stmt.limit(limit).offset(offset)

    rows = (await db.execute(stmt)).all()
    items = []
    for asset, open_count in rows:
        item = AssetOut.model_validate(asset)
        item.open_port_count = int(open_count or 0)
        items.append(item)

    return AssetListOut(items=items, total=total, limit=limit, offset=offset)


@router.get("/{asset_id}", response_model=AssetDetailOut)
async def get_asset(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AssetDetailOut:
    result = await db.execute(
        select(Asset).options(selectinload(Asset.ports)).where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    detail = AssetDetailOut.model_validate(asset)
    detail.ports = [AssetPortOut.model_validate(p) for p in asset.ports]
    detail.open_port_count = sum(1 for p in asset.ports if p.state == PortState.OPEN)
    return detail


@router.patch("/{asset_id}", response_model=AssetDetailOut)
async def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> AssetDetailOut:
    result = await db.execute(
        select(Asset).options(selectinload(Asset.ports)).where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(asset, field, value)

    await audit.record(
        db,
        action="asset.update",
        user=actor,
        resource_type="asset",
        resource_id=str(asset.id),
        detail={"fields": sorted(changes)},
        request=request,
    )
    await db.commit()
    await db.refresh(asset)

    detail = AssetDetailOut.model_validate(asset)
    detail.ports = [AssetPortOut.model_validate(p) for p in asset.ports]
    detail.open_port_count = sum(1 for p in asset.ports if p.state == PortState.OPEN)
    return detail
