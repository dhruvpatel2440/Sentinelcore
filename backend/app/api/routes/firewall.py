"""M10 — firewall containment. Every mutating route is admin-only; `GET
/actions` is viewer-readable so an analyst can see what is currently blocked
without being able to change it."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.redis import get_redis
from app.db.session import get_db
from app.models.firewall_action import FirewallAction, FirewallActionStatus
from app.models.user import User
from app.schemas.firewall import (
    FirewallActionCreate,
    FirewallActionExtend,
    FirewallActionOut,
    FirewallPrecheckRequest,
    FirewallPrecheckResult,
    FirewallStatus,
)
from app.services import firewall, helper_client
from app.services.firewall import LAST_RECONCILIATION_KEY, FirewallGuardRejected, MaxActiveBlocksReached, remaining_seconds

router = APIRouter(prefix="/firewall", tags=["firewall"])


def _out(action: FirewallAction) -> FirewallActionOut:
    # asyncpg/SQLAlchemy's CIDR column yields an ipaddress.IPv4Network, not a
    # str; build the dict explicitly rather than mutating the mapped object.
    out = FirewallActionOut(
        id=action.id, target=str(action.target), direction=action.direction, protocol=action.protocol,
        port=action.port, reason=action.reason, incident_id=action.incident_id, ttl_seconds=action.ttl_seconds,
        expires_at=action.expires_at, status=action.status, created_by=action.created_by,
        created_at=action.created_at, applied_at=action.applied_at, revoked_at=action.revoked_at,
        revoked_by=action.revoked_by, error=action.error, remaining_seconds=remaining_seconds(action),
    )
    return out


@router.get("/actions", response_model=list[FirewallActionOut])
async def list_actions(
    status_filter: FirewallActionStatus | None = Query(default=None, alias="status"),
    target: str | None = Query(default=None),
    incident_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[FirewallActionOut]:
    stmt = select(FirewallAction)
    if status_filter:
        stmt = stmt.where(FirewallAction.status == status_filter)
    if target:
        stmt = stmt.where(FirewallAction.target == target)
    if incident_id:
        stmt = stmt.where(FirewallAction.incident_id == incident_id)
    stmt = stmt.order_by(FirewallAction.created_at.desc()).limit(limit).offset(offset)

    rows = (await db.execute(stmt)).scalars().all()
    return [_out(r) for r in rows]


@router.post("/precheck", response_model=FirewallPrecheckResult)
async def precheck(
    payload: FirewallPrecheckRequest,
    _: User = Depends(require_role("admin")),
) -> FirewallPrecheckResult:
    return await firewall.precheck(payload.target)


@router.post("/actions", response_model=FirewallActionOut, status_code=status.HTTP_201_CREATED)
async def create_action(
    payload: FirewallActionCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> FirewallActionOut:
    try:
        action = await firewall.apply(db, payload=payload, user=actor, request=request)
    except FirewallGuardRejected as exc:
        raise HTTPException(status_code=422, detail=exc.reason) from exc
    except MaxActiveBlocksReached as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except helper_client.HelperError as exc:
        raise HTTPException(status_code=502, detail=f"Privileged helper error: {exc}") from exc
    return _out(action)


async def _get_action(db: AsyncSession, action_id: uuid.UUID) -> FirewallAction:
    action = await db.get(FirewallAction, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Firewall action not found")
    return action


@router.delete("/actions/{action_id}", response_model=FirewallActionOut)
async def revoke_action(
    action_id: uuid.UUID,
    request: Request,
    reason: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> FirewallActionOut:
    action = await _get_action(db, action_id)
    if action.status not in (FirewallActionStatus.PENDING, FirewallActionStatus.ACTIVE):
        raise HTTPException(status_code=409, detail=f"action is already {action.status.value}")
    try:
        action = await firewall.revoke(db, action, user=actor, reason=reason, request=request)
    except helper_client.HelperError as exc:
        raise HTTPException(status_code=502, detail=f"Privileged helper error: {exc}") from exc
    return _out(action)


@router.post("/actions/{action_id}/extend", response_model=FirewallActionOut)
async def extend_action(
    action_id: uuid.UUID,
    payload: FirewallActionExtend,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> FirewallActionOut:
    action = await _get_action(db, action_id)
    try:
        action = await firewall.extend(
            db, action, additional_seconds=payload.additional_seconds, user=actor, request=request
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _out(action)


@router.get("/status", response_model=FirewallStatus)
async def get_status(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> FirewallStatus:
    db_active_count = int(
        await db.scalar(
            select(func.count()).select_from(FirewallAction).where(FirewallAction.status == FirewallActionStatus.ACTIVE)
        )
        or 0
    )

    helper_reachable = await helper_client.ping()
    chain_present = False
    kernel_action_ids: set[str] = set()
    if helper_reachable:
        try:
            result = await helper_client.call("fw_list", {})
            chain_present = True
            kernel_action_ids = {r["action_id"] for r in result.get("rules", [])}
        except helper_client.HelperError:
            chain_present = False

    active_ids = {
        str(row[0])
        for row in (
            await db.execute(select(FirewallAction.id).where(FirewallAction.status == FirewallActionStatus.ACTIVE))
        ).all()
    }
    drift_count = len(kernel_action_ids.symmetric_difference(active_ids)) if helper_reachable else 0

    redis = get_redis()
    raw = await redis.get(LAST_RECONCILIATION_KEY)
    last_reconciliation_at = None
    if raw:
        raw_str = raw.decode() if isinstance(raw, bytes) else raw
        try:
            last_reconciliation_at = datetime.fromisoformat(raw_str)
        except ValueError:
            last_reconciliation_at = None

    return FirewallStatus(
        helper_reachable=helper_reachable,
        chain_present=chain_present,
        active_rule_count=len(kernel_action_ids),
        db_active_count=db_active_count,
        drift_count=drift_count,
        last_reconciliation_at=last_reconciliation_at,
    )


@router.post("/reconcile", response_model=dict)
async def force_reconcile(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> dict:
    redis = get_redis()
    return await firewall.reconcile(db, redis)
