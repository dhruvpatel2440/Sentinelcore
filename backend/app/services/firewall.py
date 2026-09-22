"""M10 firewall containment service.

Persist-before-apply, throughout: every state transition is written to
`firewall_actions` *before* the corresponding helper call, so a rule applied
to the kernel never lacks a database row, and a row is never left in a state
that does not match what was last confirmed with the helper.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis
from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.models.firewall_action import (
    ACTIVE_STATUSES,
    TTL_MAX_SECONDS,
    FirewallAction,
    FirewallActionStatus,
)
from app.models.user import User
from app.schemas.firewall import FirewallActionCreate, FirewallPrecheckResult
from app.services import audit, helper_client
from app.services.helper_client import HelperError, HelperRejected

logger = logging.getLogger("sentinelcore.services.firewall")

LAST_RECONCILIATION_KEY = "firewall:last_reconciliation_at"


class FirewallGuardRejected(Exception):
    """The helper refused the target. `reason` is shown to the caller
    verbatim — it names the exact protected resource, which is the point."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class MaxActiveBlocksReached(Exception):
    pass


def remaining_seconds(action: FirewallAction) -> int | None:
    if action.status not in (FirewallActionStatus.PENDING, FirewallActionStatus.ACTIVE):
        return None
    delta = (action.expires_at - datetime.now(timezone.utc)).total_seconds()
    return max(0, int(delta))


async def _active_count(db: AsyncSession) -> int:
    return int(
        await db.scalar(
            select(func.count()).select_from(FirewallAction).where(FirewallAction.status.in_(ACTIVE_STATUSES))
        )
        or 0
    )


async def precheck(target: str) -> FirewallPrecheckResult:
    try:
        result = await helper_client.call("fw_check_target", {"target": target})
    except HelperRejected as exc:
        return FirewallPrecheckResult(allowed=False, reason=exc.message)
    except HelperError as exc:
        return FirewallPrecheckResult(allowed=False, reason=f"helper unavailable: {exc}")
    return FirewallPrecheckResult(allowed=bool(result.get("allowed")), reason=result.get("reason"))


async def apply(
    db: AsyncSession, *, payload: FirewallActionCreate, user: User, request: Request | None = None
) -> FirewallAction:
    active = await _active_count(db)
    if active >= settings.max_active_blocks:
        raise MaxActiveBlocksReached(f"{active} active blocks already exist (limit {settings.max_active_blocks})")

    now = datetime.now(timezone.utc)
    action = FirewallAction(
        target=payload.target,
        direction=payload.direction,
        protocol=payload.protocol,
        port=payload.port,
        reason=payload.reason,
        incident_id=payload.incident_id,
        ttl_seconds=payload.ttl_seconds,
        expires_at=now + timedelta(seconds=payload.ttl_seconds),
        status=FirewallActionStatus.PENDING,
        created_by=user.id,
    )
    db.add(action)
    await db.flush()  # id assigned and durable before the helper is ever called

    try:
        await helper_client.call(
            "fw_apply",
            {
                "action_id": str(action.id),
                "target": payload.target,
                "direction": payload.direction.value,
                "protocol": payload.protocol,
                "port": payload.port,
            },
        )
    except HelperRejected as exc:
        action.status = FirewallActionStatus.FAILED
        action.error = exc.message
        await audit.record(
            db,
            action="firewall.blocked_attempt",
            user=user,
            resource_type="firewall_action",
            resource_id=action.id,
            outcome="refused",
            detail={"target": payload.target, "reason": exc.message},
            request=request,
        )
        await db.commit()
        raise FirewallGuardRejected(exc.message) from exc
    except HelperError as exc:
        action.status = FirewallActionStatus.FAILED
        action.error = str(exc)
        await audit.record(
            db,
            action="firewall.apply_failed",
            user=user,
            resource_type="firewall_action",
            resource_id=action.id,
            outcome="error",
            detail={"target": payload.target, "error": str(exc)},
            request=request,
        )
        await db.commit()
        raise

    action.status = FirewallActionStatus.ACTIVE
    action.applied_at = datetime.now(timezone.utc)
    await audit.record(
        db,
        action="firewall.applied",
        user=user,
        resource_type="firewall_action",
        resource_id=action.id,
        detail={"target": payload.target, "direction": payload.direction.value, "ttl_seconds": payload.ttl_seconds},
        request=request,
    )
    await db.commit()
    await db.refresh(action)
    return action


async def revoke(
    db: AsyncSession, action: FirewallAction, *, user: User, reason: str | None, request: Request | None = None
) -> FirewallAction:
    try:
        await helper_client.call("fw_revoke", {"action_id": str(action.id)})
    except HelperError as exc:
        logger.error("fw_revoke helper call failed for action_id=%s: %s", action.id, exc)
        await audit.record(
            db,
            action="firewall.revoke_failed",
            user=user,
            resource_type="firewall_action",
            resource_id=action.id,
            outcome="error",
            detail={"error": str(exc)},
            request=request,
        )
        await db.commit()
        raise

    action.status = FirewallActionStatus.REVOKED
    action.revoked_at = datetime.now(timezone.utc)
    action.revoked_by = user.id
    await audit.record(
        db,
        action="firewall.revoked",
        user=user,
        resource_type="firewall_action",
        resource_id=action.id,
        detail={"reason": reason},
        request=request,
    )
    await db.commit()
    await db.refresh(action)
    return action


async def extend(
    db: AsyncSession, action: FirewallAction, *, additional_seconds: int, user: User, request: Request | None = None
) -> FirewallAction:
    if action.status != FirewallActionStatus.ACTIVE:
        raise ValueError(f"cannot extend a {action.status.value} action")

    new_ttl = min(action.ttl_seconds + additional_seconds, TTL_MAX_SECONDS)
    action.ttl_seconds = new_ttl
    action.expires_at = action.created_at + timedelta(seconds=new_ttl)

    await audit.record(
        db,
        action="firewall.extended",
        user=user,
        resource_type="firewall_action",
        resource_id=action.id,
        detail={"additional_seconds": additional_seconds, "new_ttl_seconds": new_ttl},
        request=request,
    )
    await db.commit()
    await db.refresh(action)
    return action


# ---------------------------------------------------------------------------
# Worker-side: expiry and reconciliation. Both are also reachable from the
# API for the forced GET /status and POST /reconcile endpoints.
# ---------------------------------------------------------------------------

_expiry_attempts: dict[uuid.UUID, int] = {}


async def run_expiry_pass(db: AsyncSession) -> int:
    now = datetime.now(timezone.utc)
    due = (
        await db.execute(
            select(FirewallAction).where(FirewallAction.status == FirewallActionStatus.ACTIVE, FirewallAction.expires_at <= now)
        )
    ).scalars().all()

    expired = 0
    for action in due:
        try:
            await helper_client.call("fw_revoke", {"action_id": str(action.id)})
        except HelperError as exc:
            attempts = _expiry_attempts.get(action.id, 0) + 1
            _expiry_attempts[action.id] = attempts
            logger.error("expiry revoke failed action_id=%s attempt=%d: %s", action.id, attempts, exc)
            if attempts >= settings.firewall_expiry_alert_after_attempts:
                await audit.record(
                    db, action="firewall.expiry_stuck", username="system", resource_type="firewall_action",
                    resource_id=action.id, outcome="error", detail={"attempts": attempts, "error": str(exc)},
                )
            continue

        action.status = FirewallActionStatus.EXPIRED
        _expiry_attempts.pop(action.id, None)
        await audit.record(
            db, action="firewall.expired", username="system", resource_type="firewall_action",
            resource_id=action.id, detail={"target": str(action.target)},
        )
        logger.info("expired firewall action_id=%s target=%s", action.id, action.target)
        expired += 1

    if due:
        await db.commit()
    return expired


async def run_expiry_loop(sessionmaker: async_sessionmaker[AsyncSession], stop: asyncio.Event) -> None:
    logger.info("firewall expiry loop starting, interval=%ss", settings.firewall_expiry_interval_seconds)
    while not stop.is_set():
        try:
            async with sessionmaker() as db:
                await run_expiry_pass(db)
        except Exception:  # noqa: BLE001
            logger.exception("firewall expiry pass failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.firewall_expiry_interval_seconds)
        except asyncio.TimeoutError:
            continue


async def reconcile(db: AsyncSession, redis: aioredis.Redis | None = None) -> dict:
    """Compare kernel state to the `active` DB rows in both directions.

    A kernel rule with no expected DB row is an orphan and is removed by the
    helper itself. A DB row that says `active` but has no kernel rule is
    re-applied if unexpired, else marked `expired` — silent drift between
    intent and enforcement is how a SOC ends up trusting a block that does
    not exist.
    """
    active = (
        await db.execute(select(FirewallAction).where(FirewallAction.status == FirewallActionStatus.ACTIVE))
    ).scalars().all()
    active_by_id = {str(a.id): a for a in active}

    try:
        result = await helper_client.call("fw_reconcile", {"expected": list(active_by_id.keys())})
    except HelperError as exc:
        logger.error("reconciliation could not reach the helper: %s", exc)
        return {"error": str(exc)}

    missing = result.get("missing", [])
    orphans = result.get("orphans_removed", [])
    now = datetime.now(timezone.utc)

    reapplied: list[str] = []
    for action_id in missing:
        action = active_by_id.get(action_id)
        if action is None:
            continue
        if action.expires_at <= now:
            action.status = FirewallActionStatus.EXPIRED
            continue
        try:
            await helper_client.call(
                "fw_apply",
                {
                    "action_id": action_id, "target": str(action.target), "direction": action.direction.value,
                    "protocol": action.protocol, "port": action.port,
                },
            )
            action.applied_at = now
            reapplied.append(action_id)
        except HelperError as exc:
            logger.error("reconcile re-apply failed for action_id=%s: %s", action_id, exc)

    if missing or orphans:
        await audit.record(
            db, action="firewall.reconciled", username="system", resource_type="firewall_action",
            detail={"missing": missing, "reapplied": reapplied, "orphans_removed": orphans},
        )

    await db.commit()

    if redis is not None:
        await redis.set(LAST_RECONCILIATION_KEY, now.isoformat())

    return {"missing": missing, "reapplied": reapplied, "orphans_removed": orphans, "reconciled_at": now.isoformat()}


async def run_reconcile_loop(
    sessionmaker: async_sessionmaker[AsyncSession], redis: aioredis.Redis, stop: asyncio.Event
) -> None:
    logger.info("firewall reconciliation loop starting, interval=%ss", settings.firewall_reconcile_interval_seconds)
    # Run once immediately on startup, then on the interval.
    while not stop.is_set():
        try:
            async with sessionmaker() as db:
                await reconcile(db, redis)
        except Exception:  # noqa: BLE001
            logger.exception("firewall reconciliation pass failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.firewall_reconcile_interval_seconds)
        except asyncio.TimeoutError:
            continue
