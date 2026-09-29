"""Suricata sensor control, ruleset management and health.

Every mutating route is admin-only and lands in both `audit_log` and
`sensor_events`. Stopping the sensor blinds the platform, so it is audited like
any other containment action.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.db.session import SessionLocal, get_db
from app.models.sensor import OverrideAction, RuleOverride, RuleSource, SensorAction, SensorEvent
from app.models.user import User
from app.schemas.sensor import (
    ConfigTestOut,
    RuleOverrideCreate,
    RuleOverrideOut,
    RuleSourceCreate,
    RuleSourceOut,
    RuleSourceUpdate,
    SensorEventOut,
    SensorStatsOut,
    SensorStatusOut,
)
from app.services import audit, helper_client, ruleset, sensor_stats
from app.services.helper_client import HelperError, HelperRejected, HelperUnavailable
from app.services.ruleset import OverrideSpec, RulesetError

logger = logging.getLogger("sentinelcore.sensor")

router = APIRouter(prefix="/sensor", tags=["sensor"])

# If eve.json has not been touched in this long, the sensor is up but blind.
# Suricata's stats interval is 30s, so 3 missed intervals is a real signal.
EVE_STALE_SECONDS = 120


def _helper_http_error(exc: HelperError) -> HTTPException:
    """Map helper failures onto clean statuses — never a raw traceback."""
    if isinstance(exc, HelperUnavailable):
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The privileged helper is unavailable. Sensor control is offline.",
        )
    if isinstance(exc, HelperRejected):
        code = getattr(exc, "code", "")
        if code == "not_running":
            return HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Suricata is not running"
            )
        if code == "binary_missing":
            return HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Suricata is not installed in the helper image",
            )
        return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY, detail="The privileged helper failed"
    )


async def _record_sensor_event(
    db: AsyncSession,
    *,
    action: SensorAction,
    status_text: str,
    user: User | None,
    detail: dict | None = None,
    request: Request | None = None,
) -> None:
    db.add(
        SensorEvent(
            action=action,
            status=status_text,
            detail=detail,
            user_id=user.id if user else None,
        )
    )
    await audit.record(
        db,
        action=f"sensor.{action.value}",
        user=user,
        resource_type="sensor",
        outcome="success" if status_text in {"ok", "started", "stopped"} else "failure",
        detail=detail,
        request=request,
    )


async def _last_reload_at(db: AsyncSession):
    return await db.scalar(
        select(SensorEvent.created_at)
        .where(SensorEvent.action.in_([SensorAction.RELOAD, SensorAction.RULES_UPDATE]))
        .where(SensorEvent.status == "ok")
        .order_by(SensorEvent.created_at.desc())
        .limit(1)
    )


async def _build_status(db: AsyncSession) -> SensorStatusOut:
    """Shared by GET /status and by every control route's return value, so the
    UI always sees the state that actually resulted from the action."""
    try:
        data = await helper_client.call("suricata_status", timeout=30.0)
    except HelperError as exc:
        logger.warning("sensor status unavailable: %s", exc)
        return SensorStatusOut(running=False, helper_available=False)

    age = data.get("eve_log_age_seconds")
    return SensorStatusOut(
        running=bool(data.get("running")),
        pid=data.get("pid"),
        uptime_seconds=data.get("uptime_seconds"),
        version=data.get("version"),
        rule_count=int(data.get("rule_count") or 0),
        ruleset_sha256=data.get("ruleset_sha256"),
        last_reload_at=await _last_reload_at(db),
        eve_log_age_seconds=age,
        eve_log_stale=bool(data.get("running")) and (age is None or age > EVE_STALE_SECONDS),
        helper_available=True,
        binary_available=bool(data.get("binary_available", True)),
    )


@router.get("/status", response_model=SensorStatusOut)
async def get_status(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> SensorStatusOut:
    """Viewer-readable. Degrades gracefully when the helper is down."""
    return await _build_status(db)


@router.get("/stats", response_model=SensorStatsOut)
async def get_stats(_: User = Depends(get_current_user)) -> SensorStatsOut:
    return SensorStatsOut(**sensor_stats.read_stats())


@router.get("/events", response_model=list[SensorEventOut])
async def list_sensor_events(
    limit: int = Query(30, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[SensorEventOut]:
    result = await db.execute(
        select(SensorEvent).order_by(SensorEvent.created_at.desc()).limit(limit)
    )
    return [SensorEventOut.model_validate(e) for e in result.scalars().all()]


@router.post("/start", response_model=SensorStatusOut)
async def start_sensor(
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> SensorStatusOut:
    try:
        data = await helper_client.call("suricata_start", timeout=120.0)
    except HelperError as exc:
        await _record_sensor_event(
            db, action=SensorAction.START, status_text="failed",
            user=actor, detail={"error": str(exc)[:500]}, request=request,
        )
        await db.commit()
        raise _helper_http_error(exc) from exc

    await _record_sensor_event(
        db, action=SensorAction.START, status_text="started", user=actor,
        detail={"pid": data.get("pid")}, request=request,
    )
    await db.commit()
    return await _build_status(db)


@router.post("/stop", response_model=SensorStatusOut)
async def stop_sensor(
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> SensorStatusOut:
    try:
        data = await helper_client.call("suricata_stop", timeout=120.0)
    except HelperError as exc:
        await _record_sensor_event(
            db, action=SensorAction.STOP, status_text="failed",
            user=actor, detail={"error": str(exc)[:500]}, request=request,
        )
        await db.commit()
        raise _helper_http_error(exc) from exc

    await _record_sensor_event(
        db, action=SensorAction.STOP, status_text="stopped", user=actor,
        detail={"escalated": data.get("escalated")}, request=request,
    )
    await db.commit()
    return await _build_status(db)


@router.post("/reload", response_model=SensorStatusOut)
async def reload_rules(
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> SensorStatusOut:
    try:
        data = await helper_client.call("suricata_reload_rules", timeout=180.0)
    except HelperError as exc:
        await _record_sensor_event(
            db, action=SensorAction.RELOAD, status_text="failed",
            user=actor, detail={"error": str(exc)[:500]}, request=request,
        )
        await db.commit()
        raise _helper_http_error(exc) from exc

    await _record_sensor_event(
        db, action=SensorAction.RELOAD, status_text="ok", user=actor,
        detail={"method": data.get("method"), "rule_count": data.get("rule_count")},
        request=request,
    )
    await db.commit()
    return await _build_status(db)


@router.post("/config/test", response_model=ConfigTestOut)
async def test_config(
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> ConfigTestOut:
    try:
        data = await helper_client.call("suricata_test_config", timeout=1200.0)
    except HelperError as exc:
        raise _helper_http_error(exc) from exc

    await _record_sensor_event(
        db, action=SensorAction.CONFIG_TEST,
        status_text="ok" if data.get("valid") else "failed",
        user=actor, detail={"valid": data.get("valid")}, request=request,
    )
    await db.commit()
    return ConfigTestOut(**data)


# --------------------------------------------------------------------------
# Rule sources
# --------------------------------------------------------------------------


@router.get("/rules/sources", response_model=list[RuleSourceOut])
async def list_sources(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[RuleSourceOut]:
    result = await db.execute(select(RuleSource).order_by(RuleSource.name))
    return [RuleSourceOut.model_validate(s) for s in result.scalars().all()]


@router.post("/rules/sources", response_model=RuleSourceOut, status_code=status.HTTP_201_CREATED)
async def create_source(
    payload: RuleSourceCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> RuleSourceOut:
    source = RuleSource(**payload.model_dump())
    db.add(source)
    await audit.record(
        db, action="sensor.rule_source_create", user=actor, resource_type="rule_source",
        resource_id=payload.name, detail={"url": payload.url}, request=request,
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A rule source with that name exists"
        ) from exc
    await db.refresh(source)
    return RuleSourceOut.model_validate(source)


@router.patch("/rules/sources/{source_id}", response_model=RuleSourceOut)
async def update_source(
    source_id: uuid.UUID,
    payload: RuleSourceUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> RuleSourceOut:
    source = await db.get(RuleSource, source_id)
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule source not found")

    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(source, field, value)

    await audit.record(
        db, action="sensor.rule_source_update", user=actor, resource_type="rule_source",
        resource_id=str(source.id), detail=changes, request=request,
    )
    await db.commit()
    await db.refresh(source)
    return RuleSourceOut.model_validate(source)


@router.delete("/rules/sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_source(
    source_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> None:
    source = await db.get(RuleSource, source_id)
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule source not found")
    name = source.name
    await db.delete(source)
    await audit.record(
        db, action="sensor.rule_source_delete", user=actor, resource_type="rule_source",
        resource_id=str(source_id), detail={"name": name}, request=request,
    )
    await db.commit()


# --------------------------------------------------------------------------
# Rule overrides
# --------------------------------------------------------------------------


@router.get("/rules/overrides", response_model=list[RuleOverrideOut])
async def list_overrides(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[RuleOverrideOut]:
    result = await db.execute(select(RuleOverride).order_by(RuleOverride.created_at.desc()))
    return [RuleOverrideOut.model_validate(o) for o in result.scalars().all()]


@router.post("/rules/overrides", response_model=RuleOverrideOut, status_code=status.HTTP_201_CREATED)
async def create_override(
    payload: RuleOverrideCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> RuleOverrideOut:
    override = RuleOverride(
        sid=payload.sid,
        action=payload.action,
        params=payload.params,
        reason=payload.reason,
        created_by=actor.id,
    )
    db.add(override)
    await audit.record(
        db, action="sensor.rule_override_create", user=actor, resource_type="rule_override",
        resource_id=str(payload.sid),
        detail={"action": payload.action.value, "reason": payload.reason},
        request=request,
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An override for SID {payload.sid} already exists",
        ) from exc
    await db.refresh(override)
    return RuleOverrideOut.model_validate(override)


@router.delete("/rules/overrides/{sid}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_override(
    sid: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> None:
    override = await db.scalar(select(RuleOverride).where(RuleOverride.sid == sid))
    if override is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Override not found")
    await db.delete(override)
    await audit.record(
        db, action="sensor.rule_override_delete", user=actor, resource_type="rule_override",
        resource_id=str(sid), request=request,
    )
    await db.commit()


# --------------------------------------------------------------------------
# Rule update pipeline
# --------------------------------------------------------------------------


@router.post("/rules/update", status_code=status.HTTP_202_ACCEPTED)
async def update_rules(
    request: Request,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> dict:
    enabled = (
        await db.execute(select(RuleSource).where(RuleSource.enabled.is_(True)))
    ).scalars().all()
    if not enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No rule sources are enabled"
        )

    await audit.record(
        db, action="sensor.rules_update_started", user=actor, resource_type="sensor",
        detail={"sources": [s.name for s in enabled]}, request=request,
    )
    await db.commit()

    background.add_task(run_rules_update, actor.id)
    return {"status": "accepted", "sources": [s.name for s in enabled]}


async def run_rules_update(user_id: uuid.UUID | None) -> None:
    """Background pipeline. Owns its own session; never raises to the caller."""
    async with SessionLocal() as db:
        sources = (
            await db.execute(select(RuleSource).where(RuleSource.enabled.is_(True)))
        ).scalars().all()

        override_rows = (await db.execute(select(RuleOverride))).scalars().all()
        overrides = [
            OverrideSpec(sid=o.sid, action=o.action.value, params=o.params) for o in override_rows
        ]

        combined = ruleset.ExtractedRules()
        errors: list[str] = []

        for source in sources:
            try:
                archive = await ruleset.fetch_feed(source.url)
                extracted = ruleset.extract_rules(archive)
                combined.files.update(extracted.files)
                combined.skipped.extend(extracted.skipped)

                source.last_status = "ok"
                source.last_error = None
                source.rule_count = sum(
                    1
                    for content in extracted.files.values()
                    for line in content.splitlines()
                    if line.strip() and not line.strip().startswith(b"#")
                )
            except Exception as exc:  # noqa: BLE001
                message = f"{type(exc).__name__}: {exc}"[:500]
                logger.error("rule source %s failed: %s", source.name, message)
                source.last_status = "failed"
                source.last_error = message
                errors.append(f"{source.name}: {message}")

            source.last_updated_at = datetime.now(timezone.utc)

        if not combined.files:
            detail = {"error": "No rules could be fetched", "sources": errors}
            db.add(
                SensorEvent(
                    action=SensorAction.RULES_UPDATE, status="failed",
                    detail=detail, user_id=user_id,
                )
            )
            await audit.record(
                db, action="sensor.rules_update", resource_type="sensor",
                outcome="failure", error="; ".join(errors)[:500] or "no rules fetched",
            )
            await db.commit()
            return

        try:
            composed, stats = ruleset.compose(combined, overrides)
            result = await ruleset.deploy(composed)

            db.add(
                SensorEvent(
                    action=SensorAction.RULES_UPDATE,
                    status="ok",
                    detail={
                        "rule_count": result.get("rule_count"),
                        "sha256": result.get("sha256"),
                        "overrides_applied": stats,
                        "skipped_members": len(combined.skipped),
                        "source_errors": errors,
                    },
                    user_id=user_id,
                )
            )
            await audit.record(
                db, action="sensor.rules_update", resource_type="sensor",
                detail={"rule_count": result.get("rule_count")},
            )
            logger.info("rule update deployed: %s rules", result.get("rule_count"))

        except Exception as exc:  # noqa: BLE001
            # The helper restores the previous ruleset on failure, so the
            # sensor keeps running whatever it had before this attempt.
            message = f"{type(exc).__name__}: {exc}"[:500]
            logger.error("rule deployment failed, previous ruleset retained: %s", message)
            db.add(
                SensorEvent(
                    action=SensorAction.RULES_UPDATE, status="failed",
                    detail={"error": message, "rolled_back": True}, user_id=user_id,
                )
            )
            await audit.record(
                db, action="sensor.rules_update", resource_type="sensor",
                outcome="failure", error=message,
            )

        await db.commit()
