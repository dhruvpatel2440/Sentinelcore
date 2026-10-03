"""M9 — reporting: async generation, download, retention, schedules."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.config import settings
from app.core.redis import get_redis
from app.db.session import get_db
from app.models.report import Report, ReportFormat, ReportSchedule, ReportStatus, ReportType
from app.models.user import User
from app.schemas.report import (
    CSV_SUPPORTED_TYPES,
    ReportCreate,
    ReportOut,
    ReportScheduleIn,
    ReportScheduleOut,
    ReportScheduleUpdate,
    validate_report_params,
)
from app.services import audit

router = APIRouter(prefix="/reports", tags=["reports"])

_CONTENT_TYPES = {ReportFormat.PDF: "application/pdf", ReportFormat.CSV: "text/csv", ReportFormat.JSON: "application/json"}

_ACTIVE_REPORT_STATUSES = (ReportStatus.QUEUED, ReportStatus.RUNNING)


def _default_title(report_type: ReportType) -> str:
    return report_type.value.replace("_", " ").title()


@router.post("", response_model=ReportOut, status_code=status.HTTP_202_ACCEPTED)
async def create_report(
    payload: ReportCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
) -> ReportOut:
    try:
        params = validate_report_params(payload.report_type, payload.params)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    if "from" in params and "to" in params:
        window = datetime.fromisoformat(params["to"]) - datetime.fromisoformat(params["from"])
        if window.days > settings.max_report_window_days:
            raise HTTPException(
                status_code=422,
                detail=f"report window exceeds the {settings.max_report_window_days}-day maximum",
            )

    if payload.format == ReportFormat.CSV and payload.report_type not in CSV_SUPPORTED_TYPES:
        raise HTTPException(status_code=422, detail=f"CSV is not offered for {payload.report_type.value}")

    active_count = int(
        await db.scalar(
            select(func.count())
            .select_from(Report)
            .where(Report.requested_by == actor.id, Report.status.in_(_ACTIVE_REPORT_STATUSES))
        )
        or 0
    )
    if active_count >= settings.max_concurrent_reports_per_user:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"you already have {active_count} report(s) generating; wait for one to finish",
        )

    report = Report(
        report_type=payload.report_type,
        title=payload.title or _default_title(payload.report_type),
        params=params,
        format=payload.format,
        status=ReportStatus.QUEUED,
        requested_by=actor.id,
    )
    db.add(report)
    await db.flush()

    await audit.record(
        db, action="report.requested", user=actor, resource_type="report", resource_id=report.id,
        detail={"report_type": payload.report_type.value, "format": payload.format.value}, request=request,
    )
    await db.commit()
    await db.refresh(report)

    redis = get_redis()
    await redis.lpush(settings.report_queue_key, str(report.id))

    return ReportOut.model_validate(report, from_attributes=True)


@router.get("", response_model=list[ReportOut])
async def list_reports(
    report_type: ReportType | None = Query(default=None),
    status_filter: ReportStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
) -> list[ReportOut]:
    stmt = select(Report)
    if actor.role.value != "admin":
        stmt = stmt.where(Report.requested_by == actor.id)
    if report_type:
        stmt = stmt.where(Report.report_type == report_type)
    if status_filter:
        stmt = stmt.where(Report.status == status_filter)
    stmt = stmt.order_by(Report.requested_at.desc()).limit(limit).offset(offset)

    rows = (await db.execute(stmt)).scalars().all()
    return [ReportOut.model_validate(r, from_attributes=True) for r in rows]


# ---------------------------------------------------------------------------
# Schedules — admin only. Registered before /{report_id} so "schedules" is
# never parsed as a report id.
# ---------------------------------------------------------------------------


@router.get("/schedules", response_model=list[ReportScheduleOut])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> list[ReportScheduleOut]:
    rows = (await db.execute(select(ReportSchedule).order_by(ReportSchedule.created_at.desc()))).scalars().all()
    return [ReportScheduleOut.model_validate(r, from_attributes=True) for r in rows]


@router.post("/schedules", response_model=ReportScheduleOut, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ReportScheduleIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> ReportScheduleOut:
    if not croniter.is_valid(payload.cron):
        raise HTTPException(status_code=422, detail=f"not a valid cron expression: {payload.cron!r}")

    schedule = ReportSchedule(
        report_type=payload.report_type, format=payload.format, params=payload.params, cron=payload.cron,
        enabled=payload.enabled, recipients=payload.recipients, created_by=actor.id,
        next_run_at=croniter(payload.cron, datetime.now(timezone.utc)).get_next(datetime),
    )
    db.add(schedule)
    await audit.record(
        db, action="report.schedule_created", user=actor, resource_type="report_schedule", resource_id=schedule.id,
        detail={"report_type": payload.report_type.value, "cron": payload.cron}, request=request,
    )
    await db.commit()
    await db.refresh(schedule)
    return ReportScheduleOut.model_validate(schedule, from_attributes=True)


@router.patch("/schedules/{schedule_id}", response_model=ReportScheduleOut)
async def update_schedule(
    schedule_id: uuid.UUID,
    payload: ReportScheduleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> ReportScheduleOut:
    schedule = await db.get(ReportSchedule, schedule_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found")

    changes = payload.model_dump(exclude_unset=True)
    if "cron" in changes:
        if not croniter.is_valid(changes["cron"]):
            raise HTTPException(status_code=422, detail=f"not a valid cron expression: {changes['cron']!r}")
        schedule.next_run_at = croniter(changes["cron"], datetime.now(timezone.utc)).get_next(datetime)

    for field, value in changes.items():
        setattr(schedule, field, value)

    await audit.record(
        db, action="report.schedule_updated", user=actor, resource_type="report_schedule", resource_id=schedule.id,
        detail=changes, request=request,
    )
    await db.commit()
    await db.refresh(schedule)
    return ReportScheduleOut.model_validate(schedule, from_attributes=True)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_schedule(
    schedule_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> None:
    schedule = await db.get(ReportSchedule, schedule_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await audit.record(
        db, action="report.schedule_deleted", user=actor, resource_type="report_schedule", resource_id=schedule.id,
        detail={}, request=request,
    )
    await db.delete(schedule)
    await db.commit()


# ---------------------------------------------------------------------------
# Detail / download / delete
# ---------------------------------------------------------------------------


async def _get_owned_report(db: AsyncSession, report_id: uuid.UUID, actor: User) -> Report:
    report = await db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if actor.role.value != "admin" and report.requested_by != actor.id:
        raise HTTPException(status_code=403, detail="You can only access your own reports")
    return report


@router.get("/{report_id}", response_model=ReportOut)
async def get_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
) -> ReportOut:
    report = await _get_owned_report(db, report_id, actor)
    return ReportOut.model_validate(report, from_attributes=True)


@router.get("/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    report = await _get_owned_report(db, report_id, actor)
    if report.status != ReportStatus.COMPLETED or not report.file_path:
        raise HTTPException(status_code=409, detail=f"report is {report.status.value}, not ready for download")

    storage_root = Path(settings.report_storage_path).resolve()
    resolved = Path(report.file_path).resolve()
    if storage_root not in resolved.parents:
        # The path came from our own generator, never a client — this is a
        # defense-in-depth assertion, not a trust boundary being crossed here.
        raise HTTPException(status_code=500, detail="report file path is invalid")
    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="report file is missing from storage")

    await audit.record(
        db, action="report.downloaded", user=actor, resource_type="report", resource_id=report.id,
        detail={"report_type": report.report_type.value}, request=request,
    )
    await db.commit()

    ext = report.format.value
    filename = f"{report.report_type.value}-{report.id}.{ext}"
    return FileResponse(
        path=resolved, media_type=_CONTENT_TYPES[report.format], filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_report(
    report_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
) -> None:
    report = await _get_owned_report(db, report_id, actor)
    if report.file_path:
        Path(report.file_path).unlink(missing_ok=True)
    await audit.record(
        db, action="report.deleted", user=actor, resource_type="report", resource_id=report.id,
        detail={"report_type": report.report_type.value}, request=request,
    )
    await db.delete(report)
    await db.commit()
