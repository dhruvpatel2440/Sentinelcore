"""M9 report generation — runs in the worker container, never inline on an
API request. Failures always land in `failed` with the error recorded; a row
is never left stuck in `running`, even across a worker restart (see
`reconcile_stuck_reports`).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.email.render import app_link
from app.email.service import Recipient, enqueue, resolve_recipients_from_users
from app.email.types import EmailType
from app.models.report import Report, ReportFormat, ReportSchedule, ReportStatus
from app.models.user import User
from app.reports import render
from app.reports.types import REGISTRY

logger = logging.getLogger("sentinelcore.reports.generator")

_EXT = {ReportFormat.PDF: "pdf", ReportFormat.CSV: "csv", ReportFormat.JSON: "json"}


def _storage_root() -> Path:
    root = Path(settings.report_storage_path)
    root.mkdir(parents=True, exist_ok=True)
    return root


def resolve_report_path(report_id: uuid.UUID, fmt: ReportFormat) -> Path:
    """The only place a report's on-disk path is constructed — a UUID
    filename under a fixed root, never a user-supplied value."""
    return _storage_root() / f"{report_id}.{_EXT[fmt]}"


async def generate_report(report_id: uuid.UUID, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
    async with sessionmaker() as db:
        report = await db.get(Report, report_id)
        if report is None or report.status != ReportStatus.QUEUED:
            return
        report.status = ReportStatus.RUNNING
        report.started_at = datetime.now(timezone.utc)
        await db.commit()

    try:
        async with sessionmaker() as db:
            report = await db.get(Report, report_id)
            builder = REGISTRY[report.report_type]
            data = await asyncio.wait_for(
                builder.build(report.params, db), timeout=settings.report_generation_timeout_seconds
            )

            requester = await db.get(User, report.requested_by) if report.requested_by else None
            requested_by_display = requester.username if requester else "system"

            if report.format == ReportFormat.PDF:
                content = render.render_pdf(
                    report_type=report.report_type.value, title=report.title, params=data.get("params", report.params),
                    requested_by=requested_by_display, data=data,
                )
            elif report.format == ReportFormat.CSV:
                content = render.render_csv(report.report_type.value, data)
            else:
                content = render.render_json(data)

            path = resolve_report_path(report.id, report.format)
            # Assert containment: resolve() collapses any traversal, and the
            # result must still live under the storage root.
            resolved = path.resolve()
            if _storage_root().resolve() not in resolved.parents and resolved != _storage_root().resolve():
                raise RuntimeError("resolved report path escaped the storage root")
            path.write_bytes(content)

            report.file_path = str(path)
            report.file_size = len(content)
            report.checksum = hashlib.sha256(content).hexdigest()
            report.status = ReportStatus.COMPLETED
            report.completed_at = datetime.now(timezone.utc)
            report.expires_at = report.completed_at + timedelta(days=settings.report_retention_days)
            await db.commit()
            logger.info("report %s (%s) completed: %s", report.id, report.report_type.value, path)
            await _notify_report_completed(db, report)

    except Exception as exc:  # noqa: BLE001 — must always resolve the row, never leave it running
        logger.error("report %s failed: %s", report_id, exc)
        async with sessionmaker() as db:
            report = await db.get(Report, report_id)
            if report is not None:
                report.status = ReportStatus.FAILED
                report.error = str(exc)[:4000]
                report.completed_at = datetime.now(timezone.utc)
                await db.commit()
                await _notify_report_failed(db, report, exc)


async def _notify_report_completed(db: AsyncSession, report: Report) -> None:
    """E11 (scheduled, to the schedule's recipient list) or E12 (on-demand,
    only if the requester ticked "email me") — never both for one report."""
    if report.schedule_id is not None:
        schedule = await db.get(ReportSchedule, report.schedule_id)
        if schedule is None or not schedule.recipients:
            return
        recips = [Recipient(email=e) for e in schedule.recipients]
        within_cap = (report.file_size or 0) <= settings.email_max_attachment_mb * 1024 * 1024
        await enqueue(
            db,
            email_type=EmailType.E11_REPORT_DELIVERED,
            recipients=recips,
            heading=f"Scheduled report ready: {report.title}",
            render_context={
                "report_type": report.report_type.value,
                "window": report.params.get("window", "n/a"),
                "format": report.format.value,
                "generated_at": report.completed_at.isoformat() if report.completed_at else "",
                "attached": within_cap,
            },
            dedupe_key=lambda r, rep=report: f"E11:{rep.id}:{r.email}",
            related_type="report", related_id=str(report.id),
            button_label="Download report", button_url=app_link(f"/reports/{report.id}"),
            why_you_got_this="you are listed as a recipient on this scheduled report.",
        )
        await db.commit()
        return

    if report.notify_requester and report.requested_by is not None:
        requester = await db.get(User, report.requested_by)
        recips = await resolve_recipients_from_users(db, [requester] if requester else [])
        if not recips:
            return
        await enqueue(
            db,
            email_type=EmailType.E12_REPORT_READY,
            recipients=recips,
            heading=f"Your report is ready: {report.title}",
            render_context={},
            dedupe_key=lambda r, rep=report: f"E12:{rep.id}",
            related_type="report", related_id=str(report.id),
            button_label="Open report", button_url=app_link(f"/reports/{report.id}"),
            why_you_got_this="you asked to be emailed when this report finished.",
        )
        await db.commit()


async def _notify_report_failed(db: AsyncSession, report: Report, exc: Exception) -> None:
    from app.email import recipients as email_recipients

    targets: list[User] = list(await email_recipients.admins(db))
    if report.requested_by is not None:
        requester = await db.get(User, report.requested_by)
        if requester is not None:
            targets.append(requester)
    recips = await resolve_recipients_from_users(db, targets)
    if not recips:
        return
    await enqueue(
        db,
        email_type=EmailType.E13_REPORT_FAILED,
        recipients=recips,
        heading=f"Report failed to generate: {report.title}",
        render_context={
            "report_type": report.report_type.value,
            "window": report.params.get("window", "n/a"),
            "error_class": type(exc).__name__,
        },
        dedupe_key=lambda r, rep=report: f"E13:{rep.id}:{r.email}",
        related_type="report", related_id=str(report.id),
        button_label="Retry", button_url=app_link("/reports"),
        why_you_got_this="you requested this report, or you are an administrator.",
    )
    await db.commit()


async def reconcile_stuck_reports(sessionmaker: async_sessionmaker[AsyncSession]) -> int:
    """Startup safety net: a worker crash mid-generation leaves a row in
    `running` forever unless something fails it."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.report_generation_timeout_seconds)
    async with sessionmaker() as db:
        stuck = (
            await db.execute(
                select(Report).where(Report.status == ReportStatus.RUNNING, Report.started_at < cutoff)
            )
        ).scalars().all()
        for report in stuck:
            report.status = ReportStatus.FAILED
            report.error = "worker restarted mid-generation"
            report.completed_at = datetime.now(timezone.utc)
        if stuck:
            await db.commit()
        return len(stuck)


async def enforce_report_retention(sessionmaker: async_sessionmaker[AsyncSession]) -> int:
    now = datetime.now(timezone.utc)
    async with sessionmaker() as db:
        expired = (
            await db.execute(select(Report).where(Report.expires_at.is_not(None), Report.expires_at <= now))
        ).scalars().all()
        for report in expired:
            if report.file_path:
                try:
                    Path(report.file_path).unlink(missing_ok=True)
                except OSError as exc:
                    logger.warning("could not remove expired report file %s: %s", report.file_path, exc)
            logger.info("retention: removing report %s (%s, expired %s)", report.id, report.report_type.value, report.expires_at)
            await db.delete(report)
        if expired:
            await db.commit()
        return len(expired)


async def run_forever(
    sessionmaker: async_sessionmaker[AsyncSession], redis: aioredis.Redis, stop: asyncio.Event
) -> None:
    logger.info("report generator starting, queue=%s", settings.report_queue_key)
    reconciled = await reconcile_stuck_reports(sessionmaker)
    if reconciled:
        logger.info("reconciled %d stuck report(s) on startup", reconciled)

    while not stop.is_set():
        try:
            item = await redis.brpop(settings.report_queue_key, timeout=5)
        except Exception as exc:  # noqa: BLE001
            logger.error("report queue read failed: %s", exc)
            await asyncio.sleep(1)
            continue

        if item is None:
            continue
        _, raw_id = item
        try:
            report_id = uuid.UUID(raw_id.decode() if isinstance(raw_id, bytes) else raw_id)
            await generate_report(report_id, sessionmaker)
        except Exception as exc:  # noqa: BLE001 — one bad queue item must not kill the loop
            logger.error("failed to process report queue item %r: %s", raw_id, exc)
