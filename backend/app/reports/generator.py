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
from app.models.report import Report, ReportFormat, ReportStatus
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

    except Exception as exc:  # noqa: BLE001 — must always resolve the row, never leave it running
        logger.error("report %s failed: %s", report_id, exc)
        async with sessionmaker() as db:
            report = await db.get(Report, report_id)
            if report is not None:
                report.status = ReportStatus.FAILED
                report.error = str(exc)[:4000]
                report.completed_at = datetime.now(timezone.utc)
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
