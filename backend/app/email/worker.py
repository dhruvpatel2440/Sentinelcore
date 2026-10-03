"""Worker-side email machinery (U10 Part 5): outbox drain, stuck-row reaper,
SLA/backlog/sensor-health scanners, the digest builder, and outbox
retention. Wired into `app.pipeline.worker.main()` as additional tasks —
there is no separate email worker container.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import redis.asyncio as aioredis
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.email import recipients, render
from app.email.client import BrevoClient, BrevoFatalError, BrevoRetryableError, MAX_ATTEMPTS, RETRY_DELAYS_SECONDS, circuit_breaker
from app.email.service import Recipient, enqueue
from app.email.types import EmailType
from app.models.email import EmailOutbox, EmailOutboxStatus, EmailPreferences
from app.models.event import Severity
from app.models.incident import Incident, IncidentStatus
from app.models.user import User
from app.pipeline.tailer import STREAM_KEY
from app.services import sensor_stats

logger = logging.getLogger("sentinelcore.email.worker")

DRAIN_BATCH_SIZE = 20

_SLA_MINUTES_BY_SEVERITY = {
    Severity.CRITICAL: settings.incident_sla_minutes_critical,
    Severity.HIGH: settings.incident_sla_minutes_high,
    Severity.MEDIUM: settings.incident_sla_minutes_medium,
}

# In-process state for scanners that need to detect an edge (down->recovered,
# backlog sustained for N scans). A worker restart resets this — acceptable,
# it only delays the next alert by at most one scan interval.
_sensor_down_since: datetime | None = None
_sensor_last_alert_at: datetime | None = None
_backlog_breach_streak = 0
_backlog_last_alert_at: datetime | None = None


# ---------------------------------------------------------------------------
# Outbox drain
# ---------------------------------------------------------------------------


async def _build_attachment(db: AsyncSession, row: EmailOutbox) -> list[dict[str, str]] | None:
    """E11 only: attach the report file inline if it fits under the size
    cap. Otherwise the email just carries the in-app download link that is
    already in its body — no attachment is not a failure here."""
    if row.email_type != EmailType.E11_REPORT_DELIVERED or row.related_id is None:
        return None
    import base64

    from app.models.report import Report

    try:
        report = await db.get(Report, uuid.UUID(row.related_id))
    except ValueError:
        return
    if report is None or not report.file_path:
        return None
    cap_bytes = settings.email_max_attachment_mb * 1024 * 1024
    if not report.file_size or report.file_size > cap_bytes:
        return None
    try:
        content = Path(report.file_path).read_bytes()
    except OSError:
        return None
    ext = report.format.value
    return [{"name": f"{report.title}.{ext}", "content": base64.b64encode(content).decode("ascii")}]


async def _send_one(db: AsyncSession, row: EmailOutbox, client: BrevoClient) -> None:
    attachments = await _build_attachment(db, row)
    try:
        result = await client.send(
            outbox_id=row.id,
            email_type=row.email_type.value,
            recipient_email=row.recipient_email,
            subject=row.subject,
            html_body=row.html_body,
            text_body=row.text_body,
            reply_to=settings.email_reply_to or None,
            attachments=attachments,
        )
    except BrevoFatalError as exc:
        row.status = EmailOutboxStatus.FAILED
        row.last_error = str(exc)[:500]
        row.attempts += 1
        logger.error("outbox %s failed permanently: %s", row.id, exc)
        if circuit_breaker.should_alert():
            await _send_circuit_breaker_alert(db, str(exc))
        return
    except BrevoRetryableError as exc:
        row.attempts += 1
        row.last_error = str(exc)[:500]
        if row.attempts >= MAX_ATTEMPTS:
            row.status = EmailOutboxStatus.FAILED
            logger.error("outbox %s exhausted retries: %s", row.id, exc)
            return
        delay = exc.retry_after_seconds
        if delay is None:
            idx = min(row.attempts - 1, len(RETRY_DELAYS_SECONDS) - 1)
            delay = RETRY_DELAYS_SECONDS[idx]
        row.status = EmailOutboxStatus.QUEUED
        row.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
        logger.warning("outbox %s retry %d in %.0fs: %s", row.id, row.attempts, delay, exc)
        return

    row.status = EmailOutboxStatus.SENT
    row.provider_message_id = result.provider_message_id
    row.sent_at = datetime.now(timezone.utc)
    row.attempts += 1


async def _send_circuit_breaker_alert(db: AsyncSession, reason: str) -> None:
    admins = await recipients.admins(db)
    recips = [Recipient(email=u.email, user_id=u.id) for u in admins if u.email]
    if not recips:
        return
    await enqueue(
        db,
        email_type=EmailType.E15_SENSOR_HEALTH,
        recipients=recips,
        heading="Brevo authentication is failing — email sending paused",
        render_context={"reason": "Brevo rejected the API key (401/403)."},
        severity=Severity.HIGH,
        dedupe_key=lambda r: f"E15:brevo_auth:{datetime.now(timezone.utc).date()}",
        related_type="email_system",
        related_id="brevo_auth",
        why_you_got_this="you are an administrator and SentinelCore's outbound email is misconfigured.",
    )


async def drain_once(sessionmaker: async_sessionmaker[AsyncSession], client: BrevoClient) -> int:
    if circuit_breaker.is_open():
        return 0

    sent = 0
    async with sessionmaker() as db:
        async with db.begin():
            now = datetime.now(timezone.utc)
            rows = (
                await db.execute(
                    select(EmailOutbox)
                    .where(EmailOutbox.status == EmailOutboxStatus.QUEUED, EmailOutbox.next_attempt_at <= now, EmailOutbox.digest.is_(False))
                    .order_by(EmailOutbox.created_at)
                    .limit(DRAIN_BATCH_SIZE)
                    .with_for_update(skip_locked=True)
                )
            ).scalars().all()
            for row in rows:
                row.status = EmailOutboxStatus.SENDING

        for row in rows:
            async with sessionmaker() as send_db:
                fresh = await send_db.get(EmailOutbox, row.id)
                if fresh is None or fresh.status != EmailOutboxStatus.SENDING:
                    continue
                await _send_one(send_db, fresh, client)
                await send_db.commit()
                if fresh.status == EmailOutboxStatus.SENT:
                    sent += 1
                if circuit_breaker.is_open():
                    break
    return sent


async def reap_stuck(sessionmaker: async_sessionmaker[AsyncSession]) -> int:
    """A crash mid-send leaves rows in `sending`. The idempotency key on the
    Brevo request means resetting them to `queued` cannot double-send —
    worst case Brevo dedupes a retried identical request."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.email_outbox_reaper_stuck_minutes)
    async with sessionmaker() as db:
        result = await db.execute(
            update(EmailOutbox)
            .where(EmailOutbox.status == EmailOutboxStatus.SENDING, EmailOutbox.created_at <= cutoff)
            .values(status=EmailOutboxStatus.QUEUED)
        )
        await db.commit()
        return result.rowcount or 0


async def run_drain_loop(sessionmaker: async_sessionmaker[AsyncSession], stop: asyncio.Event) -> None:
    client = BrevoClient()
    logger.info("email outbox drain loop starting, interval=%ds", settings.email_outbox_drain_interval_seconds)
    tick = 0
    while not stop.is_set():
        try:
            if settings.email_mode_resolved != "off":
                await drain_once(sessionmaker, client)
            tick += 1
            if tick % 60 == 0:  # roughly every 5 minutes at the default interval
                reaped = await reap_stuck(sessionmaker)
                if reaped:
                    logger.warning("reaper reset %d stuck outbox row(s)", reaped)
        except Exception:  # noqa: BLE001
            logger.exception("email drain pass failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.email_outbox_drain_interval_seconds)
        except asyncio.TimeoutError:
            continue


# ---------------------------------------------------------------------------
# SLA reminders (E04)
# ---------------------------------------------------------------------------

_OPEN_STATUSES = (IncidentStatus.NEW, IncidentStatus.TRIAGE)


async def run_sla_scan(db: AsyncSession) -> int:
    from app.email.types import EmailType as ET

    now = datetime.now(timezone.utc)
    incidents = (
        await db.execute(
            select(Incident).where(Incident.deleted_at.is_(None), Incident.status.in_(_OPEN_STATUSES))
        )
    ).scalars().all()
    sent = 0
    for inc in incidents:
        sla_minutes = _SLA_MINUTES_BY_SEVERITY.get(inc.severity)
        if sla_minutes is None:
            continue
        age_minutes = (now - inc.opened_at).total_seconds() / 60
        if age_minutes < sla_minutes:
            continue

        stage = "breach" if age_minutes < sla_minutes * 2 else "escalated"
        target_users: list[User] = []
        if inc.assigned_to is not None:
            target_users = await recipients.by_id(db, inc.assigned_to)
        if stage == "escalated" or not target_users:
            target_users = list(set(target_users) | set(await recipients.admins(db)))

        recips = [Recipient(email=u.email, user_id=u.id) for u in target_users if u.email]
        if not recips:
            continue

        rows = await enqueue(
            db,
            email_type=ET.E04_SLA_REMINDER,
            recipients=recips,
            heading=f"Incident #{inc.number} is past its SLA ({stage})",
            render_context={
                "incident_number": inc.number,
                "incident_id": str(inc.id),
                "age_minutes": int(age_minutes),
                "status": inc.status.value,
                "stage": stage,
            },
            severity=inc.severity,
            dedupe_key=lambda r, inc=inc, stage=stage: f"E04:{inc.id}:{stage}",
            related_type="incident",
            related_id=str(inc.id),
            button_label="Open incident",
            button_url=render.app_link(f"/incidents/{inc.id}"),
            why_you_got_this="an incident assigned to you (or your team) is past its SLA.",
        )
        sent += len(rows)
    if sent:
        await db.commit()
    return sent


async def run_sla_scan_loop(sessionmaker: async_sessionmaker[AsyncSession], stop: asyncio.Event) -> None:
    interval = 300  # every 5 minutes, per spec
    logger.info("SLA reminder scanner starting, interval=%ds", interval)
    while not stop.is_set():
        try:
            async with sessionmaker() as db:
                await run_sla_scan(db)
        except Exception:  # noqa: BLE001
            logger.exception("SLA scan failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue


# ---------------------------------------------------------------------------
# Block expiring soon (E08)
# ---------------------------------------------------------------------------


async def run_block_expiry_scan(db: AsyncSession) -> int:
    from app.models.firewall_action import FirewallAction, FirewallActionStatus

    now = datetime.now(timezone.utc)
    soon = now + timedelta(minutes=10)
    due = (
        await db.execute(
            select(FirewallAction).where(
                FirewallAction.status == FirewallActionStatus.ACTIVE,
                FirewallAction.expires_at <= soon,
                FirewallAction.expires_at > now,
            )
        )
    ).scalars().all()

    sent = 0
    for action in due:
        target_users = await recipients.by_id(db, action.created_by)
        recips = [Recipient(email=u.email, user_id=u.id) for u in target_users if u.email]
        if not recips:
            continue
        rows = await enqueue(
            db,
            email_type=EmailType.E08_BLOCK_EXPIRING,
            recipients=recips,
            heading=f"Firewall block on {action.target} expires in under 10 minutes",
            render_context={
                "action_id": str(action.id), "target": str(action.target),
                "expires_at": action.expires_at.isoformat(),
            },
            dedupe_key=lambda r, a=action: f"E08:{a.id}",
            related_type="firewall_action", related_id=str(action.id),
            button_label="Extend or review", button_url=render.app_link(f"/firewall/{action.id}"),
            why_you_got_this="you requested this containment action.",
        )
        sent += len(rows)
    if sent:
        await db.commit()
    return sent


async def run_block_expiry_loop(sessionmaker: async_sessionmaker[AsyncSession], stop: asyncio.Event) -> None:
    interval = 60
    logger.info("block-expiring-soon scanner starting, interval=%ds", interval)
    while not stop.is_set():
        try:
            async with sessionmaker() as db:
                await run_block_expiry_scan(db)
        except Exception:  # noqa: BLE001
            logger.exception("block expiry scan failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue


# ---------------------------------------------------------------------------
# Sensor health (E15)
# ---------------------------------------------------------------------------

SENSOR_DOWN_AFTER_MINUTES = 5
SENSOR_REALERT_HOURS = 6


async def run_sensor_health_scan(db: AsyncSession) -> None:
    global _sensor_down_since, _sensor_last_alert_at

    stats = sensor_stats.read_stats()
    now = datetime.now(timezone.utc)
    captured_at = stats.get("captured_at")
    is_down = captured_at is None or (now - captured_at) > timedelta(minutes=SENSOR_DOWN_AFTER_MINUTES)

    admin_users = await recipients.admins(db)
    recips = [Recipient(email=u.email, user_id=u.id) for u in admin_users if u.email]
    if not recips:
        return

    if is_down:
        should_alert = _sensor_down_since is None or (
            _sensor_last_alert_at is not None and now - _sensor_last_alert_at >= timedelta(hours=SENSOR_REALERT_HOURS)
        )
        if _sensor_down_since is None:
            _sensor_down_since = now
        if should_alert:
            rows = await enqueue(
                db,
                email_type=EmailType.E15_SENSOR_HEALTH,
                recipients=recips,
                heading="Suricata sensor appears to be down",
                render_context={
                    "since": _sensor_down_since.isoformat(),
                    "last_event_at": captured_at.isoformat() if captured_at else None,
                },
                severity=Severity.HIGH,
                dedupe_key=lambda r, ts=now.replace(minute=0, second=0, microsecond=0): f"E15:down:{ts.isoformat()}",
                related_type="sensor", related_id="suricata",
                button_label="Open sensor page", button_url=render.app_link("/sensor"),
                why_you_got_this="you are an administrator and the detection sensor is unhealthy.",
            )
            if rows:
                _sensor_last_alert_at = now
                await db.commit()
    else:
        if _sensor_down_since is not None:
            await enqueue(
                db,
                email_type=EmailType.E15_SENSOR_HEALTH,
                recipients=recips,
                heading="Suricata sensor has recovered",
                render_context={"was_down_since": _sensor_down_since.isoformat()},
                severity=Severity.INFO,
                dedupe_key=lambda r, ts=now: f"E15:recovered:{ts.date()}:{_sensor_down_since.isoformat()}",
                related_type="sensor", related_id="suricata",
                button_label="Open sensor page", button_url=render.app_link("/sensor"),
                why_you_got_this="you are an administrator and the detection sensor state changed.",
            )
            await db.commit()
            _sensor_down_since = None
            _sensor_last_alert_at = None


async def run_sensor_health_loop(sessionmaker: async_sessionmaker[AsyncSession], stop: asyncio.Event) -> None:
    interval = settings.email_health_scan_interval_seconds
    logger.info("sensor health scanner starting, interval=%ds", interval)
    while not stop.is_set():
        try:
            async with sessionmaker() as db:
                await run_sensor_health_scan(db)
        except Exception:  # noqa: BLE001
            logger.exception("sensor health scan failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue


# ---------------------------------------------------------------------------
# Pipeline backlog (E16)
# ---------------------------------------------------------------------------

PIPELINE_BACKLOG_THRESHOLD = 10_000
PIPELINE_BACKLOG_STREAK_REQUIRED = 5  # ~5 scan intervals ≈ 5 minutes at 60s


async def run_pipeline_backlog_scan(db: AsyncSession, redis: aioredis.Redis) -> None:
    global _backlog_breach_streak, _backlog_last_alert_at

    try:
        length = await redis.xlen(STREAM_KEY)
    except Exception:  # noqa: BLE001
        return

    now = datetime.now(timezone.utc)
    if length < PIPELINE_BACKLOG_THRESHOLD:
        _backlog_breach_streak = 0
        return

    _backlog_breach_streak += 1
    if _backlog_breach_streak < PIPELINE_BACKLOG_STREAK_REQUIRED:
        return
    if _backlog_last_alert_at is not None and now - _backlog_last_alert_at < timedelta(hours=1):
        return

    admin_users = await recipients.admins(db)
    recips = [Recipient(email=u.email, user_id=u.id) for u in admin_users if u.email]
    if not recips:
        return

    rows = await enqueue(
        db,
        email_type=EmailType.E16_PIPELINE_BACKLOG,
        recipients=recips,
        heading="Event pipeline backlog is growing",
        render_context={"backlog_size": length},
        severity=Severity.MEDIUM,
        dedupe_key=lambda r, ts=now.replace(minute=0, second=0, microsecond=0): f"E16:{ts.isoformat()}",
        related_type="pipeline", related_id="stream_backlog",
        button_label="Open pipeline status", button_url=render.app_link("/pipeline"),
        why_you_got_this="you are an administrator and ingestion is falling behind.",
    )
    if rows:
        _backlog_last_alert_at = now
        await db.commit()


async def run_pipeline_backlog_loop(
    sessionmaker: async_sessionmaker[AsyncSession], redis: aioredis.Redis, stop: asyncio.Event
) -> None:
    interval = 60
    logger.info("pipeline backlog scanner starting, interval=%ds", interval)
    while not stop.is_set():
        try:
            async with sessionmaker() as db:
                await run_pipeline_backlog_scan(db, redis)
        except Exception:  # noqa: BLE001
            logger.exception("pipeline backlog scan failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue


# ---------------------------------------------------------------------------
# Digest (E14)
# ---------------------------------------------------------------------------


async def _build_digest_for_user(db: AsyncSession, prefs: EmailPreferences, user: User, now: datetime) -> bool:
    from app.models.firewall_action import FirewallAction
    from app.models.ioc import IocMatch

    period_days = 7 if prefs.digest_frequency.value == "weekly" else 1
    period_start = now - timedelta(days=period_days)

    pending = (
        await db.execute(
            select(EmailOutbox).where(
                EmailOutbox.recipient_user_id == user.id,
                EmailOutbox.digest.is_(True),
                EmailOutbox.status == EmailOutboxStatus.QUEUED,
            )
        )
    ).scalars().all()

    by_type: dict[str, int] = {}
    for row in pending:
        by_type[row.email_type.value] = by_type.get(row.email_type.value, 0) + 1

    new_incidents = (
        await db.execute(
            select(Incident).where(Incident.deleted_at.is_(None), Incident.opened_at >= period_start)
        )
    ).scalars().all()
    by_severity: dict[str, int] = {}
    for inc in new_incidents:
        by_severity[inc.severity.value] = by_severity.get(inc.severity.value, 0) + 1

    open_past_sla = (
        await db.execute(
            select(Incident).where(Incident.deleted_at.is_(None), Incident.status.in_(_OPEN_STATUSES))
        )
    ).scalars().all()
    overdue = [
        inc for inc in open_past_sla
        if inc.severity in _SLA_MINUTES_BY_SEVERITY
        and (now - inc.opened_at).total_seconds() / 60 >= _SLA_MINUTES_BY_SEVERITY[inc.severity]
    ]

    containment_count = int(
        await db.scalar(select(func.count()).select_from(FirewallAction).where(FirewallAction.created_at >= period_start)) or 0
    )
    ioc_hit_count = int(
        await db.scalar(select(func.count()).select_from(IocMatch).where(IocMatch.ts >= period_start)) or 0
    )

    has_content = bool(by_type or by_severity or overdue or containment_count or ioc_hit_count)
    if not has_content and not settings.email_send_empty_digest:
        for row in pending:
            row.status = EmailOutboxStatus.SENT
            row.sent_at = now
        return False

    rows = await enqueue(
        db,
        email_type=EmailType.E14_DIGEST,
        recipients=[Recipient(email=user.email, user_id=user.id)],
        heading=f"Your SentinelCore {prefs.digest_frequency.value} digest",
        render_context={
            "period_start": period_start.isoformat(),
            "period_end": now.isoformat(),
            "new_incidents_by_severity": by_severity,
            "overdue_incidents": [{"number": i.number, "severity": i.severity.value} for i in overdue],
            "containment_count": containment_count,
            "ioc_hit_count": ioc_hit_count,
            "queued_by_type": by_type,
        },
        dedupe_key=lambda r, u=user, ps=period_start: f"E14:{u.id}:{ps.date()}",
        related_type="digest", related_id=str(user.id),
        button_label="Open dashboard", button_url=render.app_link("/dashboard"),
        why_you_got_this="your notification preferences are set to digest delivery.",
    )
    if rows:
        for row in pending:
            row.status = EmailOutboxStatus.SENT
            row.sent_at = now
    return bool(rows)


async def run_digest_builder(db: AsyncSession) -> int:
    now = datetime.now(timezone.utc)
    due = (
        await db.execute(
            select(EmailPreferences).where(
                EmailPreferences.delivery_mode == "digest", EmailPreferences.digest_hour_utc == now.hour
            )
        )
    ).scalars().all()

    built = 0
    for prefs in due:
        user = await db.get(User, prefs.user_id)
        if user is None or not user.is_active or not user.email:
            continue
        if await _build_digest_for_user(db, prefs, user, now):
            built += 1
    if due:
        await db.commit()
    return built


async def run_digest_loop(sessionmaker: async_sessionmaker[AsyncSession], stop: asyncio.Event) -> None:
    logger.info("digest builder starting")
    last_run_hour: int | None = None
    while not stop.is_set():
        now = datetime.now(timezone.utc)
        if last_run_hour != now.hour:
            try:
                async with sessionmaker() as db:
                    await run_digest_builder(db)
            except Exception:  # noqa: BLE001
                logger.exception("digest build failed")
            last_run_hour = now.hour
        try:
            await asyncio.wait_for(stop.wait(), timeout=300)
        except asyncio.TimeoutError:
            continue


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


async def enforce_outbox_retention(sessionmaker: async_sessionmaker[AsyncSession]) -> int:
    now = datetime.now(timezone.utc)
    sent_cutoff = now - timedelta(days=settings.email_outbox_retention_sent_days)
    failed_cutoff = now - timedelta(days=settings.email_outbox_retention_failed_days)

    async with sessionmaker() as db:
        result = await db.execute(
            delete(EmailOutbox).where(
                or_(
                    EmailOutbox.status.in_([EmailOutboxStatus.SENT, EmailOutboxStatus.SUPPRESSED]) & (EmailOutbox.created_at <= sent_cutoff),
                    (EmailOutbox.status == EmailOutboxStatus.FAILED) & (EmailOutbox.created_at <= failed_cutoff),
                )
            )
        )
        await db.commit()
        return result.rowcount or 0
