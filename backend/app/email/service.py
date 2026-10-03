"""`enqueue()` — the single entry point that writes to `email_outbox`.

Nothing else inserts a row here (CLAUDE.md-style single write path). Every
hook in the platform (incident promotion, firewall, reports, worker
scanners, auth) calls this instead of talking to Brevo or the outbox table
directly, so preferences/caps/suppression/dedupe are enforced exactly once.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, time, timezone
from typing import Any, Callable
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.email import render
from app.email.types import DIGEST_ELIGIBLE_TYPES, LOCKED_TYPES, NEVER_DIGESTED_TYPES, SEVERITY_GATED_TYPES, EmailType, severity_at_least
from app.models.email import EmailDeliveryMode, EmailOutbox, EmailOutboxStatus, EmailPreferences, EmailSettings, EmailSuppression
from app.models.event import Severity
from app.models.user import User

logger = logging.getLogger("sentinelcore.email.service")


IST = ZoneInfo("Asia/Kolkata")


@dataclass(frozen=True)
class Recipient:
    email: str
    user_id: uuid.UUID | None = None


def _today_start(now: datetime) -> datetime:
    """Start of the current IST day, as a UTC instant. The caps are a per-day
    budget and this platform is operated from IST, so the budget has to roll
    over at IST midnight — a UTC-midnight reset lands at 05:30 IST, halfway
    through the Indian working morning."""
    ist_today = now.astimezone(IST).date()
    return datetime.combine(ist_today, time.min, tzinfo=IST).astimezone(timezone.utc)


async def get_settings_row(db: AsyncSession) -> EmailSettings:
    row = await db.get(EmailSettings, 1)
    if row is None:
        row = EmailSettings(id=1, types_enabled={}, global_pause=False)
        db.add(row)
        await db.flush()
    return row


async def get_or_create_preferences(db: AsyncSession, user_id: uuid.UUID) -> EmailPreferences:
    prefs = await db.get(EmailPreferences, user_id)
    if prefs is None:
        prefs = EmailPreferences(user_id=user_id)
        db.add(prefs)
        await db.flush()
    return prefs


async def is_suppressed(db: AsyncSession, email: str) -> bool:
    return (await db.scalar(select(EmailSuppression.id).where(EmailSuppression.email == email.lower()))) is not None


def _allowed_domain(email: str) -> bool:
    allowed = settings.email_allowed_recipient_domains_parsed
    if not allowed:
        return True
    domain = email.rsplit("@", 1)[-1].lower()
    return domain in allowed


async def resolve_recipients_from_users(db: AsyncSession, users: list[User]) -> list[Recipient]:
    """Step 1 of the catalog pipeline: drop users with no email, inactive
    users, and domains outside the allow-list. Suppression/caps/preferences
    are still checked per-recipient inside `enqueue()`."""
    out: list[Recipient] = []
    for user in users:
        if not user.is_active or not user.email:
            continue
        if not _allowed_domain(user.email):
            continue
        out.append(Recipient(email=user.email, user_id=user.id))
    return out


async def _daily_count(db: AsyncSession, *, recipient_email: str | None, now: datetime) -> int:
    stmt = select(func.count()).select_from(EmailOutbox).where(
        EmailOutbox.created_at >= _today_start(now),
        EmailOutbox.status != EmailOutboxStatus.SUPPRESSED,
    )
    if recipient_email is not None:
        stmt = stmt.where(EmailOutbox.recipient_email == recipient_email)
    return int(await db.scalar(stmt) or 0)


async def _insert_row(
    db: AsyncSession,
    *,
    email_type: EmailType,
    recipient: Recipient,
    subject: str,
    html: str,
    text: str,
    status: EmailOutboxStatus,
    dedupe_key: str | None,
    digest: bool,
    related_type: str | None,
    related_id: str | None,
    last_error: str | None = None,
) -> EmailOutbox | None:
    """Inserts with `ON CONFLICT DO NOTHING` on the unique `dedupe_key`
    index — the real guarantee against a duplicate send under concurrent
    `enqueue()` calls (not the Python-level check above, which only avoids
    an unnecessary render in the common case)."""
    values = dict(
        id=uuid.uuid4(),
        email_type=email_type,
        recipient_user_id=recipient.user_id,
        recipient_email=recipient.email,
        subject=subject,
        html_body=html,
        text_body=text,
        dedupe_key=dedupe_key,
        status=status,
        digest=digest,
        related_type=related_type,
        related_id=related_id,
        last_error=last_error,
    )
    if dedupe_key is None:
        db.add(EmailOutbox(**values))
        await db.flush()
        return None

    stmt = pg_insert(EmailOutbox).values(**values)
    stmt = stmt.on_conflict_do_nothing(
        index_elements=["dedupe_key"], index_where=sa_text("dedupe_key IS NOT NULL")
    ).returning(EmailOutbox.id)
    result = await db.execute(stmt)
    inserted_id = result.scalar_one_or_none()
    if inserted_id is None:
        logger.info("enqueue: dedupe_key %r already present, skipped", dedupe_key)
        return None
    return await db.get(EmailOutbox, inserted_id)


async def enqueue(
    db: AsyncSession,
    *,
    email_type: EmailType,
    recipients: list[Recipient],
    heading: str,
    render_context: dict[str, Any],
    severity: Severity | None = None,
    dedupe_key: Callable[[Recipient], str | None] | None = None,
    related_type: str | None = None,
    related_id: str | None = None,
    button_label: str | None = None,
    button_url: str | None = None,
    why_you_got_this: str | None = None,
) -> list[EmailOutbox]:
    mode = settings.email_mode_resolved
    if mode == "off":
        return []

    settings_row = await get_settings_row(db)
    if settings_row.global_pause:
        return []
    if settings_row.types_enabled.get(email_type.value, True) is False:
        return []

    now = datetime.now(timezone.utc)
    inserted: list[EmailOutbox] = []
    locked = email_type in LOCKED_TYPES
    digest_eligible = email_type in DIGEST_ELIGIBLE_TYPES and email_type not in NEVER_DIGESTED_TYPES

    for recipient in recipients:
        if not recipient.email:
            continue
        if not _allowed_domain(recipient.email):
            continue
        if await is_suppressed(db, recipient.email):
            continue  # dropped per catalog step 1 — never sent to again

        prefs: EmailPreferences | None = None
        if recipient.user_id is not None:
            prefs = await get_or_create_preferences(db, recipient.user_id)
            if not locked:
                if not prefs.enabled:
                    continue
                if email_type.value in prefs.types_disabled:
                    continue
            if email_type in SEVERITY_GATED_TYPES and severity is not None:
                if not severity_at_least(severity, prefs.min_severity):
                    continue

        key = dedupe_key(recipient) if dedupe_key is not None else None

        route_to_digest = (
            digest_eligible
            and prefs is not None
            and prefs.delivery_mode == EmailDeliveryMode.DIGEST
        )

        if not route_to_digest:
            per_recipient_count = await _daily_count(db, recipient_email=recipient.email, now=now)
            global_count = await _daily_count(db, recipient_email=None, now=now)
            if per_recipient_count >= settings.email_daily_cap_per_recipient or global_count >= settings.email_global_daily_cap:
                logger.warning(
                    "email cap exceeded type=%s recipient=%s per_recipient=%d global=%d",
                    email_type.value, recipient.email, per_recipient_count, global_count,
                )
                await _insert_row(
                    db, email_type=email_type, recipient=recipient, subject="", html="", text="",
                    status=EmailOutboxStatus.SUPPRESSED, dedupe_key=key, digest=False,
                    related_type=related_type, related_id=related_id, last_error="daily cap exceeded",
                )
                continue

        subject = render.build_subject(prefix_severity=severity.value if severity else None, title=heading)
        context = {
            "heading": heading,
            "severity": severity.value if severity else None,
            "button_label": button_label,
            "button_url": button_url,
            "why_you_got_this": why_you_got_this,
            "prefs_url": render.app_link("/profile/notifications"),
            **render_context,
        }
        html, text = render.render(email_type, context)

        status = EmailOutboxStatus.DRY_RUN if mode == "dry_run" else EmailOutboxStatus.QUEUED
        row = await _insert_row(
            db, email_type=email_type, recipient=recipient, subject=subject, html=html, text=text,
            status=status, dedupe_key=key, digest=route_to_digest,
            related_type=related_type, related_id=related_id,
        )
        if row is not None:
            inserted.append(row)

    return inserted
