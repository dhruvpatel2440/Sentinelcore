"""U10 Part 7 — admin email status, settings, outbox, suppressions, test send."""

from __future__ import annotations

import uuid
from datetime import datetime, time, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.config import settings
from app.core.redis import get_redis
from app.db.session import get_db
from app.email.render import app_link
from app.email.service import Recipient, enqueue, get_settings_row
from app.email.types import EmailType
from app.models.email import EmailOutbox, EmailOutboxStatus, EmailSettings, EmailSuppression
from app.models.user import User
from app.schemas.email import (
    EmailOutboxListOut,
    EmailOutboxOut,
    EmailSettingsOut,
    EmailSettingsUpdate,
    EmailStatusOut,
    EmailSuppressionOut,
)
from app.services import audit

router = APIRouter(prefix="/email", tags=["email"])

_TEST_SEND_RATE_KEY = "email:test_send:{user_id}"
_TEST_SEND_LIMIT_PER_HOUR = 5


@router.get("/status", response_model=EmailStatusOut)
async def email_status(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> EmailStatusOut:
    settings_row = await get_settings_row(db)
    today_start = datetime.combine(datetime.now(timezone.utc).date(), time.min, tzinfo=timezone.utc)

    queue_depth = int(
        await db.scalar(select(func.count()).select_from(EmailOutbox).where(EmailOutbox.status == EmailOutboxStatus.QUEUED)) or 0
    )
    failed_count = int(
        await db.scalar(select(func.count()).select_from(EmailOutbox).where(EmailOutbox.status == EmailOutboxStatus.FAILED)) or 0
    )
    sends_today = int(
        await db.scalar(
            select(func.count()).select_from(EmailOutbox).where(
                EmailOutbox.created_at >= today_start, EmailOutbox.status != EmailOutboxStatus.SUPPRESSED
            )
        )
        or 0
    )
    last_sent = await db.scalar(
        select(func.max(EmailOutbox.sent_at)).where(EmailOutbox.status == EmailOutboxStatus.SENT)
    )

    return EmailStatusOut(
        mode=settings.email_mode_resolved,
        sender=settings.email_sender_address,
        api_key_present=bool(settings.brevo_api_key),
        last_successful_send_at=last_sent,
        queue_depth=queue_depth,
        failed_count=failed_count,
        sends_today=sends_today,
        daily_cap_per_recipient=settings.email_daily_cap_per_recipient,
        global_daily_cap=settings.email_global_daily_cap,
        global_pause=settings_row.global_pause,
        webhook_active=bool(settings.brevo_webhook_secret),
    )


@router.post("/test", status_code=status.HTTP_202_ACCEPTED)
async def send_test_email(
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> dict:
    if not actor.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Your account has no email on file")

    key = _TEST_SEND_RATE_KEY.format(user_id=actor.id)
    try:
        redis = get_redis()
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, 3600)
        if count > _TEST_SEND_LIMIT_PER_HOUR:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many test emails this hour")
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 — redis down should not block a test send
        pass

    await enqueue(
        db,
        email_type=EmailType.E20_ACCOUNT_CHANGED,
        recipients=[Recipient(email=actor.email, user_id=actor.id)],
        heading="SentinelCore test email",
        render_context={
            "what_changed": "This is a test email from SentinelCore's admin panel.",
            "changed_by": actor.username,
            "changed_at": datetime.now(timezone.utc).isoformat(),
        },
        dedupe_key=None,
        related_type="email_test", related_id=str(actor.id),
        button_label="Open SentinelCore", button_url=app_link("/"),
        why_you_got_this="you asked for a test email from the admin panel.",
    )
    await audit.record(db, action="email.test_sent", user=actor, request=request)
    await db.commit()
    return {"detail": "Test email queued"}


@router.get("/settings", response_model=EmailSettingsOut)
async def get_email_settings(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> EmailSettingsOut:
    row = await get_settings_row(db)
    await db.commit()
    return EmailSettingsOut(types_enabled=row.types_enabled, global_pause=row.global_pause, updated_at=row.updated_at)


@router.put("/settings", response_model=EmailSettingsOut)
async def update_email_settings(
    payload: EmailSettingsUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> EmailSettingsOut:
    row = await get_settings_row(db)
    changes = payload.model_dump(exclude_unset=True)
    if "types_enabled" in changes and changes["types_enabled"] is not None:
        row.types_enabled = {**row.types_enabled, **changes["types_enabled"]}
    if "global_pause" in changes and changes["global_pause"] is not None:
        row.global_pause = changes["global_pause"]
    row.updated_by = actor.id
    row.updated_at = datetime.now(timezone.utc)

    await audit.record(db, action="email.settings_updated", user=actor, detail=changes, request=request)
    await db.commit()
    await db.refresh(row)
    return EmailSettingsOut(types_enabled=row.types_enabled, global_pause=row.global_pause, updated_at=row.updated_at)


@router.get("/outbox", response_model=EmailOutboxListOut)
async def list_outbox(
    status_filter: EmailOutboxStatus | None = Query(default=None, alias="status"),
    email_type: EmailType | None = Query(default=None),
    include_body: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> EmailOutboxListOut:
    stmt = select(EmailOutbox)
    count_stmt = select(func.count()).select_from(EmailOutbox)
    if status_filter is not None:
        stmt = stmt.where(EmailOutbox.status == status_filter)
        count_stmt = count_stmt.where(EmailOutbox.status == status_filter)
    if email_type is not None:
        stmt = stmt.where(EmailOutbox.email_type == email_type)
        count_stmt = count_stmt.where(EmailOutbox.email_type == email_type)

    total = int(await db.scalar(count_stmt) or 0)
    rows = (
        await db.execute(stmt.order_by(EmailOutbox.created_at.desc()).limit(limit).offset(offset))
    ).scalars().all()

    items = []
    for row in rows:
        out = EmailOutboxOut.model_validate(row)
        if not include_body:
            out.html_body = None
            out.text_body = None
        items.append(out)
    return EmailOutboxListOut(items=items, total=total)


@router.post("/outbox/{outbox_id}/retry", status_code=status.HTTP_202_ACCEPTED)
async def retry_outbox_row(
    outbox_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> dict:
    row = await db.get(EmailOutbox, outbox_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Outbox row not found")
    if row.status != EmailOutboxStatus.FAILED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only failed rows can be retried")

    row.status = EmailOutboxStatus.QUEUED
    row.next_attempt_at = datetime.now(timezone.utc)
    row.attempts = 0
    await audit.record(db, action="email.outbox_retry", user=actor, resource_type="email_outbox", resource_id=row.id, request=request)
    await db.commit()
    return {"detail": "Queued for retry"}


@router.get("/suppressions", response_model=list[EmailSuppressionOut])
async def list_suppressions(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> list[EmailSuppressionOut]:
    rows = (await db.execute(select(EmailSuppression).order_by(EmailSuppression.created_at.desc()))).scalars().all()
    return [EmailSuppressionOut.model_validate(r) for r in rows]


@router.delete("/suppressions/{suppression_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_suppression(
    suppression_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> None:
    row = await db.get(EmailSuppression, suppression_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppression not found")
    email = row.email
    await db.delete(row)
    await audit.record(db, action="email.suppression_removed", user=actor, resource_type="email_suppression", resource_id=suppression_id, detail={"email": email}, request=request)
    await db.commit()
