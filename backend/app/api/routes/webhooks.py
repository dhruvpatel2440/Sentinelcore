"""Brevo delivery-event webhook (U10 Part 6).

Unauthenticated in the FastAPI-dependency sense — there is no user session —
but gated by a shared secret compared with `hmac.compare_digest`. Brevo is
told to send `Authorization: Bearer <BREVO_WEBHOOK_SECRET>` (or the header
name your Brevo plan offers); this endpoint checks whichever is present.

If the lab host is not reachable from the internet, this endpoint is simply
never called — Brevo events then show up only in the Brevo dashboard and
delivery failures surface via the API error codes `BrevoClient` already
classifies. `GET /api/email/status.webhook_active` tells the admin UI which
mode is in effect so that is never a silent gap.
"""

from __future__ import annotations

import hmac
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.email import EmailOutbox, EmailOutboxStatus, EmailSuppression, EmailSuppressionReason
from app.schemas.email import BrevoWebhookEvent

router = APIRouter(prefix="/webhooks", tags=["webhooks"])
logger = logging.getLogger("sentinelcore.email.webhook")

MAX_BODY_BYTES = 64 * 1024

_BOUNCE_LIKE = {
    "hard_bounce": EmailSuppressionReason.HARD_BOUNCE,
    "blocked": EmailSuppressionReason.BLOCKED,
    "spam": EmailSuppressionReason.SPAM,
    "unsubscribed": EmailSuppressionReason.UNSUBSCRIBED,
}


def _secret_ok(request: Request) -> bool:
    if not settings.brevo_webhook_secret:
        return False
    provided = request.headers.get("authorization", "")
    if provided.lower().startswith("bearer "):
        provided = provided[7:]
    return hmac.compare_digest(provided, settings.brevo_webhook_secret)


@router.post("/brevo", status_code=status.HTTP_200_OK)
async def brevo_webhook(request: Request, db: AsyncSession = Depends(get_db)) -> dict:
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="payload too large")

    if not _secret_ok(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid signature")

    try:
        payload = BrevoWebhookEvent.model_validate_json(raw)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="malformed payload") from exc

    if payload.message_id:
        row = (
            await db.execute(select(EmailOutbox).where(EmailOutbox.provider_message_id == payload.message_id))
        ).scalar_one_or_none()
        if row is not None:
            if payload.event == "delivered":
                row.status = EmailOutboxStatus.SENT
            elif payload.event in _BOUNCE_LIKE:
                row.status = EmailOutboxStatus.FAILED
                row.last_error = f"brevo event: {payload.event}"[:500]
            else:
                # deferred / soft_bounce / error / request / opened / click — logged, not fatal.
                logger.info("brevo webhook event=%s outbox_id=%s", payload.event, row.id)

    if payload.event in _BOUNCE_LIKE and payload.email:
        reason = _BOUNCE_LIKE[payload.event]
        stmt = pg_insert(EmailSuppression).values(email=payload.email.lower(), reason=reason)
        stmt = stmt.on_conflict_do_update(index_elements=["email"], set_={"reason": reason})
        await db.execute(stmt)

    await db.commit()
    return {"ok": True}
