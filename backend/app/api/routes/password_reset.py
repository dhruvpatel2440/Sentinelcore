"""E19 — self-service password reset. Unauthenticated, rate-limited, and
deliberately uninformative: the response is identical whether the account
exists or not, so this endpoint cannot be used to enumerate usernames.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.password_reset import PasswordResetAccepted, PasswordResetConfirm, PasswordResetRequest
from app.services import audit, password_reset

router = APIRouter(prefix="/auth/password-reset", tags=["auth"])


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip() or None
    return request.client.host if request.client else None


@router.post("/request", response_model=PasswordResetAccepted)
async def request_reset(
    payload: PasswordResetRequest, request: Request, db: AsyncSession = Depends(get_db)
) -> PasswordResetAccepted:
    ip = _client_ip(request)
    accepted = PasswordResetAccepted()

    if await password_reset.is_rate_limited(username=payload.username, ip=ip):
        # Same response as success — a 429 here would itself leak information
        # about which usernames are being probed.
        return accepted

    user = (await db.execute(select(User).where(User.username == payload.username))).scalar_one_or_none()
    if user is not None and user.is_active and user.email:
        raw_token = await password_reset.issue_token(db, user, requested_ip=ip)
        await audit.record(
            db, action="auth.password_reset_requested", user=user, resource_type="user",
            resource_id=str(user.id), request=request,
        )
        await db.commit()
        await password_reset.send_password_email(db, user, raw_token, purpose="reset")
    else:
        await audit.record(
            db, action="auth.password_reset_requested", username=payload.username,
            outcome="no_such_account_or_inactive", request=request,
        )
        await db.commit()

    return accepted


@router.post("/confirm", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def confirm_reset(
    payload: PasswordResetConfirm, request: Request, db: AsyncSession = Depends(get_db)
) -> None:
    user = await password_reset.consume_token(db, payload.token)
    if user is None:
        await audit.record(
            db, action="auth.password_reset_confirmed", outcome="failure", error="invalid_or_expired_token",
            request=request,
        )
        await db.commit()
        # Same shape as a bad credential check — do not distinguish "token
        # didn't exist" from "token expired" from "token already used".
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

    user.password_hash = hash_password(payload.new_password)
    user.tokens_valid_from = datetime.now(timezone.utc)

    await audit.record(
        db, action="auth.password_reset_confirmed", user=user, resource_type="user",
        resource_id=str(user.id), request=request,
    )
    await db.commit()

    from app.email.render import app_link
    from app.email.service import Recipient, enqueue
    from app.email.types import EmailType

    if user.email:
        await enqueue(
            db,
            email_type=EmailType.E20_ACCOUNT_CHANGED,
            recipients=[Recipient(email=user.email, user_id=user.id)],
            heading="Your SentinelCore password was changed",
            render_context={
                "what_changed": "Your password was changed via the password-reset flow.",
                "changed_by": "you (password reset)",
                "changed_at": datetime.now(timezone.utc).isoformat(),
            },
            dedupe_key=None,
            related_type="user", related_id=str(user.id),
            button_label="Open SentinelCore", button_url=app_link("/login"),
            why_you_got_this="this is a security notice for your account and cannot be disabled.",
        )
        await db.commit()
