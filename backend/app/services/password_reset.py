"""E19 password reset / set-password flow.

Token model: 32 random bytes, URL-safe. Only its SHA-256 hash is ever
stored — the raw token exists only in memory for the duration of this
request and inside the one email it is sent in. 30 minute expiry, single
use, and consuming it bumps `tokens_valid_from` so every other session is
revoked at the same time (CLAUDE.md: Argon2 hashing, every write audited).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import get_redis
from app.email.render import app_link
from app.email.service import Recipient, enqueue
from app.email.types import EmailType
from app.models.password_reset import PasswordResetToken
from app.models.user import User

TOKEN_TTL_MINUTES = 30
RATE_LIMIT_PER_HOUR = 3
# Per-account ceiling across ALL source IPs. Much higher than the per-(account, IP)
# limit so a third party cannot lock the real owner out of recovery.
ACCOUNT_GLOBAL_LIMIT_PER_HOUR = 20
RATE_LIMIT_WINDOW_SECONDS = 3600


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def _rate_limited(key: str, limit: int = RATE_LIMIT_PER_HOUR) -> bool:
    try:
        redis = get_redis()
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, RATE_LIMIT_WINDOW_SECONDS)
        return count > limit
    except Exception:
        # Redis down must not block password recovery entirely.
        return False


async def is_rate_limited(*, username: str, ip: str | None) -> bool:
    # Keyed on (account, IP): an attacker burning their own quota against a
    # victim's username no longer exhausts the quota the victim needs.
    acct_ip_hit = await _rate_limited(f"pwreset:acct:{username.lower()}:{ip or '-'}")
    acct_hit = await _rate_limited(f"pwreset:acct_all:{username.lower()}", ACCOUNT_GLOBAL_LIMIT_PER_HOUR)
    ip_hit = await _rate_limited(f"pwreset:ip:{ip or '-'}", RATE_LIMIT_PER_HOUR * 5)
    return acct_ip_hit or acct_hit or ip_hit


async def issue_token(db: AsyncSession, user: User, *, requested_ip: str | None) -> str:
    raw = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=_hash(raw),
            expires_at=now + timedelta(minutes=TOKEN_TTL_MINUTES),
            requested_ip=requested_ip,
        )
    )
    await db.flush()
    return raw


async def consume_token(db: AsyncSession, raw_token: str) -> User | None:
    """Returns the user if `raw_token` is valid, unexpired, and unused —
    marking it used in the same call. Returns `None` for every failure mode
    (unknown/expired/used), deliberately indistinguishable to the caller so
    the API response cannot be used to enumerate valid tokens."""
    now = datetime.now(timezone.utc)
    row = (
        await db.execute(select(PasswordResetToken)
            .where(PasswordResetToken.token_hash == _hash(raw_token))
            # Row lock: two concurrent confirms must not both see used_at IS NULL.
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None or row.used_at is not None or row.expires_at < now:
        return None
    row.used_at = now
    user = await db.get(User, row.user_id)
    return user


async def send_password_email(db: AsyncSession, user: User, raw_token: str, *, purpose: str) -> None:
    """`purpose` is `"set_password"` (admin-created account) or `"reset"`
    (self-service forgot-password)."""
    if not user.email:
        return
    await enqueue(
        db,
        email_type=EmailType.E19_ACCOUNT_PASSWORD,
        recipients=[Recipient(email=user.email, user_id=user.id)],
        heading="Set your SentinelCore password" if purpose == "set_password" else "Reset your SentinelCore password",
        render_context={
            "display_name": user.full_name or user.username,
            "purpose": purpose,
            "expiry_minutes": TOKEN_TTL_MINUTES,
        },
        dedupe_key=lambda r, uid=user.id, t=raw_token: f"E19:{uid}:{_hash(t)}",
        related_type="user", related_id=str(user.id),
        button_label="Set password" if purpose == "set_password" else "Reset password",
        button_url=app_link(f"/reset-password?token={raw_token}"),
        why_you_got_this="this is the account email on file for this request.",
    )
    await db.commit()
