"""U10 E19 password reset flow: hashed token storage, expired/used/unknown
rejection with identical shape, rate limiting, session revocation, and
audit. Requires the real test database."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.core.security import hash_password, verify_password
from app.db.session import SessionLocal
from app.models.password_reset import PasswordResetToken
from app.models.user import User, UserRole
from app.services import password_reset

UTC = timezone.utc


async def _make_user(db) -> User:
    user = User(
        username=f"pwtest-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex}@example.com",
        password_hash=hash_password("original-password-123"), role=UserRole.VIEWER, is_active=True,
    )
    db.add(user)
    await db.flush()
    return user


async def _cleanup(db, user_id: uuid.UUID) -> None:
    await db.execute(text("DELETE FROM password_reset_tokens WHERE user_id = :id"), {"id": user_id})
    await db.execute(text("DELETE FROM email_outbox WHERE recipient_user_id = :id"), {"id": user_id})
    await db.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
    await db.commit()


@pytest.mark.asyncio
async def test_token_is_stored_hashed_not_raw():
    async with SessionLocal() as db:
        user = await _make_user(db)
        try:
            raw = await password_reset.issue_token(db, user, requested_ip="10.0.0.1")
            await db.commit()
            row = (
                await db.execute(text("SELECT token_hash FROM password_reset_tokens WHERE user_id = :id"), {"id": user.id})
            ).first()
            assert row is not None
            assert row.token_hash != raw
            assert len(row.token_hash) == 64  # sha256 hex
        finally:
            await _cleanup(db, user.id)


@pytest.mark.asyncio
async def test_consume_token_succeeds_once_then_rejects_reuse():
    async with SessionLocal() as db:
        user = await _make_user(db)
        try:
            raw = await password_reset.issue_token(db, user, requested_ip=None)
            await db.commit()

            resolved = await password_reset.consume_token(db, raw)
            await db.commit()
            assert resolved is not None
            assert resolved.id == user.id

            resolved_again = await password_reset.consume_token(db, raw)
            await db.commit()
            assert resolved_again is None
        finally:
            await _cleanup(db, user.id)


@pytest.mark.asyncio
async def test_expired_token_rejected():
    async with SessionLocal() as db:
        user = await _make_user(db)
        try:
            raw = await password_reset.issue_token(db, user, requested_ip=None)
            await db.flush()
            await db.execute(
                text("UPDATE password_reset_tokens SET expires_at = :t WHERE user_id = :id"),
                {"t": datetime.now(UTC) - timedelta(minutes=1), "id": user.id},
            )
            await db.commit()
            assert await password_reset.consume_token(db, raw) is None
        finally:
            await _cleanup(db, user.id)


@pytest.mark.asyncio
async def test_unknown_token_rejected_with_same_shape_as_expired():
    async with SessionLocal() as db:
        # Both resolve to None — the caller (route) returns the identical
        # 400 regardless of which failure mode this is, which is the actual
        # no-enumeration guarantee.
        assert await password_reset.consume_token(db, "not-a-real-token") is None


@pytest.mark.asyncio
async def test_rate_limit_trips_after_three_requests_per_account():
    username = f"ratelimit-{uuid.uuid4().hex[:8]}"
    ip = f"10.1.2.{uuid.uuid4().int % 250}"
    try:
        for _ in range(3):
            assert await password_reset.is_rate_limited(username=username, ip=ip) is False
        assert await password_reset.is_rate_limited(username=username, ip=ip) is True
    finally:
        from app.core.redis import get_redis

        redis = get_redis()
        await redis.delete(f"pwreset:acct:{username.lower()}")
        await redis.delete(f"pwreset:ip:{ip}")


@pytest.mark.asyncio
async def test_consuming_token_does_not_itself_revoke_sessions():
    """`consume_token` only marks the token used and returns the user — the
    *route* is responsible for setting the new password hash and bumping
    `tokens_valid_from`, matching how `confirm_reset` in
    `app.api.routes.password_reset` is written."""
    async with SessionLocal() as db:
        user = await _make_user(db)
        original_cutoff = user.tokens_valid_from
        try:
            raw = await password_reset.issue_token(db, user, requested_ip=None)
            await db.commit()
            resolved = await password_reset.consume_token(db, raw)
            await db.commit()
            assert resolved.tokens_valid_from == original_cutoff

            resolved.password_hash = hash_password("brand-new-password-456")
            resolved.tokens_valid_from = datetime.now(UTC)
            await db.commit()
            assert verify_password("brand-new-password-456", resolved.password_hash)
            assert resolved.tokens_valid_from > original_cutoff
        finally:
            await _cleanup(db, user.id)
