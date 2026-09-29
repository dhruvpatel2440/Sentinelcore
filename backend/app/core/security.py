"""Password hashing (Argon2) and JWT issuing/verification.

Argon2id is mandated by CLAUDE.md. Never swap this for bcrypt/sha*.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import settings

_hasher = PasswordHasher()

TokenType = Literal["access", "refresh"]


class TokenError(Exception):
    """Raised when a JWT is malformed, expired, or of the wrong type."""


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        _hasher.verify(password_hash, password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash uses outdated Argon2 parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def _encode(subject: str, token_type: TokenType, expires_delta: timedelta, **extra: Any) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": str(uuid.uuid4()),
        **extra,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_access_token(user_id: uuid.UUID, role: str) -> str:
    return _encode(
        str(user_id),
        "access",
        timedelta(minutes=settings.access_token_expire_minutes),
        role=role,
    )


def create_refresh_token(user_id: uuid.UUID, session_id: str) -> str:
    """`session_id` lets a single refresh lineage be revoked on logout."""
    return _encode(
        str(user_id),
        "refresh",
        timedelta(days=settings.refresh_token_expire_days),
        sid=session_id,
    )


def decode_token(token: str, expected_type: TokenType) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("Token is invalid") from exc

    # A refresh token must never be usable as an access token, and vice versa.
    if payload.get("type") != expected_type:
        raise TokenError(f"Expected a {expected_type} token")
    if not payload.get("sub"):
        raise TokenError("Token is missing a subject")
    return payload
