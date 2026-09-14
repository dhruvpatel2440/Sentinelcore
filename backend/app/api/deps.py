"""Shared FastAPI dependencies: DB session, current user, role enforcement.

`require_role` is the single authorization chokepoint for the whole platform.
M3 (scans), M4 (sensor control) and M10 (firewall) all gate on it.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TokenError, decode_token
from app.db.session import get_db
from app.models.user import User, UserRole

# auto_error=False so a missing header yields our own 401 shape, not FastAPI's.
_bearer = HTTPBearer(auto_error=False)

_CREDENTIALS_EXC = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise _CREDENTIALS_EXC

    try:
        payload = decode_token(credentials.credentials, "access")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    try:
        user_id = uuid.UUID(payload["sub"])
    except (ValueError, KeyError, TypeError) as exc:
        raise _CREDENTIALS_EXC from exc

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise _CREDENTIALS_EXC

    # Tokens minted before the user's cutoff (logout, password change, role
    # change) are dead even if they have not expired yet.
    issued_at = datetime.fromtimestamp(payload.get("iat", 0), tz=timezone.utc)
    if issued_at < user.tokens_valid_from:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


CurrentUser = Depends(get_current_user)


def require_role(*roles: str | UserRole) -> Callable[..., Awaitable[User]]:
    """Dependency factory enforcing that the caller holds one of `roles`.

    Admin is *not* implicitly granted — pass it explicitly when it should be
    allowed. Being explicit makes every call site auditable by reading it.
    """
    allowed = {UserRole(r) if isinstance(r, str) else r for r in roles}
    if not allowed:
        raise ValueError("require_role() needs at least one role")

    async def _dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this action",
            )
        return user

    return _dependency


def get_request(request: Request) -> Request:
    """Explicit dependency so audit calls can take the request uniformly."""
    return request
