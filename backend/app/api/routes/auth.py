"""Authentication: login, silent refresh, logout, current user.

Token model (per CLAUDE.md):
  - access token  — 15 min, returned in the JSON body, held in browser memory
  - refresh token —  7 days, httpOnly cookie scoped to /api/auth, JS never reads it

Revocation uses `users.tokens_valid_from`: bumping it invalidates every token
issued before that instant. This makes logout global across a user's devices,
which is the behaviour we want in an IR platform — "sign me out" should mean
everywhere, and it costs no extra lookup since the user row is already loaded.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse, UserOut
from app.services import audit, login_throttle

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "sentinelcore_refresh"
REFRESH_COOKIE_PATH = "/api/auth"

# Verifying against a throwaway hash keeps the "no such user" path the same
# cost as the "wrong password" path, so response time does not enumerate users.
_DUMMY_HASH = hash_password("timing-equalisation-placeholder")


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=token,
        max_age=settings.refresh_token_expire_days * 24 * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path=REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REFRESH_COOKIE,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
    )


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip() or None
    return request.client.host if request.client else None


def _token_response(user: User) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(user.id, user.role.value),
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserOut.model_validate(user),
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    ip = _client_ip(request)

    if await login_throttle.is_locked_out(payload.username, ip):
        await audit.record(
            db,
            action="auth.login",
            username=payload.username,
            outcome="denied",
            error="rate_limited",
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again shortly.",
        )

    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()

    if user is not None:
        password_ok = verify_password(payload.password, user.password_hash)
    else:
        # Burn an equivalent Argon2 verification and discard it, so an unknown
        # username takes the same wall-clock time as a wrong password.
        verify_password(payload.password, _DUMMY_HASH)
        password_ok = False

    if user is None or not password_ok or not user.is_active:
        await login_throttle.record_failure(payload.username, ip)
        await audit.record(
            db,
            action="auth.login",
            user=user if user is not None and user.is_active else None,
            username=payload.username,
            outcome="failure",
            error="inactive_account" if user is not None and not user.is_active else "bad_credentials",
            request=request,
        )
        await db.commit()
        # One message for every failure mode — never reveal which part was wrong.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Opportunistically upgrade hashes when Argon2 parameters have moved on.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    await login_throttle.clear(payload.username, ip)
    user.last_login_at = datetime.now(timezone.utc)

    session_id = str(uuid.uuid4())
    _set_refresh_cookie(response, create_refresh_token(user.id, session_id))

    await audit.record(
        db,
        action="auth.login",
        user=user,
        outcome="success",
        detail={"session_id": session_id},
        request=request,
    )
    await db.commit()
    await db.refresh(user)

    return _token_response(user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Exchange the refresh cookie for a new access token.

    The cookie is re-issued on every call, so an active session slides forward
    and an idle one expires 7 days after its last use.
    """
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token"
        )

    try:
        payload = decode_token(token, "refresh")
    except TokenError as exc:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc

    try:
        user_id = uuid.UUID(payload["sub"])
    except (ValueError, KeyError, TypeError) as exc:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        ) from exc

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Account unavailable"
        )

    issued_at = datetime.fromtimestamp(payload.get("iat", 0), tz=timezone.utc)
    if issued_at < user.tokens_valid_from:
        _clear_refresh_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has been revoked"
        )

    session_id = payload.get("sid") or str(uuid.uuid4())
    _set_refresh_cookie(response, create_refresh_token(user.id, session_id))

    return _token_response(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Clear the cookie and invalidate outstanding tokens for this user.

    Deliberately tolerant: logging out with an already-invalid token still
    clears the cookie and returns 204, so the client can always reach a
    signed-out state.
    """
    token = request.cookies.get(REFRESH_COOKIE)
    _clear_refresh_cookie(response)

    if token:
        try:
            payload = decode_token(token, "refresh")
            user = await db.get(User, uuid.UUID(payload["sub"]))
            if user is not None:
                user.tokens_valid_from = datetime.now(timezone.utc)
                await audit.record(
                    db,
                    action="auth.logout",
                    user=user,
                    detail={"session_id": payload.get("sid")},
                    request=request,
                )
                await db.commit()
        except (TokenError, ValueError, KeyError, TypeError):
            pass

    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)
