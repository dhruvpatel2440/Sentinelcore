"""User management. All mutations are admin-only and audited."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.core.security import hash_password, verify_password
from app.db.session import get_db
from app.email import recipients as email_recipients
from app.email.render import app_link
from app.email.service import enqueue, resolve_recipients_from_users
from app.email.types import EmailType
from app.models.user import User, UserRole
from app.schemas.auth import UserOut
from app.schemas.user import PasswordChange, PasswordReset, UserCreate, UserUpdate
from app.services import audit, password_reset

router = APIRouter(prefix="/users", tags=["users"])


async def _notify_account_changed(db: AsyncSession, user: User, *, what_changed: str, changed_by: str, notify_admins: bool = False) -> None:
    targets: list[User] = [user]
    if notify_admins:
        targets = targets + await email_recipients.admins(db)
    recips = await resolve_recipients_from_users(db, targets)
    if not recips:
        return
    await enqueue(
        db,
        email_type=EmailType.E20_ACCOUNT_CHANGED,
        recipients=recips,
        heading=f"SentinelCore account change: {user.username}",
        render_context={
            "what_changed": what_changed,
            "changed_by": changed_by,
            "changed_at": datetime.now(timezone.utc).isoformat(),
        },
        dedupe_key=None,
        related_type="user", related_id=str(user.id),
        button_label="Open SentinelCore", button_url=app_link("/login"),
        why_you_got_this="this is a security notice for your account and cannot be disabled.",
    )
    await db.commit()


async def _count_active_admins(db: AsyncSession, *, excluding: uuid.UUID | None = None) -> int:
    stmt = select(func.count()).select_from(User).where(
        User.role == UserRole.ADMIN, User.is_active.is_(True)
    )
    if excluding is not None:
        stmt = stmt.where(User.id != excluding)
    return int((await db.execute(stmt)).scalar_one())


@router.get("", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> list[UserOut]:
    result = await db.execute(select(User).order_by(User.username))
    return [UserOut.model_validate(u) for u in result.scalars().all()]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> UserOut:
    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        role=payload.role,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await audit.record(
        db,
        action="user.create",
        user=actor,
        resource_type="user",
        resource_id=payload.username,
        detail={"role": payload.role.value},
        request=request,
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with that username or email already exists",
        ) from exc

    await db.refresh(user)

    # Admin sets an initial password (existing contract, unchanged), but the
    # user still gets a "set your own password" link — CLAUDE.md-adjacent:
    # never put the admin-chosen password itself in the email.
    if user.email:
        raw_token = await password_reset.issue_token(db, user, requested_ip=None)
        await db.commit()
        await password_reset.send_password_email(db, user, raw_token, purpose="set_password")

    return UserOut.model_validate(user)


@router.post("/me/password", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def change_own_password(
    payload: PasswordChange,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
) -> None:
    """Declared before the `/{user_id}` routes so "me" is not parsed as a UUID."""
    if not verify_password(payload.current_password, actor.password_hash):
        await audit.record(
            db,
            action="user.password_change",
            user=actor,
            outcome="failure",
            error="bad_current_password",
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect"
        )

    actor.password_hash = hash_password(payload.new_password)
    actor.tokens_valid_from = datetime.now(timezone.utc)

    await audit.record(
        db,
        action="user.password_change",
        user=actor,
        resource_type="user",
        resource_id=str(actor.id),
        request=request,
    )
    await db.commit()
    await _notify_account_changed(db, actor, what_changed="Your password was changed.", changed_by=actor.username)


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> UserOut:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserOut.model_validate(user)


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> UserOut:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    changes = payload.model_dump(exclude_unset=True)
    role_or_activation_changed = "role" in changes or "is_active" in changes
    change_summary = ", ".join(
        f"{k} -> {(v.value if isinstance(v, UserRole) else v)}" for k, v in changes.items() if k in ("role", "is_active")
    )
    losing_admin = (
        changes.get("role") not in (None, UserRole.ADMIN) and user.role == UserRole.ADMIN
    ) or changes.get("is_active") is False

    # Never let the last admin demote or disable themselves out of the system.
    if losing_admin and user.role == UserRole.ADMIN:
        if await _count_active_admins(db, excluding=user.id) == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot remove the last active admin",
            )

    for field, value in changes.items():
        setattr(user, field, value)

    # A role or activation change must not be honoured by tokens already issued.
    if "role" in changes or "is_active" in changes:
        user.tokens_valid_from = datetime.now(timezone.utc)

    await audit.record(
        db,
        action="user.update",
        user=actor,
        resource_type="user",
        resource_id=str(user.id),
        detail={k: (v.value if isinstance(v, UserRole) else v) for k, v in changes.items()},
        request=request,
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email already in use"
        ) from exc

    await db.refresh(user)

    if role_or_activation_changed:
        await _notify_account_changed(
            db, user, what_changed=f"Your account was changed: {change_summary}.",
            changed_by=actor.username, notify_admins=True,
        )

    return UserOut.model_validate(user)


@router.post("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def reset_password(
    user_id: uuid.UUID,
    payload: PasswordReset,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> None:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.password_hash = hash_password(payload.new_password)
    user.tokens_valid_from = datetime.now(timezone.utc)

    await audit.record(
        db,
        action="user.password_reset",
        user=actor,
        resource_type="user",
        resource_id=str(user.id),
        request=request,
    )
    await db.commit()
    await _notify_account_changed(
        db, user, what_changed="Your password was reset by an administrator.", changed_by=actor.username,
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_user(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> None:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.id == actor.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="You cannot delete your own account"
        )
    if user.role == UserRole.ADMIN and await _count_active_admins(db, excluding=user.id) == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Cannot remove the last active admin"
        )

    username = user.username
    await db.delete(user)
    await audit.record(
        db,
        action="user.delete",
        user=actor,
        resource_type="user",
        resource_id=str(user_id),
        detail={"username": username},
        request=request,
    )
    await db.commit()
