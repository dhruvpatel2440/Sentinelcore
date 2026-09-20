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
from app.models.user import User, UserRole
from app.schemas.auth import UserOut
from app.schemas.user import PasswordChange, PasswordReset, UserCreate, UserUpdate
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])


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
