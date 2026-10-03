"""Common recipient-set queries shared by every hook that calls `enqueue()`."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, UserRole


async def admins(db: AsyncSession) -> list[User]:
    return list((await db.execute(select(User).where(User.role == UserRole.ADMIN, User.is_active.is_(True)))).scalars())


async def analysts_and_admins(db: AsyncSession) -> list[User]:
    return list(
        (
            await db.execute(
                select(User).where(User.role.in_([UserRole.ANALYST, UserRole.ADMIN]), User.is_active.is_(True))
            )
        ).scalars()
    )


async def by_id(db: AsyncSession, user_id: uuid.UUID | None) -> list[User]:
    if user_id is None:
        return []
    user = await db.get(User, user_id)
    return [user] if user is not None and user.is_active else []
