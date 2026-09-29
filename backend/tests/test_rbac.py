"""M1 unit tests for the require_role authorization chokepoint."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.deps import require_role
from app.models.user import User, UserRole


def _user(role: UserRole) -> User:
    return User(username=f"{role.value}-user", password_hash="x", role=role, is_active=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN])
async def test_matching_role_is_allowed(role):
    dep = require_role(role.value)
    assert await dep(user=_user(role)) is not None


@pytest.mark.asyncio
async def test_viewer_denied_admin_only_route():
    dep = require_role("admin")
    with pytest.raises(HTTPException) as exc:
        await dep(user=_user(UserRole.VIEWER))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_analyst_denied_admin_only_route():
    dep = require_role("admin")
    with pytest.raises(HTTPException) as exc:
        await dep(user=_user(UserRole.ANALYST))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_admin_is_not_implicitly_granted_analyst_routes():
    """Admin must be listed explicitly — no silent privilege inheritance."""
    dep = require_role("analyst")
    with pytest.raises(HTTPException) as exc:
        await dep(user=_user(UserRole.ADMIN))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_multi_role_dependency_allows_each_listed_role():
    dep = require_role("analyst", "admin")
    assert await dep(user=_user(UserRole.ANALYST)) is not None
    assert await dep(user=_user(UserRole.ADMIN)) is not None
    with pytest.raises(HTTPException):
        await dep(user=_user(UserRole.VIEWER))


def test_require_role_rejects_unknown_role_name_at_import_time():
    with pytest.raises(ValueError):
        require_role("superuser")


def test_require_role_needs_at_least_one_role():
    with pytest.raises(ValueError):
        require_role()
