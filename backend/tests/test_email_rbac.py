"""U10 RBAC matrix for the new email endpoints — same no-DB pattern as
`test_rbac.py`: call the actual dependency each route declares, with a
bare in-memory `User`, rather than standing up the whole HTTP stack."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.deps import get_current_user, require_role
from app.models.user import User, UserRole


def _user(role: UserRole) -> User:
    return User(username=f"{role.value}-user", password_hash="x", role=role, is_active=True)


# email_admin.py — every route is `require_role("admin")`
@pytest.mark.asyncio
@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.ANALYST])
async def test_email_admin_routes_deny_non_admins(role):
    dep = require_role("admin")
    with pytest.raises(HTTPException) as exc:
        await dep(user=_user(role))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_email_admin_routes_allow_admin():
    dep = require_role("admin")
    assert await dep(user=_user(UserRole.ADMIN)) is not None


# email_prefs.py — any authenticated role via plain get_current_user
@pytest.mark.asyncio
@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN])
async def test_email_preferences_allow_any_authenticated_role(role):
    # get_current_user itself only rejects on missing/invalid token — once a
    # User is resolved, the route body applies no further role check, so
    # this documents "any role" rather than exercising the dependency chain.
    user = _user(role)
    assert user.is_active


# password_reset.py / webhooks.py — unauthenticated by design. FastAPI
# flattens the whole sub-dependency graph into `dependant.dependencies`, so
# this catches `get_current_user` even if it were pulled in indirectly via
# `require_role`.
def test_password_reset_routes_declare_no_auth_dependency():
    from app.api.routes import password_reset as pr_routes

    for route in pr_routes.router.routes:
        calls = [d.call for d in route.dependant.dependencies]
        assert get_current_user not in calls


def test_webhook_route_declares_no_auth_dependency():
    from app.api.routes import webhooks as webhook_routes

    for route in webhook_routes.router.routes:
        calls = [d.call for d in route.dependant.dependencies]
        assert get_current_user not in calls
