"""Audit trail writer.

`CLAUDE.md`: every write action is logged to `audit_log`. Call `record()` from
inside the same transaction as the action it describes, so a rolled-back action
does not leave a phantom audit entry.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    # nginx sets X-Forwarded-For; take the left-most entry (the original client).
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip() or None
    return request.client.host if request.client else None


async def record(
    db: AsyncSession,
    *,
    action: str,
    user: User | None = None,
    username: str | None = None,
    resource_type: str | None = None,
    resource_id: str | uuid.UUID | None = None,
    outcome: str = "success",
    detail: dict[str, Any] | None = None,
    error: str | None = None,
    request: Request | None = None,
) -> AuditLog:
    """Add an audit row to `db`. The caller owns the commit."""
    entry = AuditLog(
        user_id=user.id if user else None,
        username=username or (user.username if user else None),
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        outcome=outcome,
        detail=detail,
        error=error,
        ip_address=_client_ip(request),
        user_agent=(request.headers.get("user-agent") if request else None),
    )
    db.add(entry)
    return entry
