"""Read-only access to the append-only audit trail."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.db.session import get_db
from app.models.user import User
from app.services import audit

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/verify")
async def verify_audit_chain(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
    batch_size: int = Query(1000, ge=100, le=10000),
) -> dict:
    """Walk the audit_log hash chain and report the first broken link, if any."""
    return await audit.verify_chain(db, batch_size=batch_size)
