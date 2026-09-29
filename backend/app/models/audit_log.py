from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CHAR, CheckConstraint, DateTime, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLog(Base):
    """Append-only record of every write action. Never updated, never deleted
    — enforced in the database by a trigger, not just application code (see
    migration `0012_audit_immutable`).

    `user_id` is nullable and carries no foreign key: it used to reference
    `users.id` with `ON DELETE SET NULL`, but that is itself an UPDATE on
    this table, which the append-only trigger now rejects. `username` is
    denormalised onto the row so the trail stays readable after the user is
    gone.

    `prev_hash`/`row_hash` form a SHA-256 hash chain (see
    `app/services/audit.py::record`) so that tampering which bypasses the
    trigger (e.g. a superuser disabling triggers) is still detectable via
    `GET /api/audit/verify`.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    # Denormalised so the trail stays readable after the user row is gone.
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # "success" | "failure" | "denied"
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="success")

    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    # SHA-256 hash chain, filled in by services/audit.py::record(). NULL on
    # rows written before migration 0012 — the verifier starts there.
    prev_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    row_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)


class AuditChainHead(Base):
    """Singleton row holding the tip of the audit_log hash chain.

    `record()` locks this row (`SELECT ... FOR UPDATE`) inside the same
    transaction as the audit insert, so concurrent writers serialise on one
    small row instead of scanning audit_log for its last entry.
    """

    __tablename__ = "audit_chain_head"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    last_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)

    __table_args__ = (CheckConstraint("id = 1", name="ck_audit_chain_head_singleton"),)
