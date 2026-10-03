from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, func, text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class LoginEvent(Base):
    """Backs E21 (suspicious login). `user_agent_hash` rather than the raw
    UA string — enough to detect "never seen this device" without storing
    a browser fingerprint verbatim. Pruned by the existing retention job."""

    __tablename__ = "login_events"
    __table_args__ = (Index("ix_login_events_user_created", "user_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
