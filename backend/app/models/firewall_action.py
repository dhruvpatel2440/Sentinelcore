from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class FirewallDirection(str, enum.Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"


class FirewallActionStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    FAILED = "failed"


# 1 minute .. 24 hours. Mirrors the helper-side and pydantic-side bounds — a
# layer that can be bypassed by a direct insert is not a control.
TTL_MIN_SECONDS = 60
TTL_MAX_SECONDS = 86400

ACTIVE_STATUSES = frozenset({FirewallActionStatus.PENDING, FirewallActionStatus.ACTIVE})


class FirewallAction(Base):
    """The canonical `firewall_actions` table. `id` doubles as the iptables
    comment tag (`sentinelcore:<id>`), which is how a rule is found for
    revocation without relying on rule numbers.

    No block is ever permanent: `ttl_seconds` is enforced here by a CHECK
    constraint in addition to the pydantic schema, because a control that can
    be bypassed by a direct insert is not a control."""

    __tablename__ = "firewall_actions"
    __table_args__ = (
        CheckConstraint(f"ttl_seconds BETWEEN {TTL_MIN_SECONDS} AND {TTL_MAX_SECONDS}", name="ck_firewall_actions_ttl_bounds"),
        CheckConstraint("ttl_seconds > 0", name="ck_firewall_actions_ttl_positive"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    target: Mapped[str] = mapped_column(CIDR, nullable=False)
    direction: Mapped[FirewallDirection] = mapped_column(
        Enum(FirewallDirection, name="firewall_direction", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    protocol: Mapped[str | None] = mapped_column(String(4), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )

    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    status: Mapped[FirewallActionStatus] = mapped_column(
        Enum(FirewallActionStatus, name="firewall_action_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=FirewallActionStatus.PENDING,
    )

    created_by: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
