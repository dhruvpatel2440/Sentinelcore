from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class OverrideAction(str, enum.Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"
    THRESHOLD = "threshold"


class SensorAction(str, enum.Enum):
    START = "start"
    STOP = "stop"
    RELOAD = "reload"
    RULES_UPDATE = "rules_update"
    CONFIG_TEST = "config_test"


class RuleSource(Base):
    """An upstream rule feed. Emerging Threats Open is the sensible default."""

    __tablename__ = "rule_sources"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    last_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class RuleOverride(Base):
    """Tuning for a noisy signature.

    `reason` is NOT NULL on purpose: six months later nobody remembers why a
    signature was silenced, and an unexplained silenced rule is a blind spot.
    """

    __tablename__ = "rule_overrides"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    sid: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True, index=True)
    action: Mapped[OverrideAction] = mapped_column(
        Enum(OverrideAction, name="override_action", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    params: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class SensorEvent(Base):
    """Sensor-specific operational history. `audit_log` still records the
    action too — this table is the operator-facing timeline."""

    __tablename__ = "sensor_events"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    action: Mapped[SensorAction] = mapped_column(
        Enum(SensorAction, name="sensor_action", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
