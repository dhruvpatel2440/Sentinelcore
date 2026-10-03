from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.event import Severity


class EmailType(str, enum.Enum):
    """Lives here (not `app.email.types`) to avoid a circular import:
    `app.email.types` needs `app.models.event.Severity`, and importing any
    `app.models.*` submodule runs `app.models/__init__.py`, which imports
    this file. `app.email.types` re-exports this enum for everyone else."""

    E01_NEW_INCIDENT = "E01"
    E02_INCIDENT_ESCALATED = "E02"
    E03_INCIDENT_ASSIGNED = "E03"
    E04_SLA_REMINDER = "E04"
    E05_INCIDENT_RESOLVED = "E05"
    E06_THREAT_INTEL_MATCH = "E06"
    E07_BLOCK_APPLIED = "E07"
    E08_BLOCK_EXPIRING = "E08"
    E09_BLOCK_EXPIRED = "E09"
    E10_BLOCK_REFUSED = "E10"
    E11_REPORT_DELIVERED = "E11"
    E12_REPORT_READY = "E12"
    E13_REPORT_FAILED = "E13"
    E14_DIGEST = "E14"
    E15_SENSOR_HEALTH = "E15"
    E16_PIPELINE_BACKLOG = "E16"
    E17_FEED_FAILING = "E17"
    E18_FIREWALL_DRIFT = "E18"
    E19_ACCOUNT_PASSWORD = "E19"
    E20_ACCOUNT_CHANGED = "E20"
    E21_SUSPICIOUS_LOGIN = "E21"


class EmailOutboxStatus(str, enum.Enum):
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    SUPPRESSED = "suppressed"
    DRY_RUN = "dry_run"


class EmailDeliveryMode(str, enum.Enum):
    INSTANT = "instant"
    DIGEST = "digest"


class EmailDigestFrequency(str, enum.Enum):
    DAILY = "daily"
    WEEKLY = "weekly"


class EmailSuppressionReason(str, enum.Enum):
    HARD_BOUNCE = "hard_bounce"
    BLOCKED = "blocked"
    SPAM = "spam"
    UNSUBSCRIBED = "unsubscribed"
    MANUAL = "manual"


class EmailOutbox(Base):
    """Single write path for every outbound email (U10). The API never calls
    Brevo inline — it inserts a row here and the worker's drain loop sends
    it. `dedupe_key` carries a unique partial index so two concurrent
    `enqueue()` calls for "the same alert, the same recipient" can only ever
    produce one row."""

    __tablename__ = "email_outbox"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    email_type: Mapped[EmailType] = mapped_column(
        Enum(EmailType, name="email_type", values_callable=lambda e: [m.value for m in e]), nullable=False
    )
    recipient_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    recipient_email: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    html_body: Mapped[str] = mapped_column(Text, nullable=False)
    text_body: Mapped[str] = mapped_column(Text, nullable=False)
    dedupe_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[EmailOutboxStatus] = mapped_column(
        Enum(EmailOutboxStatus, name="email_outbox_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=EmailOutboxStatus.QUEUED,
    )
    digest: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    provider_message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    related_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    related_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EmailPreferences(Base):
    """Per-user notification preferences. `types_disabled` is ignored for
    `app.email.types.LOCKED_TYPES` — enforced in `service.enqueue()`, not
    here, so this row stays a plain record of intent."""

    __tablename__ = "email_preferences"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    min_severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="event_severity", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=Severity.HIGH,
    )
    delivery_mode: Mapped[EmailDeliveryMode] = mapped_column(
        Enum(EmailDeliveryMode, name="email_delivery_mode", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=EmailDeliveryMode.INSTANT,
    )
    types_disabled: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    digest_frequency: Mapped[EmailDigestFrequency] = mapped_column(
        Enum(EmailDigestFrequency, name="email_digest_frequency", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=EmailDigestFrequency.DAILY,
    )
    digest_hour_utc: Mapped[int] = mapped_column(Integer, nullable=False, default=13)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EmailSettings(Base):
    """Single-row (id=1), admin-controlled, global switchboard."""

    __tablename__ = "email_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    types_enabled: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    global_pause: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EmailSuppression(Base):
    """An address that must never be sent to again, until an admin removes
    the row."""

    __tablename__ = "email_suppressions"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    reason: Mapped[EmailSuppressionReason] = mapped_column(
        Enum(EmailSuppressionReason, name="email_suppression_reason", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
