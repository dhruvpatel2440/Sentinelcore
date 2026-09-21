from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.event import Severity


class RuleType(str, enum.Enum):
    THRESHOLD = "threshold"
    SEQUENCE = "sequence"
    RARE = "rare"
    BEACON = "beacon"


class CandidateStatus(str, enum.Enum):
    NEW = "new"
    PROMOTED = "promoted"
    SUPPRESSED = "suppressed"


class CorrelationRule(Base):
    """A stored, admin-editable correlation rule.

    Rules are data, never a Python file to redeploy — tuning a threshold is a
    PATCH, not a deploy.
    """

    __tablename__ = "correlation_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    # Required — this becomes the incident narrative M8 seeds `description` from.
    description: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    rule_type: Mapped[RuleType] = mapped_column(
        Enum(RuleType, name="correlation_rule_type", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )

    match: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    group_by: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="event_severity", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    dedup_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class IncidentCandidate(Base):
    """A finding produced by the correlation engine. M8 promotes it into an
    incident (or merges it into an existing one) — this table stays owned by
    M7's engine, `incident_id` is the only field M8 writes back."""

    __tablename__ = "incident_candidates"
    __table_args__ = (
        UniqueConstraint("rule_id", "group_key", "first_event_ts", name="uq_candidate_rule_group_first"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("correlation_rules.id", ondelete="CASCADE"), nullable=False
    )
    group_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)

    first_event_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_event_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)

    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="event_severity", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[str] = mapped_column(Text, nullable=False)

    # Matched event ids, capped — first and last 100 plus the true count, not
    # every id a port scan produced.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    status: Mapped[CandidateStatus] = mapped_column(
        Enum(CandidateStatus, name="candidate_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=CandidateStatus.NEW,
    )
    # No FK to `incidents` yet — that table does not exist until M8. M8's
    # migration adds the constraint once it does.
    incident_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True, unique=True)

    suppressed_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    suppressed_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )


class RuleRun(Base):
    """One engine tick's outcome for one rule — what lets a rule that 'is not
    firing' get debugged instead of just distrusted."""

    __tablename__ = "rule_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("correlation_rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    events_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    candidates_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
