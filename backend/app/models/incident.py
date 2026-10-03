from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.event import Severity


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    TRIAGE = "triage"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


TERMINAL_STATUSES = frozenset({IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE})


class HistoryAction(str, enum.Enum):
    CREATED = "created"
    STATUS_CHANGED = "status_changed"
    ASSIGNED = "assigned"
    SEVERITY_CHANGED = "severity_changed"
    COMMENTED = "commented"
    EVENTS_LINKED = "events_linked"
    EVENTS_UNLINKED = "events_unlinked"
    REOPENED = "reopened"
    CLOSED = "closed"


class Incident(Base):
    """The canonical `incidents` table. `number` is what an analyst says out
    loud during a call — a UUID is not."""

    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_queue", "status", "severity", "opened_at"),
        Index("ix_incidents_assignee", "assigned_to", "status"),
        Index("ix_incidents_src_ip", "src_ip"),
        Index("ix_incidents_opened_at", "opened_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    number: Mapped[int] = mapped_column(
        BigInteger, nullable=False, unique=True, server_default=text("nextval('incident_number_seq')")
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, name="incident_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=IncidentStatus.NEW,
    )
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="event_severity", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    src_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(INET, nullable=True)

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("correlation_rules.id", ondelete="SET NULL"), nullable=True
    )
    candidate_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incident_candidates.id", ondelete="SET NULL"), nullable=True, unique=True
    )

    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_event_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Optimistic concurrency: PATCH/status/assign accept `If-Match`/`version`
    # and bump this on every mutation, so two analysts on the same incident
    # never silently overwrite each other.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class IncidentEvent(Base):
    """Join table — events are linked, never copied. No FK to `events.id`:
    the partitioned table's primary key is (id, ts), so `id` alone cannot
    carry a foreign key; the IDENTITY sequence still makes it a valid
    application-level reference."""

    __tablename__ = "incident_events"
    __table_args__ = (PrimaryKeyConstraint("incident_id", "event_id", name="pk_incident_events"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    linked_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class IncidentHistory(Base):
    """Append-only. The database trigger `trg_incident_history_immutable`
    (added in the M8 migration) rejects UPDATE/DELETE outright — this is not
    enforced by convention alone."""

    __tablename__ = "incident_history"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[HistoryAction] = mapped_column(
        Enum(HistoryAction, name="incident_history_action", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    from_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    to_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
