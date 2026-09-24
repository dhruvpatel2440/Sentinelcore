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
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class EventType(str, enum.Enum):
    ALERT = "alert"
    FLOW = "flow"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"


class Severity(str, enum.Enum):
    """The platform's single severity scale.

    Suricata emits priority 1 (highest) to 4. The mapping lives in
    `app/pipeline/normalize.py::SEVERITY_BY_SURICATA_PRIORITY` and nowhere
    else — M2's Badge colours, M7's scoring and M9's reports all depend on
    these exact names agreeing.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Event(Base):
    """A normalized detection or flow record from the sensor.

    Range-partitioned by `ts` (monthly) from the very first migration.
    Retrofitting partitioning onto a 50M-row table is a migration nobody wants
    to write, and retention becomes an instant DROP rather than a bulk DELETE.

    Because the table is partitioned, the primary key must include the
    partition key: PostgreSQL requires every unique constraint to contain it.
    Hence PK (id, ts) and the dedup uniqueness being (dedup_key, ts).
    """

    __tablename__ = "events"
    __table_args__ = (
        PrimaryKeyConstraint("id", "ts", name="pk_events"),
        Index("ix_events_ts", "ts"),
        Index("ix_events_src_ip_ts", "src_ip", "ts"),
        Index("ix_events_dst_ip_ts", "dst_ip", "ts"),
        Index("ix_events_signature_id_ts", "signature_id", "ts"),
        Index("ix_events_severity_ts", "severity", "ts"),
        Index("ix_events_flow_id", "flow_id"),
        Index("ix_events_ioc_match_ts", "ioc_match", "ts"),
        {"postgresql_partition_by": "RANGE (ts)"},
    )

    id: Mapped[int] = mapped_column(BigInteger, autoincrement=True, nullable=False)

    # Event time from EVE, never insert time — they differ under backlog.
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    event_type: Mapped[EventType] = mapped_column(
        Enum(EventType, name="event_type", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )

    src_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    proto: Mapped[str | None] = mapped_column(String(8), nullable=True)

    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    signature_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    rev: Mapped[int | None] = mapped_column(Integer, nullable=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)

    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="event_severity", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=Severity.INFO,
    )

    # ON DELETE SET NULL: deleting an asset must not erase its event history.
    src_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    dst_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )

    # Suricata's flow id ties an alert to its flow and to http/dns records.
    flow_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # SHA-256 over the identity tuple; provides idempotency for at-least-once
    # delivery from the Redis stream.
    dedup_key: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)

    # The full original record. During an investigation, the field you did not
    # model is always the one you need.
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    # M12 — stamped by the matcher during M5 enrichment. `ioc_severity` is the
    # highest IOC severity seen; `severity` above is escalated to at least
    # that value but never downgraded.
    ioc_match: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ioc_severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, name="event_severity", values_callable=lambda e: [m.value for m in e], create_type=False),
        nullable=True,
    )
