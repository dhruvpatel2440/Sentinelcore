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
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import CIDR, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class IocType(str, enum.Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


class IocSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SourceFormat(str, enum.Enum):
    CSV = "csv"
    JSON = "json"
    TXT = "txt"
    MISP = "misp"
    STIX = "stix"


class IocSource(Base):
    """A feed configuration. `parser_config` holds the column mapping needed
    to turn one row of the feed's raw format into a normalized indicator."""

    __tablename__ = "ioc_sources"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[SourceFormat] = mapped_column(
        Enum(SourceFormat, name="ioc_source_format", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    parser_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    default_confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    default_severity: Mapped[IocSeverity] = mapped_column(
        Enum(IocSeverity, name="ioc_severity", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=IocSeverity.MEDIUM,
    )
    refresh_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    ttl_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    last_fetch_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    indicator_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class Ioc(Base):
    """The canonical `ioc` table. Unique on (indicator, ioc_type, source_id) —
    the same indicator reported by two sources is two rows on purpose:
    agreement across sources is itself a confidence signal."""

    __tablename__ = "ioc"
    __table_args__ = (
        UniqueConstraint("indicator", "ioc_type", "source_id", name="uq_ioc_indicator_type_source"),
        Index("ix_ioc_indicator", "indicator"),
        Index("ix_ioc_type_active", "ioc_type", "is_active"),
        Index("ix_ioc_expires_at", "expires_at"),
        Index("ix_ioc_cidr_shadow", "cidr_shadow", postgresql_using="gist"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    indicator: Mapped[str] = mapped_column(Text, nullable=False)
    ioc_type: Mapped[IocType] = mapped_column(
        Enum(IocType, name="ioc_type", values_callable=lambda e: [m.value for m in e]), nullable=False
    )
    # Shadow column for CIDR indicators only, so containment can use a GiST
    # index instead of parsing `indicator` on every lookup.
    cidr_shadow: Mapped[str | None] = mapped_column(CIDR, nullable=True)

    source_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ioc_sources.id", ondelete="SET NULL"), nullable=True
    )
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    severity: Mapped[IocSeverity] = mapped_column(
        Enum(IocSeverity, name="ioc_severity", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=IocSeverity.MEDIUM,
    )
    threat_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    added_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class IocMatch(Base):
    """The evidence trail: why an event or artifact was flagged. Always
    answerable, because `ioc_matches` is written on every hit."""

    __tablename__ = "ioc_matches"
    __table_args__ = (
        Index("ix_ioc_matches_ioc_ts", "ioc_id", "ts"),
        Index("ix_ioc_matches_event_id", "event_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("ioc.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    pcap_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("pcap_artifacts.id", ondelete="CASCADE"), nullable=True
    )
    matched_value: Mapped[str] = mapped_column(Text, nullable=False)
    matched_field: Mapped[str] = mapped_column(String(32), nullable=False)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
