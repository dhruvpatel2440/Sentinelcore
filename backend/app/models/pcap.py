from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PcapStatus(str, enum.Enum):
    UPLOADED = "uploaded"
    PARSING = "parsing"
    PARSED = "parsed"
    FAILED = "failed"


class ArtifactType(str, enum.Enum):
    DNS_QUERY = "dns_query"
    HTTP_REQUEST = "http_request"
    TLS_SNI = "tls_sni"
    CREDENTIAL = "credential"
    FILE_TRANSFER = "file_transfer"
    USER_AGENT = "user_agent"


class PcapFile(Base):
    """The canonical `pcap_files` table. `stored_path` is always
    `PCAP_STORAGE_PATH/<uuid>.pcap` — the client-supplied filename is kept
    only as a display string, never used in a path."""

    __tablename__ = "pcap_files"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[PcapStatus] = mapped_column(
        Enum(PcapStatus, name="pcap_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=PcapStatus.UPLOADED,
        index=True,
    )
    packet_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_packet_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_packet_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    link_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    capture_interface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    flow_truncated: Mapped[bool] = mapped_column(nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    parsed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )


class PcapFlow(Base):
    """One conversation (`tshark -z conv,tcp/udp`) within a capture."""

    __tablename__ = "pcap_flows"
    __table_args__ = (
        Index("ix_pcap_flows_pcap_bytes", "pcap_id", "byte_count"),
        Index("ix_pcap_flows_pcap_start", "pcap_id", "start_ts"),
        Index("ix_pcap_flows_src_ip", "src_ip"),
        Index("ix_pcap_flows_dst_ip", "dst_ip"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    pcap_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("pcap_files.id", ondelete="CASCADE"), nullable=False
    )
    stream_id: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[str] = mapped_column(INET, nullable=False)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    byte_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    start_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    app_protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    src_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    dst_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )


class PcapArtifact(Base):
    """A searchable indicator extracted from a capture — "which captures
    mention this domain" is the question this table answers."""

    __tablename__ = "pcap_artifacts"
    __table_args__ = (Index("ix_pcap_artifacts_pcap_type", "pcap_id", "artifact_type"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    pcap_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("pcap_files.id", ondelete="CASCADE"), nullable=False
    )
    flow_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("pcap_flows.id", ondelete="SET NULL"), nullable=True
    )
    artifact_type: Mapped[ArtifactType] = mapped_column(
        Enum(ArtifactType, name="pcap_artifact_type", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    packet_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
