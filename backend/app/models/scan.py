from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanType(str, enum.Enum):
    NMAP = "nmap"
    ARP = "arp"
    COMBINED = "combined"


class Scan(Base):
    """A discovery run. Extends the canonical table list in CLAUDE.md (M3)."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )

    scan_type: Mapped[ScanType] = mapped_column(
        Enum(ScanType, name="scan_type", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=ScanType.COMBINED,
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=ScanStatus.QUEUED,
        index=True,
    )

    targets: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    ports: Mapped[str | None] = mapped_column(String(512), nullable=True)
    mode: Mapped[str | None] = mapped_column(String(32), nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    hosts_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ports_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None or self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()
