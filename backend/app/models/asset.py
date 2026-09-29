from __future__ import annotations

import enum
import uuid
from datetime import datetime

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
from sqlalchemy.dialects.postgresql import INET, MACADDR
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Protocol(str, enum.Enum):
    TCP = "tcp"
    UDP = "udp"


class PortState(str, enum.Enum):
    OPEN = "open"
    FILTERED = "filtered"
    CLOSED = "closed"


class Asset(Base):
    """A host observed on the monitored network.

    Assets are never deleted by discovery — a host that stops answering is
    flagged inactive. In an IR tool the history of what *was* on the network
    is often the evidence that matters.
    """

    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    ip_address: Mapped[str] = mapped_column(INET, nullable=False, unique=True, index=True)
    mac_address: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_guess: Mapped[str | None] = mapped_column(String(128), nullable=True)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    # Analyst-editable. Discovery never overwrites these.
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    hostname_override: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # How many consecutive scans have missed this host — drives deactivation.
    missed_scans: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    ports: Mapped[list[AssetPort]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def display_hostname(self) -> str | None:
        return self.hostname_override or self.hostname


class AssetPort(Base):
    __tablename__ = "asset_ports"
    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_port_proto"),)

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[Protocol] = mapped_column(
        Enum(Protocol, name="port_protocol", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    state: Mapped[PortState] = mapped_column(
        Enum(PortState, name="port_state", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )

    service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    asset: Mapped[Asset] = relationship(back_populates="ports")
