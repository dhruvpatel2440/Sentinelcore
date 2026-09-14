from __future__ import annotations

import re
import uuid
from datetime import datetime
from ipaddress import IPv4Network, ip_network
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.config import settings
from app.models.asset import PortState, Protocol
from app.models.scan import ScanStatus, ScanType

MAX_TARGETS = 64

# Mirrors the helper's grammar in helper/helper/validation.py. Kept in sync
# deliberately rather than shared: the helper must never depend on backend code,
# since its whole job is to distrust the backend.
_PORT_SPEC_RE = re.compile(r"\A\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*\Z")

ALLOWED_SCAN_MODES = frozenset(
    {"tcp_syn", "tcp_connect", "udp", "ping", "service_version"}
)


class AssetPortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    port: int
    protocol: Protocol
    state: PortState
    service: str | None
    product: str | None
    version: str | None
    first_seen: datetime
    last_seen: datetime


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ip_address: str
    mac_address: str | None
    hostname: str | None
    hostname_override: str | None
    vendor: str | None
    os_guess: str | None
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    notes: str | None
    open_port_count: int = 0

    @field_validator("ip_address", "mac_address", mode="before")
    @classmethod
    def _stringify(cls, v: Any) -> Any:
        # asyncpg returns INET/MACADDR as ipaddress/str objects.
        return str(v) if v is not None else None


class AssetDetailOut(AssetOut):
    ports: list[AssetPortOut] = Field(default_factory=list)


class AssetListOut(BaseModel):
    items: list[AssetOut]
    total: int
    limit: int
    offset: int


class AssetUpdate(BaseModel):
    """Analyst-editable fields only. Discovery owns everything else."""

    notes: str | None = Field(default=None, max_length=10_000)
    hostname_override: str | None = Field(default=None, max_length=255)


class ScanRequest(BaseModel):
    targets: list[str] | None = None
    ports: str = Field(default="1-1024", max_length=512)
    mode: str = Field(default="tcp_syn", max_length=32)

    @field_validator("targets")
    @classmethod
    def _validate_targets(cls, value: list[str] | None) -> list[str] | None:
        """First of two independent checks — the helper re-validates all of this
        as if this layer had been bypassed entirely."""
        if value is None:
            return None
        if not value:
            raise ValueError("targets must not be empty")
        if len(value) > MAX_TARGETS:
            raise ValueError(f"too many targets (limit {MAX_TARGETS})")

        monitored = settings.monitored_network_parsed
        for raw in value:
            try:
                network = ip_network(raw.strip(), strict=False)
            except ValueError as exc:
                raise ValueError(f"not a valid IPv4 address or CIDR: {raw!r}") from exc
            if not isinstance(network, IPv4Network):
                raise ValueError("only IPv4 targets are supported")
            if network.is_loopback or network.is_link_local or network.is_multicast:
                raise ValueError(f"target {raw} is not a permitted address type")
            if not network.subnet_of(monitored):
                raise ValueError(f"target {raw} is outside the monitored network {monitored}")
        return [t.strip() for t in value]

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, value: str) -> str:
        """Digits, ranges and commas only — nothing that could be a shell token."""
        spec = value.strip()
        if not _PORT_SPEC_RE.match(spec):
            raise ValueError(
                "ports must contain only digits, ranges and commas (e.g. 22,80,1-1024)"
            )

        for part in spec.split(","):
            lo_s, _, hi_s = part.partition("-")
            lo = int(lo_s)
            hi = int(hi_s) if hi_s else lo
            if not (1 <= lo <= 65535) or not (1 <= hi <= 65535):
                raise ValueError(f"port out of range 1-65535: {part}")
            if lo > hi:
                raise ValueError(f"port range is reversed: {part}")
        return spec

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, value: str) -> str:
        """A mode name, never an nmap flag. The helper maps it to fixed flags."""
        if value not in ALLOWED_SCAN_MODES:
            raise ValueError(
                f"unknown scan mode {value!r}; allowed: {', '.join(sorted(ALLOWED_SCAN_MODES))}"
            )
        return value


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_type: ScanType
    status: ScanStatus
    targets: list[str]
    ports: str | None
    mode: str | None
    started_at: datetime | None
    finished_at: datetime | None
    hosts_found: int
    ports_found: int
    error: str | None
    requested_by: uuid.UUID | None
    created_at: datetime
    duration_seconds: float | None = None
