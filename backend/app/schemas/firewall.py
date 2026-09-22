from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.firewall_action import TTL_MAX_SECONDS, TTL_MIN_SECONDS, FirewallActionStatus, FirewallDirection


class FirewallActionCreate(BaseModel):
    target: str = Field(min_length=1, max_length=64)
    direction: FirewallDirection
    protocol: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    ttl_seconds: int = Field(ge=TTL_MIN_SECONDS, le=TTL_MAX_SECONDS)
    reason: str = Field(min_length=1, max_length=2000)
    incident_id: uuid.UUID | None = None

    @field_validator("protocol")
    @classmethod
    def _protocol_enum(cls, v: str | None) -> str | None:
        if v is not None and v not in ("tcp", "udp"):
            raise ValueError("protocol must be 'tcp' or 'udp'")
        return v

    @field_validator("target")
    @classmethod
    def _target_is_ip_or_cidr(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"target must be an IP address or CIDR: {v!r}") from exc
        return v.strip()


class FirewallActionExtend(BaseModel):
    additional_seconds: int = Field(ge=1, le=TTL_MAX_SECONDS)


class FirewallActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target: str
    direction: FirewallDirection
    protocol: str | None
    port: int | None
    reason: str
    incident_id: uuid.UUID | None
    ttl_seconds: int
    expires_at: datetime
    status: FirewallActionStatus
    created_by: uuid.UUID
    created_at: datetime
    applied_at: datetime | None
    revoked_at: datetime | None
    revoked_by: uuid.UUID | None
    error: str | None
    remaining_seconds: int | None = None


class FirewallPrecheckRequest(BaseModel):
    target: str = Field(min_length=1, max_length=64)


class FirewallPrecheckResult(BaseModel):
    allowed: bool
    reason: str | None = None


class FirewallStatus(BaseModel):
    helper_reachable: bool
    chain_present: bool
    active_rule_count: int
    db_active_count: int
    drift_count: int
    last_reconciliation_at: datetime | None
