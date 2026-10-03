from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.ioc import IocSeverity, IocType, SourceFormat


class IocOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    indicator: str
    ioc_type: IocType
    source_id: uuid.UUID | None
    confidence: int
    severity: IocSeverity
    threat_type: str | None
    description: str | None
    tags: list[str]
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    is_active: bool
    added_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    match_count: int = 0
    source_name: str | None = None


class IocCreate(BaseModel):
    indicator: str = Field(min_length=1)
    ioc_type: IocType | None = None  # best-effort detected if omitted
    confidence: int = Field(default=50, ge=0, le=100)
    severity: IocSeverity = IocSeverity.MEDIUM
    threat_type: str | None = None
    description: str = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None


class IocBulkCreate(BaseModel):
    indicators: list[str] = Field(min_length=1)
    ioc_type: IocType | None = None
    confidence: int = Field(default=50, ge=0, le=100)
    severity: IocSeverity = IocSeverity.MEDIUM
    threat_type: str | None = None
    description: str = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)


class IocBulkResultLine(BaseModel):
    input: str
    accepted: bool
    reason: str | None = None
    ioc_id: uuid.UUID | None = None


class IocBulkResult(BaseModel):
    results: list[IocBulkResultLine]
    accepted_count: int
    rejected_count: int


class IocUpdate(BaseModel):
    confidence: int | None = Field(default=None, ge=0, le=100)
    severity: IocSeverity | None = None
    threat_type: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    expires_at: datetime | None = None
    is_active: bool | None = None


class IocMatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ioc_id: uuid.UUID
    event_id: int | None
    pcap_artifact_id: uuid.UUID | None
    matched_value: str
    matched_field: str
    incident_id: uuid.UUID | None
    ts: datetime
    indicator: str | None = None
    severity: IocSeverity | None = None


class IocDetailOut(IocOut):
    recent_matches: list[IocMatchOut] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)


class LookupResult(BaseModel):
    query: str
    normalized: str | None
    ioc_type: IocType | None
    found: bool
    matches: list[IocOut] = Field(default_factory=list)


class IocSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    url: str
    format: SourceFormat
    parser_config: dict[str, Any]
    enabled: bool
    default_confidence: int
    default_severity: IocSeverity
    refresh_interval_hours: int
    ttl_days: int
    last_fetch_at: datetime | None
    last_status: str | None
    last_error: str | None
    indicator_count: int
    created_at: datetime
    updated_at: datetime


class IocSourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=1)
    format: SourceFormat
    parser_config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    default_confidence: int = Field(default=50, ge=0, le=100)
    default_severity: IocSeverity = IocSeverity.MEDIUM
    refresh_interval_hours: int = Field(default=24, ge=1)
    ttl_days: int = Field(default=30, ge=1)


class IocSourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    url: str | None = None
    format: SourceFormat | None = None
    parser_config: dict[str, Any] | None = None
    enabled: bool | None = None
    default_confidence: int | None = Field(default=None, ge=0, le=100)
    default_severity: IocSeverity | None = None
    refresh_interval_hours: int | None = Field(default=None, ge=1)
    ttl_days: int | None = Field(default=None, ge=1)


class RetrohuntRequest(BaseModel):
    ioc_id: uuid.UUID | None = None
    source_id: uuid.UUID | None = None
    days: int = Field(default=7, ge=1, le=365)


class RetrohuntAccepted(BaseModel):
    accepted: bool = True
    days: int


class IntelStatsOut(BaseModel):
    active_by_type: dict[str, int]
    active_by_source: dict[str, int]
    matches_last_24h: int
    matches_last_7d: int
    top_matched: list[dict[str, Any]]
    source_health: list[IocSourceOut]
