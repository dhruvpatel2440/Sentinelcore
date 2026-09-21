from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.event import EventType, Severity


class AssetSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ip_address: str
    hostname: str | None = None
    hostname_override: str | None = None
    is_active: bool

    @field_validator("ip_address", mode="before")
    @classmethod
    def _stringify(cls, v: Any) -> Any:
        return str(v) if v is not None else None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    ingested_at: datetime
    event_type: EventType
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    proto: str | None
    signature: str | None
    signature_id: int | None
    rev: int | None
    category: str | None
    severity: Severity
    src_asset_id: uuid.UUID | None
    dst_asset_id: uuid.UUID | None
    flow_id: int | None

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def _stringify(cls, v: Any) -> Any:
        return str(v) if v is not None else None


class EventDetailOut(EventOut):
    raw: dict[str, Any]
    src_asset: AssetSummaryOut | None = None
    dst_asset: AssetSummaryOut | None = None
    related_flow_events: list[EventOut] = Field(default_factory=list)
    signature_24h_count: int = 0


class EventListOut(BaseModel):
    items: list[EventOut]
    next_cursor: str | None
    took_ms: int
    has_more: bool
    capped_count: int | None = None


class FacetBucket(BaseModel):
    value: str
    count: int


class EventFacetsOut(BaseModel):
    severity: list[FacetBucket]
    event_type: list[FacetBucket]
    top_signatures: list[FacetBucket]
    top_src_ips: list[FacetBucket]
    top_dst_ips: list[FacetBucket]
    took_ms: int
    cached: bool = False


# ---------------------------------------------------------------------------
# Saved searches
# ---------------------------------------------------------------------------


class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    filters: dict[str, Any]
    is_shared: bool = False


class SavedSearchUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    filters: dict[str, Any] | None = None
    is_shared: bool | None = None


class SavedSearchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    filters: dict[str, Any]
    is_shared: bool
    created_at: datetime
    updated_at: datetime
    is_owner: bool = True
