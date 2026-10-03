from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.event import Severity
from app.models.incident import HistoryAction, IncidentStatus


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    number: int
    title: str
    description: str | None
    status: IncidentStatus
    severity: Severity
    score: int
    src_ip: str | None
    dst_ip: str | None
    asset_id: uuid.UUID | None
    assigned_to: uuid.UUID | None
    rule_id: uuid.UUID | None
    candidate_id: uuid.UUID | None
    event_count: int
    first_event_ts: datetime | None
    last_event_ts: datetime | None
    opened_at: datetime
    acknowledged_at: datetime | None
    closed_at: datetime | None
    closed_by: uuid.UUID | None
    resolution_note: str | None
    version: int
    created_at: datetime
    updated_at: datetime

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def _stringify(cls, v: Any) -> Any:
        return str(v) if v is not None else None


class IncidentHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID | None
    username: str | None = None
    action: HistoryAction
    from_value: str | None
    to_value: str | None
    note: str | None
    created_at: datetime


class IncidentDetailOut(IncidentOut):
    assignee_username: str | None = None
    rule_name: str | None = None
    asset_hostname: str | None = None
    recent_history: list[IncidentHistoryOut] = Field(default_factory=list)


class IncidentListOut(BaseModel):
    items: list[IncidentOut]
    next_cursor: str | None
    has_more: bool


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    severity: Severity
    src_ip: str | None = None
    dst_ip: str | None = None
    asset_id: uuid.UUID | None = None
    event_ids: list[int] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    version: int
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    severity: Severity | None = None
    score: int | None = None
    assigned_to: uuid.UUID | None = None


class StatusChangeRequest(BaseModel):
    version: int
    status: IncidentStatus
    note: str | None = None


class AssignRequest(BaseModel):
    version: int
    user_id: uuid.UUID | None = None


class CommentRequest(BaseModel):
    note: str = Field(min_length=1, max_length=10_000)


class EventLinkRequest(BaseModel):
    event_ids: list[int] = Field(min_length=1)


class LinkedEventOut(BaseModel):
    id: int
    ts: datetime
    event_type: str
    severity: Severity
    signature: str | None
    src_ip: str | None
    dst_ip: str | None
    linked_by: uuid.UUID | None
    linked_at: datetime

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def _stringify(cls, v: Any) -> Any:
        return str(v) if v is not None else None


class StatsSummaryOut(BaseModel):
    open_by_severity: dict[str, int]
    unassigned_count: int
    mtta_seconds: float | None
    mttr_seconds: float | None
    top_rules: list[dict[str, Any]]
