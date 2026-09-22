from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.event import EventType, Severity
from app.models.incident import IncidentStatus
from app.models.report import ReportFormat, ReportStatus, ReportType


class IncidentSummaryParams(BaseModel):
    from_: datetime = Field(alias="from")
    to: datetime
    severity: list[Severity] = Field(default_factory=list)
    status: list[IncidentStatus] = Field(default_factory=list)
    model_config = ConfigDict(populate_by_name=True)


class IncidentDetailParams(BaseModel):
    incident_id: uuid.UUID


class AssetInventoryParams(BaseModel):
    is_active: bool | None = None
    cidr: str | None = None
    from_: datetime | None = Field(default=None, alias="from")
    to: datetime | None = None
    model_config = ConfigDict(populate_by_name=True)


class EventStatisticsParams(BaseModel):
    from_: datetime = Field(alias="from")
    to: datetime
    severity: list[Severity] = Field(default_factory=list)
    event_type: list[EventType] = Field(default_factory=list)
    model_config = ConfigDict(populate_by_name=True)


_PARAMS_MODEL: dict[ReportType, type[BaseModel]] = {
    ReportType.INCIDENT_SUMMARY: IncidentSummaryParams,
    ReportType.INCIDENT_DETAIL: IncidentDetailParams,
    ReportType.ASSET_INVENTORY: AssetInventoryParams,
    ReportType.EVENT_STATISTICS: EventStatisticsParams,
}


def validate_report_params(report_type: ReportType, params: dict[str, Any]) -> dict[str, Any]:
    """Raises pydantic.ValidationError. Returns the JSON-serializable, alias'd
    dict form (so `from`/`to` round-trip through JSONB storage correctly)."""
    model = _PARAMS_MODEL[report_type]
    validated = model.model_validate(params or {})
    return validated.model_dump(mode="json", by_alias=True)


# CSV is not offered for incident_detail, which is narrative rather than tabular.
CSV_SUPPORTED_TYPES = frozenset(
    {ReportType.INCIDENT_SUMMARY, ReportType.ASSET_INVENTORY, ReportType.EVENT_STATISTICS}
)


class ReportCreate(BaseModel):
    report_type: ReportType
    format: ReportFormat
    params: dict[str, Any]
    title: str | None = Field(default=None, max_length=255)


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    report_type: ReportType
    title: str
    params: dict[str, Any]
    format: ReportFormat
    status: ReportStatus
    requested_by: uuid.UUID | None
    file_size: int | None
    checksum: str | None
    error: str | None
    requested_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    expires_at: datetime | None


class ReportScheduleIn(BaseModel):
    report_type: ReportType
    format: ReportFormat
    params: dict[str, Any] = Field(default_factory=dict)
    cron: str = Field(min_length=1, max_length=64)
    enabled: bool = True
    recipients: list[str] = Field(default_factory=list)


class ReportScheduleUpdate(BaseModel):
    params: dict[str, Any] | None = None
    cron: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None
    recipients: list[str] | None = None


class ReportScheduleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    report_type: ReportType
    format: ReportFormat
    params: dict[str, Any]
    cron: str
    enabled: bool
    recipients: list[str]
    last_run_at: datetime | None
    next_run_at: datetime | None
    created_at: datetime
