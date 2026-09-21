"""M7 correlation rule schemas.

`match` and `params` are stored as JSONB and are only as safe as their
validation at write time — a malformed rule must 422 here, never surface as
an exception inside the engine at 3am.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from ipaddress import ip_network
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.correlation import CandidateStatus, RuleType
from app.models.event import EventType, Severity

GROUP_BY_FIELDS = frozenset({"src_ip", "dst_ip", "signature_id", "dst_port", "src_port", "proto"})


class MatchBlock(BaseModel):
    """An event filter shared by rule `match` and `sequence` step params."""

    model_config = ConfigDict(extra="forbid")

    severity: list[Severity] | None = None
    event_type: list[EventType] | None = None
    signature_id: list[int] | None = None
    category_regex: str | None = None
    src_cidr: str | None = None
    dst_cidr: str | None = None

    @field_validator("category_regex")
    @classmethod
    def _valid_regex(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"category_regex is not a valid regular expression: {exc}") from exc
        return v

    @field_validator("src_cidr", "dst_cidr")
    @classmethod
    def _valid_cidr(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError(f"not a valid CIDR: {v!r}") from exc
        return v


class ThresholdParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count_distinct_field: str | None = None

    @field_validator("count_distinct_field")
    @classmethod
    def _known_field(cls, v: str | None) -> str | None:
        if v is not None and v not in GROUP_BY_FIELDS:
            raise ValueError(f"count_distinct_field must be one of {sorted(GROUP_BY_FIELDS)}")
        return v


class SequenceParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    steps: list[MatchBlock] = Field(min_length=2)


class RareParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    baseline_days: int = Field(default=14, ge=1, le=365)
    frequency_floor: int = Field(default=3, ge=1)


class BeaconParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_cv: float = Field(default=0.15, gt=0, le=1)
    min_samples: int = Field(default=5, ge=3)


_PARAMS_MODEL: dict[RuleType, type[BaseModel]] = {
    RuleType.THRESHOLD: ThresholdParams,
    RuleType.SEQUENCE: SequenceParams,
    RuleType.RARE: RareParams,
    RuleType.BEACON: BeaconParams,
}


def validate_params(rule_type: RuleType, params: dict[str, Any]) -> dict[str, Any]:
    """Raises `pydantic.ValidationError` naming the bad field on failure."""
    model = _PARAMS_MODEL[rule_type]
    return model.model_validate(params or {}).model_dump()


class RuleBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    enabled: bool = True
    rule_type: RuleType
    match: MatchBlock = Field(default_factory=MatchBlock)
    group_by: list[str] = Field(min_length=1)
    window_seconds: int = Field(gt=0, le=7 * 24 * 3600)
    threshold: int = Field(default=1, ge=1)
    severity: Severity
    dedup_window_seconds: int = Field(default=3600, ge=0, le=7 * 24 * 3600)
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("group_by")
    @classmethod
    def _valid_group_by(cls, v: list[str]) -> list[str]:
        bad = set(v) - GROUP_BY_FIELDS
        if bad:
            raise ValueError(f"group_by contains unknown field(s) {sorted(bad)}; allowed: {sorted(GROUP_BY_FIELDS)}")
        return v

    @model_validator(mode="after")
    def _valid_params_for_type(self) -> "RuleBase":
        # Raises pydantic.ValidationError naming the offending field — the
        # caller (route) lets FastAPI turn that into a 422.
        self.params = validate_params(self.rule_type, self.params)
        return self


class RuleCreate(RuleBase):
    pass


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, min_length=1)
    enabled: bool | None = None
    match: MatchBlock | None = None
    group_by: list[str] | None = None
    window_seconds: int | None = Field(default=None, gt=0, le=7 * 24 * 3600)
    threshold: int | None = Field(default=None, ge=1)
    severity: Severity | None = None
    dedup_window_seconds: int | None = Field(default=None, ge=0, le=7 * 24 * 3600)
    params: dict[str, Any] | None = None

    @field_validator("group_by")
    @classmethod
    def _valid_group_by(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        bad = set(v) - GROUP_BY_FIELDS
        if bad:
            raise ValueError(f"group_by contains unknown field(s) {sorted(bad)}; allowed: {sorted(GROUP_BY_FIELDS)}")
        return v


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    rule_type: RuleType
    match: dict[str, Any]
    group_by: list[str]
    window_seconds: int
    threshold: int
    severity: Severity
    dedup_window_seconds: int
    params: dict[str, Any]
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    candidates_24h: int = 0
    last_run_status: str | None = None


class RuleTestRequest(BaseModel):
    from_: datetime = Field(alias="from")
    to: datetime
    model_config = ConfigDict(populate_by_name=True)


class CandidatePreview(BaseModel):
    group_key: str
    first_event_ts: datetime
    last_event_ts: datetime
    event_count: int
    severity: Severity
    score: int
    summary: str
    evidence: dict[str, Any]


class RuleTestResponse(BaseModel):
    candidates: list[CandidatePreview]
    events_scanned: int
    duration_ms: int


class RuleRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    window_start: datetime
    window_end: datetime
    events_scanned: int
    candidates_created: int
    duration_ms: int
    error: str | None
    created_at: datetime


class CandidateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: uuid.UUID
    rule_name: str | None = None
    group_key: str
    first_event_ts: datetime
    last_event_ts: datetime
    event_count: int
    severity: Severity
    score: int
    summary: str
    evidence: dict[str, Any]
    status: CandidateStatus
    incident_id: uuid.UUID | None
    created_at: datetime


class SuppressRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
