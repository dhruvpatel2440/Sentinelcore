from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.sensor import OverrideAction, SensorAction

# Fixed vocabularies — threshold params end up in a Suricata config file, so
# nothing free-form is accepted.
THRESHOLD_TYPES = frozenset({"limit", "threshold", "both"})
THRESHOLD_TRACKS = frozenset({"by_src", "by_dst", "by_rule", "by_both"})


class SensorStatusOut(BaseModel):
    running: bool
    pid: int | None = None
    uptime_seconds: float | None = None
    version: str | None = None
    rule_count: int = 0
    ruleset_sha256: str | None = None
    last_reload_at: datetime | None = None

    # A sensor that is up but not writing eve.json is a distinct failure from
    # a sensor that is down — surface it separately.
    eve_log_age_seconds: float | None = None
    eve_log_stale: bool = False

    helper_available: bool = True
    binary_available: bool = True


class SensorStatsOut(BaseModel):
    packets: int = 0
    drops: int = 0
    drop_rate: float = 0.0
    kernel_packets: int = 0
    kernel_drops: int = 0
    uptime_seconds: float | None = None
    captured_at: datetime | None = None
    history: list[dict] = Field(default_factory=list)


class ConfigTestOut(BaseModel):
    valid: bool
    returncode: int | None = None
    output: str = ""


class RuleSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    url: str
    enabled: bool
    last_updated_at: datetime | None
    last_status: str | None
    last_error: str | None
    rule_count: int
    created_at: datetime


class RuleSourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=1, max_length=1024)
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def _must_be_https(cls, value: str) -> str:
        if not value.lower().startswith("https://"):
            raise ValueError("rule source URL must use HTTPS")
        return value


class RuleSourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    url: str | None = Field(default=None, min_length=1, max_length=1024)
    enabled: bool | None = None

    @field_validator("url")
    @classmethod
    def _must_be_https(cls, value: str | None) -> str | None:
        if value is not None and not value.lower().startswith("https://"):
            raise ValueError("rule source URL must use HTTPS")
        return value


class RuleOverrideOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    sid: int
    action: OverrideAction
    params: dict | None
    reason: str
    created_by: uuid.UUID | None
    created_at: datetime


class RuleOverrideCreate(BaseModel):
    sid: int = Field(gt=0, le=2**63 - 1)
    action: OverrideAction
    params: dict | None = None
    # Required, with a real minimum — "test" is not an explanation.
    reason: str = Field(min_length=5, max_length=2000)

    @field_validator("params")
    @classmethod
    def _validate_params(cls, value: dict | None) -> dict | None:
        if value is None:
            return None
        if "type" in value and value["type"] not in THRESHOLD_TYPES:
            raise ValueError(f"threshold type must be one of {sorted(THRESHOLD_TYPES)}")
        if "track" in value and value["track"] not in THRESHOLD_TRACKS:
            raise ValueError(f"threshold track must be one of {sorted(THRESHOLD_TRACKS)}")
        for key, bounds in (("count", (1, 10_000)), ("seconds", (1, 86_400))):
            if key in value:
                try:
                    number = int(value[key])
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"{key} must be an integer") from exc
                if not (bounds[0] <= number <= bounds[1]):
                    raise ValueError(f"{key} must be between {bounds[0]} and {bounds[1]}")
        return value


class SensorEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    action: SensorAction
    status: str
    detail: dict | None
    user_id: uuid.UUID | None
    created_at: datetime
