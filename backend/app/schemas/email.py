from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.email import EmailOutboxStatus, EmailSuppressionReason
from app.models.event import Severity


class EmailStatusOut(BaseModel):
    mode: str
    sender: str
    api_key_present: bool
    last_successful_send_at: datetime | None
    queue_depth: int
    failed_count: int
    sends_today: int
    daily_cap_per_recipient: int
    global_daily_cap: int
    global_pause: bool
    webhook_active: bool


class EmailTestRequest(BaseModel):
    pass


class EmailSettingsOut(BaseModel):
    types_enabled: dict[str, bool]
    global_pause: bool
    updated_at: datetime


class EmailSettingsUpdate(BaseModel):
    types_enabled: dict[str, bool] | None = None
    global_pause: bool | None = None


class EmailOutboxOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email_type: str
    recipient_email: str
    subject: str
    status: EmailOutboxStatus
    digest: bool
    attempts: int
    last_error: str | None
    related_type: str | None
    related_id: str | None
    created_at: datetime
    sent_at: datetime | None
    html_body: str | None = None
    text_body: str | None = None


class EmailOutboxListOut(BaseModel):
    items: list[EmailOutboxOut]
    total: int


class EmailSuppressionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    reason: EmailSuppressionReason
    created_at: datetime


class EmailPreferencesOut(BaseModel):
    enabled: bool
    min_severity: Severity
    delivery_mode: str
    types_disabled: list[str]
    digest_frequency: str
    digest_hour_utc: int
    locked_types: list[str]


class EmailPreferencesUpdate(BaseModel):
    enabled: bool | None = None
    min_severity: Severity | None = None
    delivery_mode: str | None = None
    types_disabled: list[str] | None = None
    digest_frequency: str | None = None
    digest_hour_utc: int | None = Field(default=None, ge=0, le=23)


class BrevoWebhookEvent(BaseModel):
    """Loose mapping of Brevo's transactional webhook payload — only the
    fields we act on. Extra fields are ignored, never trusted as HTML."""

    model_config = ConfigDict(extra="ignore")

    event: str
    message_id: str | None = Field(default=None, alias="message-id")
    email: EmailStr | None = None
    reason: str | None = None
    date: str | None = None
