"""U05 — dashboard stats (top talkers)."""

from __future__ import annotations

from pydantic import BaseModel

from app.models.event import Severity


class TopTalkerBucket(BaseModel):
    value: str
    count: int
    # The most severe event seen for this value in the window, or None if
    # every matching event somehow lacked a severity (should not happen).
    max_severity: Severity | None = None
    ioc_match: bool = False
    hostname: str | None = None


class TopTalkersOut(BaseModel):
    by: str
    window: str
    items: list[TopTalkerBucket]
    took_ms: int
    cached: bool = False
