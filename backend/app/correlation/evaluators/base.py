from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.correlation import CorrelationRule

EVIDENCE_SAMPLE_CAP = 100


@dataclass
class Candidate:
    group_key: str
    first_event_ts: datetime
    last_event_ts: datetime
    event_count: int
    summary: str
    event_ids: list[int] = field(default_factory=list)
    extra_evidence: dict[str, Any] = field(default_factory=dict)
    # Carried separately from `group_key` (a formatted string) so scoring can
    # look up the destination asset without re-parsing it.
    src_ip: str | None = None
    dst_ip: str | None = None

    def evidence(self) -> dict[str, Any]:
        ids = sorted(self.event_ids)
        return {
            "event_ids_first": ids[:EVIDENCE_SAMPLE_CAP],
            "event_ids_last": ids[-EVIDENCE_SAMPLE_CAP:],
            "total_matched": len(ids),
            **self.extra_evidence,
        }


class Evaluator(Protocol):
    async def evaluate(
        self,
        rule: CorrelationRule,
        window_start: datetime,
        window_end: datetime,
        db: AsyncSession,
    ) -> tuple[list[Candidate], int]:
        """Returns (candidates, events_scanned)."""
        ...
