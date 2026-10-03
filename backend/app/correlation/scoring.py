"""Candidate scoring — kept in one small, unit-tested module with the weights
as named constants, per M7's design principles. Never scattered across
evaluators, so tuning the weights is a one-file change.
"""

from __future__ import annotations

import math
from ipaddress import ip_address

from sqlalchemy import cast, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.correlation.evaluators.base import Candidate
from app.models.asset import Asset, AssetPort, PortState
from app.models.event import Severity

SEVERITY_BASE_SCORE: dict[Severity, int] = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 70,
    Severity.MEDIUM: 50,
    Severity.LOW: 30,
    Severity.INFO: 10,
}

# Ports where a compromise is disproportionately dangerous: remote admin,
# databases, file shares.
SENSITIVE_PORTS = frozenset({22, 23, 445, 1433, 3306, 3389, 5432, 5900})

DEST_SENSITIVE_ASSET_BONUS = 15
EXTERNAL_TO_INTERNAL_BONUS = 10
OVERSHOOT_BONUS_PER_DOUBLING = 5
OVERSHOOT_BONUS_MAX = 20

SCORE_MIN = 0
SCORE_MAX = 100


async def _dst_asset_has_sensitive_open_port(dst_ip: str | None, db: AsyncSession) -> bool:
    if not dst_ip:
        return False
    asset = await db.scalar(select(Asset).where(Asset.ip_address == cast(dst_ip, INET)))
    if asset is None:
        return False
    open_sensitive = await db.scalar(
        select(AssetPort.id).where(
            AssetPort.asset_id == asset.id,
            AssetPort.state == PortState.OPEN,
            AssetPort.port.in_(SENSITIVE_PORTS),
        )
    )
    return open_sensitive is not None


def _is_external_to_internal(src_ip: str | None, dst_ip: str | None) -> bool:
    if not src_ip or not dst_ip:
        return False
    try:
        src = ip_address(src_ip)
        dst = ip_address(dst_ip)
    except ValueError:
        return False
    monitored = settings.monitored_network_parsed
    return src not in monitored and dst in monitored


def _overshoot_bonus(event_count: int, threshold: int) -> int:
    if threshold <= 0:
        return 0
    ratio = event_count / threshold
    if ratio <= 1:
        return 0
    # +5 per doubling past the threshold, capped — a scan that fires at 30x
    # threshold should not blow past a 100-point scale on volume alone.
    doublings = math.log2(ratio)
    return min(int(doublings * OVERSHOOT_BONUS_PER_DOUBLING), OVERSHOOT_BONUS_MAX)


async def score_candidate(candidate: Candidate, base_severity: Severity, threshold: int, db: AsyncSession) -> int:
    score = SEVERITY_BASE_SCORE[base_severity]

    if await _dst_asset_has_sensitive_open_port(candidate.dst_ip, db):
        score += DEST_SENSITIVE_ASSET_BONUS

    if _is_external_to_internal(candidate.src_ip, candidate.dst_ip):
        score += EXTERNAL_TO_INTERNAL_BONUS

    score += _overshoot_bonus(candidate.event_count, threshold)

    return max(SCORE_MIN, min(SCORE_MAX, score))
