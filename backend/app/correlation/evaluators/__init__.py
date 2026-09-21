from __future__ import annotations

from app.models.correlation import RuleType

from . import beacon, rare, sequence, threshold
from .base import Candidate, Evaluator

REGISTRY: dict[RuleType, Evaluator] = {
    RuleType.THRESHOLD: threshold,
    RuleType.SEQUENCE: sequence,
    RuleType.RARE: rare,
    RuleType.BEACON: beacon,
}

__all__ = ["Candidate", "Evaluator", "REGISTRY"]
