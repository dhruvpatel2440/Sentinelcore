"""M7 correlation engine tests.

Evaluators run real SQL against Postgres (grouping and the `<<=`/`~`
operators are not worth faking), so these tests talk to the real database the
same way M5/M6's smoke checks do: seed synthetic rows tagged with a
per-test-unique category, run the code under test, then delete exactly those
rows. Redis is faked, matching the `FakeRedis` pattern in test_writer.py.
"""

from __future__ import annotations

import hashlib
import statistics
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import delete, select, text

from app.correlation.engine import run_rule
from app.correlation.evaluators import beacon, rare, sequence, threshold
from app.correlation.scoring import (
    _is_external_to_internal,
    _overshoot_bonus,
    score_candidate,
)
from app.db.session import SessionLocal
from app.models.correlation import CorrelationRule, IncidentCandidate, RuleRun, RuleType
from app.models.event import Severity
from app.schemas.correlation import (
    BeaconParams,
    MatchBlock,
    RareParams,
    RuleCreate,
    SequenceParams,
    ThresholdParams,
    validate_params,
)

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Fixture helpers — real DB, tagged and cleaned up per test.
# ---------------------------------------------------------------------------


async def _insert_events(db, category: str, events: list[dict]) -> list[int]:
    ids = []
    for i, e in enumerate(events):
        dedup = hashlib.sha256(f"{category}-{i}-{uuid.uuid4()}".encode()).digest()
        row = {
            "ts": e["ts"],
            "event_type": e.get("event_type", "alert"),
            "src_ip": e.get("src_ip", "192.168.10.50"),
            "dst_ip": e.get("dst_ip", "192.168.10.60"),
            "src_port": e.get("src_port"),
            "dst_port": e.get("dst_port"),
            "proto": e.get("proto", "tcp"),
            "signature": e.get("signature", "test signature"),
            "signature_id": e.get("signature_id", 9200000),
            "rev": 1,
            "category": category,
            "severity": e.get("severity", "medium"),
            "flow_id": e.get("flow_id"),
            "dedup_key": dedup,
            "raw": "{}",
        }
        result = await db.execute(
            text(
                """
                INSERT INTO events (ts, event_type, src_ip, dst_ip, src_port, dst_port, proto,
                    signature, signature_id, rev, category, severity, flow_id, dedup_key, raw)
                VALUES (:ts, :event_type, :src_ip, :dst_ip, :src_port, :dst_port, :proto,
                    :signature, :signature_id, :rev, :category, :severity, :flow_id, :dedup_key, :raw)
                RETURNING id
                """
            ),
            row,
        )
        ids.append(result.scalar_one())
    await db.commit()
    return ids


async def _cleanup_events(db, category: str) -> None:
    await db.execute(text("DELETE FROM events WHERE category = :c"), {"c": category})
    await db.commit()


def _rule(rule_type: RuleType, **overrides) -> CorrelationRule:
    defaults = dict(
        id=uuid.uuid4(),
        name=f"test-{uuid.uuid4().hex[:8]}",
        description="test rule",
        enabled=True,
        rule_type=rule_type,
        match={},
        group_by=["src_ip"],
        window_seconds=300,
        threshold=1,
        severity=Severity.HIGH,
        dedup_window_seconds=3600,
        params={},
    )
    defaults.update(overrides)
    return CorrelationRule(**defaults)


@pytest.fixture
def category():
    return f"m7-test-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# threshold evaluator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threshold_fires_once_on_a_port_scan(category):
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        events = [
            {"ts": now - timedelta(seconds=i), "dst_port": 1000 + i, "src_ip": "10.0.0.5"}
            for i in range(30)
        ]
        await _insert_events(db, category, events)
        try:
            rule = _rule(
                RuleType.THRESHOLD,
                match={"category_regex": f"^{category}$"},
                group_by=["src_ip"],
                threshold=25,
                params={"count_distinct_field": "dst_port"},
            )
            candidates, scanned = await threshold.evaluate(
                rule, now - timedelta(minutes=5), now + timedelta(seconds=1), db
            )
            assert scanned == 30
            assert len(candidates) == 1  # one candidate, not thirty
            assert candidates[0].extra_evidence["metric"] == 30
        finally:
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_threshold_does_not_fire_below_threshold(category):
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        events = [{"ts": now - timedelta(seconds=i), "dst_port": 1000 + i} for i in range(5)]
        await _insert_events(db, category, events)
        try:
            rule = _rule(
                RuleType.THRESHOLD,
                match={"category_regex": f"^{category}$"},
                threshold=25,
                params={"count_distinct_field": "dst_port"},
            )
            candidates, _ = await threshold.evaluate(rule, now - timedelta(minutes=5), now + timedelta(seconds=1), db)
            assert candidates == []
        finally:
            await _cleanup_events(db, category)


# ---------------------------------------------------------------------------
# sequence evaluator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sequence_fires_when_stages_occur_in_order(category):
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        events = [
            {"ts": now - timedelta(seconds=30), "signature_id": 1, "src_ip": "10.0.0.9"},  # recon
            {"ts": now - timedelta(seconds=20), "signature_id": 2, "src_ip": "10.0.0.9"},  # exploit
            {"ts": now - timedelta(seconds=10), "signature_id": 3, "src_ip": "10.0.0.9"},  # callback
        ]
        await _insert_events(db, category, events)
        try:
            rule = _rule(
                RuleType.SEQUENCE,
                match={"category_regex": f"^{category}$"},
                group_by=["src_ip"],
                params={
                    "steps": [
                        {"signature_id": [1]},
                        {"signature_id": [2]},
                        {"signature_id": [3]},
                    ]
                },
            )
            candidates, _ = await sequence.evaluate(rule, now - timedelta(minutes=5), now + timedelta(seconds=1), db)
            assert len(candidates) == 1
            assert candidates[0].event_count == 3
        finally:
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_sequence_does_not_fire_out_of_order(category):
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        events = [
            {"ts": now - timedelta(seconds=30), "signature_id": 3, "src_ip": "10.0.0.9"},  # callback first
            {"ts": now - timedelta(seconds=20), "signature_id": 2, "src_ip": "10.0.0.9"},
            {"ts": now - timedelta(seconds=10), "signature_id": 1, "src_ip": "10.0.0.9"},
        ]
        await _insert_events(db, category, events)
        try:
            rule = _rule(
                RuleType.SEQUENCE,
                match={"category_regex": f"^{category}$"},
                params={"steps": [{"signature_id": [1]}, {"signature_id": [2]}, {"signature_id": [3]}]},
            )
            candidates, _ = await sequence.evaluate(rule, now - timedelta(minutes=5), now + timedelta(seconds=1), db)
            assert candidates == []
        finally:
            await _cleanup_events(db, category)


# ---------------------------------------------------------------------------
# rare evaluator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rare_flags_a_signature_with_a_thin_baseline(category):
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        # One occurrence total, ever (within the baseline window) — clearly rare.
        events = [{"ts": now - timedelta(seconds=5), "signature_id": 42424, "src_ip": "10.0.0.1"}]
        await _insert_events(db, category, events)
        try:
            rule = _rule(
                RuleType.RARE,
                match={"category_regex": f"^{category}$"},
                group_by=["src_ip"],
                params={"baseline_days": 14, "frequency_floor": 3},
            )
            candidates, _ = await rare.evaluate(rule, now - timedelta(minutes=1), now + timedelta(seconds=1), db)
            assert len(candidates) == 1
            assert candidates[0].extra_evidence["baseline_count"] == 1
        finally:
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_rare_does_not_flag_a_common_signature(category):
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        # Ten occurrences over the baseline window — comfortably above the floor.
        events = [
            {"ts": now - timedelta(hours=i), "signature_id": 5555, "src_ip": "10.0.0.2"} for i in range(10)
        ]
        await _insert_events(db, category, events)
        try:
            rule = _rule(
                RuleType.RARE,
                match={"category_regex": f"^{category}$"},
                group_by=["src_ip"],
                params={"baseline_days": 14, "frequency_floor": 3},
            )
            candidates, _ = await rare.evaluate(rule, now - timedelta(minutes=1), now + timedelta(seconds=1), db)
            assert candidates == []
        finally:
            await _cleanup_events(db, category)


# ---------------------------------------------------------------------------
# beacon evaluator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_beacon_fires_on_regular_interval(category):
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        # Exactly every 10s — zero jitter, cv == 0.
        events = [
            {"ts": now - timedelta(seconds=10 * i), "src_ip": "10.0.0.7", "dst_ip": "203.0.113.9"}
            for i in range(8)
        ]
        await _insert_events(db, category, events)
        try:
            rule = _rule(
                RuleType.BEACON,
                match={"category_regex": f"^{category}$"},
                group_by=["src_ip", "dst_ip"],
                params={"max_cv": 0.1, "min_samples": 5},
            )
            candidates, _ = await beacon.evaluate(rule, now - timedelta(minutes=5), now + timedelta(seconds=1), db)
            assert len(candidates) == 1
            assert candidates[0].extra_evidence["cv"] < 0.05
        finally:
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_beacon_does_not_fire_with_high_jitter(category):
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        # Wildly irregular deltas — human-driven traffic, not a beacon.
        offsets = [0, 3, 47, 51, 130, 133, 400, 401]
        events = [
            {"ts": now - timedelta(seconds=o), "src_ip": "10.0.0.8", "dst_ip": "203.0.113.10"}
            for o in offsets
        ]
        await _insert_events(db, category, events)
        try:
            rule = _rule(
                RuleType.BEACON,
                match={"category_regex": f"^{category}$"},
                group_by=["src_ip", "dst_ip"],
                params={"max_cv": 0.1, "min_samples": 5},
            )
            candidates, _ = await beacon.evaluate(rule, now - timedelta(minutes=10), now + timedelta(seconds=1), db)
            assert candidates == []
        finally:
            await _cleanup_events(db, category)


def test_beacon_cv_math_sanity():
    """Independent of the DB: a perfectly regular series has cv == 0."""
    deltas = [10.0] * 8
    assert statistics.pstdev(deltas) / statistics.mean(deltas) == 0


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def test_overshoot_bonus_zero_at_threshold():
    assert _overshoot_bonus(event_count=10, threshold=10) == 0


def test_overshoot_bonus_grows_with_multiples_and_caps():
    low = _overshoot_bonus(event_count=20, threshold=10)  # 2x
    high = _overshoot_bonus(event_count=10_000, threshold=10)  # 1000x
    assert 0 < low < high
    assert high <= 20  # OVERSHOOT_BONUS_MAX


def test_external_to_internal_detection():
    assert _is_external_to_internal("8.8.8.8", "192.168.10.5") is True
    assert _is_external_to_internal("192.168.10.5", "192.168.10.9") is False
    assert _is_external_to_internal("192.168.10.5", "8.8.8.8") is False
    assert _is_external_to_internal(None, "192.168.10.5") is False


@pytest.mark.asyncio
async def test_score_never_exceeds_max_or_drops_below_min():
    from app.correlation.evaluators.base import Candidate

    async with SessionLocal() as db:
        candidate = Candidate(
            group_key="src_ip=8.8.8.8",
            first_event_ts=datetime.now(UTC),
            last_event_ts=datetime.now(UTC),
            event_count=1,
            summary="x",
            src_ip="8.8.8.8",
            dst_ip="192.168.10.250",  # not a known asset — no bonus, but no crash either
        )
        score = await score_candidate(candidate, Severity.CRITICAL, threshold=1, db=db)
        assert 0 <= score <= 100


# ---------------------------------------------------------------------------
# JSONB param validation per rule type
# ---------------------------------------------------------------------------


def test_threshold_params_reject_unknown_distinct_field():
    with pytest.raises(ValidationError):
        ThresholdParams(count_distinct_field="not_a_real_field")


def test_sequence_params_require_at_least_two_steps():
    with pytest.raises(ValidationError):
        SequenceParams(steps=[{"signature_id": [1]}])


def test_beacon_params_reject_cv_out_of_range():
    with pytest.raises(ValidationError):
        BeaconParams(max_cv=1.5)


def test_rare_params_defaults_are_sane():
    p = RareParams()
    assert p.baseline_days >= 1
    assert p.frequency_floor >= 1


def test_validate_params_dispatches_by_rule_type():
    out = validate_params(RuleType.BEACON, {"max_cv": 0.2, "min_samples": 4})
    assert out == {"max_cv": 0.2, "min_samples": 4}
    with pytest.raises(ValidationError):
        validate_params(RuleType.THRESHOLD, {"count_distinct_field": "bogus"})


def test_match_block_rejects_bad_cidr():
    with pytest.raises(ValidationError):
        MatchBlock(src_cidr="not-a-cidr")


def test_match_block_rejects_bad_regex():
    with pytest.raises(ValidationError):
        MatchBlock(category_regex="(unterminated")


def test_rule_create_rejects_malformed_match_for_its_type():
    """A rule whose params clearly don't fit its declared type is a 422 at
    write time, not a crash inside the engine at 3am."""
    with pytest.raises(ValidationError) as exc:
        RuleCreate(
            name="bad-rule",
            description="d",
            rule_type=RuleType.SEQUENCE,
            group_by=["src_ip"],
            window_seconds=60,
            severity=Severity.HIGH,
            params={"steps": [{"signature_id": [1]}]},  # only one step
        )
    assert "steps" in str(exc.value)


def test_rule_create_rejects_unknown_group_by_field():
    with pytest.raises(ValidationError):
        RuleCreate(
            name="bad-rule-2",
            description="d",
            rule_type=RuleType.THRESHOLD,
            group_by=["not_a_field"],
            window_seconds=60,
            severity=Severity.HIGH,
        )


# ---------------------------------------------------------------------------
# Dedup suppression and idempotency across overlapping windows
# ---------------------------------------------------------------------------


class FakeRedis:
    def __init__(self):
        self.store: dict[str, bytes] = {}
        self.published: list[tuple[str, str]] = []

    async def exists(self, key):
        return 1 if key in self.store else 0

    async def set(self, key, value, ex=None):
        self.store[key] = value

    async def publish(self, channel, message):
        self.published.append((channel, message))


async def _cleanup_rule(db, rule_id) -> None:
    await db.execute(delete(RuleRun).where(RuleRun.rule_id == rule_id))
    await db.execute(delete(IncidentCandidate).where(IncidentCandidate.rule_id == rule_id))
    await db.execute(delete(CorrelationRule).where(CorrelationRule.id == rule_id))
    await db.commit()


@pytest.mark.asyncio
async def test_dedup_suppresses_a_repeat_candidate_within_the_window(category):
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        events = [{"ts": now - timedelta(seconds=i), "dst_port": 1000 + i} for i in range(30)]
        await _insert_events(db, category, events)

        rule = _rule(
            RuleType.THRESHOLD,
            match={"category_regex": f"^{category}$"},
            threshold=10,
            dedup_window_seconds=3600,
            params={"count_distinct_field": "dst_port"},
        )
        db.add(rule)
        await db.commit()

        redis = FakeRedis()
        try:
            await run_rule(rule, now, SessionLocal, redis)
            await run_rule(rule, now, SessionLocal, redis)  # same window again, e.g. a second tick

            all_rows = (
                await db.execute(select(IncidentCandidate).where(IncidentCandidate.rule_id == rule.id))
            ).scalars().all()
            assert len(all_rows) == 1  # not two — the second tick was deduped
        finally:
            await _cleanup_rule(db, rule.id)
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_idempotent_on_overlapping_windows_even_without_redis_dedup(category):
    """Restart-safety: the unique (rule_id, group_key, first_event_ts)
    constraint must catch a duplicate even if Redis dedup state was lost
    (e.g. the worker restarted), which is exactly the scenario 'reprocessing
    an overlapping window' describes."""
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        events = [{"ts": now - timedelta(seconds=i), "dst_port": 1000 + i} for i in range(30)]
        await _insert_events(db, category, events)

        rule = _rule(
            RuleType.THRESHOLD,
            match={"category_regex": f"^{category}$"},
            threshold=10,
            params={"count_distinct_field": "dst_port"},
        )
        db.add(rule)
        await db.commit()

        try:
            # Two independent FakeRedis instances — simulates dedup state
            # being gone (a fresh Redis, or a restart) on the second run.
            await run_rule(rule, now, SessionLocal, FakeRedis())
            await run_rule(rule, now, SessionLocal, FakeRedis())

            rows = (
                await db.execute(select(IncidentCandidate).where(IncidentCandidate.rule_id == rule.id))
            ).scalars().all()
            assert len(rows) == 1
        finally:
            await _cleanup_rule(db, rule.id)
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_run_rule_records_rule_run_and_publishes_on_success(category):
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        events = [{"ts": now - timedelta(seconds=i), "dst_port": 1000 + i} for i in range(30)]
        await _insert_events(db, category, events)

        rule = _rule(
            RuleType.THRESHOLD,
            match={"category_regex": f"^{category}$"},
            threshold=10,
            params={"count_distinct_field": "dst_port"},
        )
        db.add(rule)
        await db.commit()

        redis = FakeRedis()
        try:
            await run_rule(rule, now, SessionLocal, redis)

            run = await db.scalar(
                select(RuleRun).where(RuleRun.rule_id == rule.id).order_by(RuleRun.created_at.desc())
            )
            assert run is not None
            assert run.error is None
            assert run.candidates_created == 1
            assert len(redis.published) == 1
        finally:
            await _cleanup_rule(db, rule.id)
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_run_rule_records_timeout_error_and_does_not_stop_other_rules(category, monkeypatch):
    """A pathological rule must time out and be recorded — never raise out of
    run_rule and take the whole tick down with it."""
    import asyncio

    from app.core.config import settings

    async with SessionLocal() as db:
        now = datetime.now(UTC)
        rule = _rule(RuleType.THRESHOLD, match={"category_regex": f"^{category}$"}, threshold=1)
        db.add(rule)
        await db.commit()

        async def _hang(*args, **kwargs):
            await asyncio.sleep(10)
            return [], 0

        monkeypatch.setattr(
            "app.correlation.engine.REGISTRY",
            {RuleType.THRESHOLD: type("M", (), {"evaluate": staticmethod(_hang)})()},
        )
        monkeypatch.setattr(settings, "correlation_rule_timeout_seconds", 0.05)

        redis = FakeRedis()
        try:
            await run_rule(rule, now, SessionLocal, redis)  # must not raise
            run = await db.scalar(
                select(RuleRun).where(RuleRun.rule_id == rule.id).order_by(RuleRun.created_at.desc())
            )
            assert run is not None
            assert run.error is not None and "timed out" in run.error
        finally:
            await _cleanup_rule(db, rule.id)
