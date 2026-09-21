"""M8 incident management tests: state machine matrix, merge-window
promotion logic, append-only history trigger, optimistic concurrency.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.api.routes.incidents import _check_version
from app.db.session import SessionLocal
from app.models.correlation import CandidateStatus, CorrelationRule, IncidentCandidate, RuleType
from app.models.event import Severity
from app.models.incident import HistoryAction, Incident, IncidentHistory, IncidentStatus
from app.services.incident_state import (
    FORWARD_TRANSITIONS,
    IllegalTransition,
    ReopenRequiresAdmin,
    can_assign,
    is_forward_move_from_new,
    is_reopen,
    requires_resolution_note,
    validate_transition,
)
from app.services.promotion import _find_mergeable_incident, _group_field, promote_candidate

UTC = timezone.utc
ALL_STATUSES = list(IncidentStatus)


# ---------------------------------------------------------------------------
# State machine transition matrix
# ---------------------------------------------------------------------------


LEGAL_FORWARD = {
    (IncidentStatus.NEW, IncidentStatus.TRIAGE),
    (IncidentStatus.NEW, IncidentStatus.FALSE_POSITIVE),
    (IncidentStatus.TRIAGE, IncidentStatus.INVESTIGATING),
    (IncidentStatus.TRIAGE, IncidentStatus.FALSE_POSITIVE),
    (IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED),
    (IncidentStatus.INVESTIGATING, IncidentStatus.FALSE_POSITIVE),
    (IncidentStatus.CONTAINED, IncidentStatus.RESOLVED),
    (IncidentStatus.CONTAINED, IncidentStatus.FALSE_POSITIVE),
}
LEGAL_REOPEN = {
    (IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING),
    (IncidentStatus.FALSE_POSITIVE, IncidentStatus.INVESTIGATING),
}


@pytest.mark.parametrize("current", ALL_STATUSES)
@pytest.mark.parametrize("target", ALL_STATUSES)
def test_transition_matrix_matches_spec_exactly(current, target):
    legal = (current, target) in LEGAL_FORWARD or (current, target) in LEGAL_REOPEN
    is_admin_only_reopen = (current, target) in LEGAL_REOPEN

    if not legal:
        with pytest.raises((IllegalTransition, ReopenRequiresAdmin)):
            validate_transition(current, target, is_admin=False)
        return

    if is_admin_only_reopen:
        with pytest.raises(ReopenRequiresAdmin):
            validate_transition(current, target, is_admin=False)
        validate_transition(current, target, is_admin=True)  # must not raise
    else:
        validate_transition(current, target, is_admin=False)  # must not raise
        validate_transition(current, target, is_admin=True)


def test_every_status_has_a_false_positive_escape_except_terminal_states():
    for s in (IncidentStatus.NEW, IncidentStatus.TRIAGE, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED):
        assert IncidentStatus.FALSE_POSITIVE in FORWARD_TRANSITIONS[s]


def test_illegal_direct_jump_new_to_resolved():
    with pytest.raises(IllegalTransition) as exc:
        validate_transition(IncidentStatus.NEW, IncidentStatus.RESOLVED, is_admin=True)
    assert exc.value.current == IncidentStatus.NEW
    assert exc.value.target == IncidentStatus.RESOLVED


def test_same_status_is_illegal():
    with pytest.raises(IllegalTransition):
        validate_transition(IncidentStatus.TRIAGE, IncidentStatus.TRIAGE, is_admin=True)


def test_requires_resolution_note_only_for_terminal_states():
    assert requires_resolution_note(IncidentStatus.RESOLVED) is True
    assert requires_resolution_note(IncidentStatus.FALSE_POSITIVE) is True
    assert requires_resolution_note(IncidentStatus.TRIAGE) is False
    assert requires_resolution_note(IncidentStatus.NEW) is False


def test_forward_move_from_new_flags_acknowledgement():
    assert is_forward_move_from_new(IncidentStatus.NEW, IncidentStatus.TRIAGE) is True
    assert is_forward_move_from_new(IncidentStatus.NEW, IncidentStatus.FALSE_POSITIVE) is True
    assert is_forward_move_from_new(IncidentStatus.TRIAGE, IncidentStatus.INVESTIGATING) is False


def test_is_reopen_detection():
    assert is_reopen(IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING) is True
    assert is_reopen(IncidentStatus.FALSE_POSITIVE, IncidentStatus.INVESTIGATING) is True
    assert is_reopen(IncidentStatus.NEW, IncidentStatus.INVESTIGATING) is False
    assert is_reopen(IncidentStatus.RESOLVED, IncidentStatus.TRIAGE) is False


# ---------------------------------------------------------------------------
# Assignment RBAC logic
# ---------------------------------------------------------------------------


def test_analyst_can_self_assign():
    me = uuid.uuid4()
    assert can_assign(is_admin=False, actor_id=me, target_user_id=me, current_assignee=None) is True


def test_analyst_can_unassign_own_incident():
    me = uuid.uuid4()
    assert can_assign(is_admin=False, actor_id=me, target_user_id=None, current_assignee=me) is True


def test_analyst_cannot_take_someone_elses_incident():
    me, other = uuid.uuid4(), uuid.uuid4()
    assert can_assign(is_admin=False, actor_id=me, target_user_id=me, current_assignee=other) is True
    # ^ self-assign is always allowed regardless of current assignee — the
    # restriction is on touching *another user's* assignment, e.g.:
    assert can_assign(is_admin=False, actor_id=me, target_user_id=other, current_assignee=None) is False


def test_analyst_cannot_unassign_someone_elses_incident():
    me, other = uuid.uuid4(), uuid.uuid4()
    assert can_assign(is_admin=False, actor_id=me, target_user_id=None, current_assignee=other) is False


def test_admin_can_do_anything():
    me, other = uuid.uuid4(), uuid.uuid4()
    assert can_assign(is_admin=True, actor_id=me, target_user_id=other, current_assignee=other) is True
    assert can_assign(is_admin=True, actor_id=me, target_user_id=None, current_assignee=other) is True


# ---------------------------------------------------------------------------
# Optimistic concurrency
# ---------------------------------------------------------------------------


def test_check_version_passes_on_match():
    incident = Incident(title="t", severity=Severity.HIGH, version=3)
    _check_version(incident, 3)  # must not raise


def test_check_version_raises_409_on_mismatch():
    incident = Incident(title="t", severity=Severity.HIGH, version=3)
    with pytest.raises(HTTPException) as exc:
        _check_version(incident, 2)
    assert exc.value.status_code == 409


# ---------------------------------------------------------------------------
# Promotion: merge-window logic (real DB, tagged + cleaned up)
# ---------------------------------------------------------------------------


def _rule(**overrides) -> CorrelationRule:
    defaults = dict(
        id=uuid.uuid4(), name=f"m8-test-{uuid.uuid4().hex[:8]}", description="d", enabled=True,
        rule_type=RuleType.THRESHOLD, match={}, group_by=["src_ip"], window_seconds=300,
        threshold=1, severity=Severity.HIGH, dedup_window_seconds=3600, params={},
    )
    defaults.update(overrides)
    return CorrelationRule(**defaults)


def _candidate(rule_id, group_key, score, ts, **overrides) -> IncidentCandidate:
    defaults = dict(
        id=uuid.uuid4(), rule_id=rule_id, group_key=group_key, first_event_ts=ts, last_event_ts=ts,
        event_count=10, severity=Severity.HIGH, score=score, summary="s",
        evidence={"event_ids_first": [1, 2, 3], "event_ids_last": [1, 2, 3], "total_matched": 3},
        status=CandidateStatus.NEW,
    )
    defaults.update(overrides)
    return IncidentCandidate(**defaults)


async def _cleanup(db, rule_id) -> None:
    """`incident_history` is append-only by database trigger — even a
    cascading DELETE off `incidents` hits it and is rejected, which is the
    whole point of the feature under test. So fixtures never delete
    incidents or their history, only the correlation_rules/incident_candidates
    rows a test created directly; ON DELETE SET NULL detaches any promoted
    incident from the deleted rule and it is simply left behind, uniquely
    tagged and harmless."""
    await db.execute(text("DELETE FROM incident_candidates WHERE rule_id = :r"), {"r": rule_id})
    await db.execute(text("DELETE FROM correlation_rules WHERE id = :r"), {"r": rule_id})
    await db.commit()


def test_group_field_parses_group_key():
    assert _group_field("src_ip=10.0.0.1|dst_port=22", "src_ip") == "10.0.0.1"
    assert _group_field("src_ip=10.0.0.1|dst_port=22", "dst_port") == "22"
    assert _group_field("src_ip=10.0.0.1", "dst_ip") is None
    assert _group_field("src_ip=None", "src_ip") is None


@pytest.mark.asyncio
async def test_low_score_candidate_is_not_auto_promoted():
    async with SessionLocal() as db:
        rule = _rule()
        db.add(rule)
        await db.commit()
        try:
            candidate = _candidate(rule.id, "src_ip=10.0.0.1", score=10, ts=datetime.now(UTC))  # below auto-promote
            db.add(candidate)
            await db.commit()

            await promote_candidate(candidate.id, SessionLocal)

            await db.refresh(candidate)
            assert candidate.status == CandidateStatus.NEW
            assert candidate.incident_id is None
        finally:
            await _cleanup(db, rule.id)


@pytest.mark.asyncio
async def test_high_score_candidate_creates_incident_with_events_linked():
    async with SessionLocal() as db:
        rule = _rule()
        db.add(rule)
        await db.commit()
        try:
            candidate = _candidate(rule.id, "src_ip=10.0.0.2", score=95, ts=datetime.now(UTC))
            db.add(candidate)
            await db.commit()

            await promote_candidate(candidate.id, SessionLocal)

            await db.refresh(candidate)
            assert candidate.status == CandidateStatus.PROMOTED
            assert candidate.incident_id is not None

            incident = await db.get(Incident, candidate.incident_id)
            assert incident.title == f"{rule.name} from 10.0.0.2"
            assert incident.status == IncidentStatus.NEW

            history = (
                await db.execute(text("SELECT action FROM incident_history WHERE incident_id = :i"), {"i": incident.id})
            ).scalar()
            assert history == "created"

            linked = (
                await db.execute(text("SELECT count(*) FROM incident_events WHERE incident_id = :i"), {"i": incident.id})
            ).scalar()
            assert linked == 3
        finally:
            await _cleanup(db, rule.id)


@pytest.mark.asyncio
async def test_second_candidate_same_rule_and_source_merges_within_window():
    async with SessionLocal() as db:
        rule = _rule()
        db.add(rule)
        await db.commit()
        try:
            now = datetime.now(UTC)
            c1 = _candidate(rule.id, "src_ip=10.0.0.3", score=90, ts=now - timedelta(minutes=30))
            db.add(c1)
            await db.commit()
            await promote_candidate(c1.id, SessionLocal)
            await db.refresh(c1)
            first_incident_id = c1.incident_id
            assert first_incident_id is not None

            c2 = _candidate(rule.id, "src_ip=10.0.0.3", score=90, ts=now, first_event_ts=now, last_event_ts=now)
            db.add(c2)
            await db.commit()
            await promote_candidate(c2.id, SessionLocal)
            await db.refresh(c2)

            assert c2.incident_id == first_incident_id  # merged, not a new incident

            incident_count = (
                await db.execute(text("SELECT count(*) FROM incidents WHERE rule_id = :r"), {"r": rule.id})
            ).scalar()
            assert incident_count == 1

            incident = await db.get(Incident, first_incident_id)
            assert incident.event_count == c1.event_count + c2.event_count
        finally:
            await _cleanup(db, rule.id)


@pytest.mark.asyncio
async def test_candidate_outside_merge_window_creates_a_new_incident(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "incident_merge_window_minutes", 5)

    async with SessionLocal() as db:
        rule = _rule()
        db.add(rule)
        await db.commit()
        try:
            now = datetime.now(UTC)
            c1 = _candidate(rule.id, "src_ip=10.0.0.4", score=90, ts=now - timedelta(hours=2))
            db.add(c1)
            await db.commit()
            await promote_candidate(c1.id, SessionLocal)
            await db.refresh(c1)

            c2 = _candidate(rule.id, "src_ip=10.0.0.4", score=90, ts=now, first_event_ts=now, last_event_ts=now)
            db.add(c2)
            await db.commit()
            await promote_candidate(c2.id, SessionLocal)
            await db.refresh(c2)

            assert c2.incident_id != c1.incident_id

            incident_count = (
                await db.execute(text("SELECT count(*) FROM incidents WHERE rule_id = :r"), {"r": rule.id})
            ).scalar()
            assert incident_count == 2
        finally:
            await _cleanup(db, rule.id)


@pytest.mark.asyncio
async def test_find_mergeable_incident_ignores_terminal_incidents():
    async with SessionLocal() as db:
        rule = _rule()
        db.add(rule)
        await db.commit()
        try:
            now = datetime.now(UTC)
            closed = Incident(
                title="closed one", severity=Severity.HIGH, status=IncidentStatus.RESOLVED,
                rule_id=rule.id, src_ip="10.0.0.5", last_event_ts=now, resolution_note="done",
            )
            db.add(closed)
            await db.commit()

            found = await _find_mergeable_incident(db, rule.id, "10.0.0.5", now)
            assert found is None  # a resolved incident is not a merge target
        finally:
            await _cleanup(db, rule.id)


# ---------------------------------------------------------------------------
# Append-only incident_history trigger
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_history_update_is_rejected_by_db_trigger():
    """Never commits: the incident/history rows are only flushed, so a
    single final rollback discards them — no cleanup DELETE is needed (and
    none would work: deleting incident_history is exactly what this test
    proves the trigger rejects)."""
    async with SessionLocal() as db:
        incident = Incident(title="trigger-test", severity=Severity.HIGH)
        db.add(incident)
        await db.flush()
        entry = IncidentHistory(incident_id=incident.id, action=HistoryAction.CREATED)
        db.add(entry)
        await db.flush()
        entry_id = entry.id

        with pytest.raises(DBAPIError, match="append-only"):
            await db.execute(text("UPDATE incident_history SET note = 'edited' WHERE id = :id"), {"id": entry_id})
        await db.rollback()


@pytest.mark.asyncio
async def test_history_delete_is_rejected_by_db_trigger():
    async with SessionLocal() as db:
        incident = Incident(title="trigger-test-2", severity=Severity.HIGH)
        db.add(incident)
        await db.flush()
        entry = IncidentHistory(incident_id=incident.id, action=HistoryAction.CREATED)
        db.add(entry)
        await db.flush()
        entry_id = entry.id

        with pytest.raises(DBAPIError, match="append-only"):
            await db.execute(text("DELETE FROM incident_history WHERE id = :id"), {"id": entry_id})
        await db.rollback()
