"""M9 reporting tests: per-type param validation, build() against seeded
fixture data, path-traversal containment on download, RBAC, and relative
window resolution for schedules.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import text

from app.api.routes.reports import _get_owned_report
from app.core.config import settings
from app.db.session import SessionLocal
from app.models.incident import Incident, IncidentStatus
from app.models.report import Report, ReportFormat, ReportStatus, ReportType
from app.models.user import User, UserRole
from app.reports.generator import resolve_report_path
from app.reports.scheduling import RELATIVE_WINDOWS, resolve_relative_window
from app.reports.types import asset_inventory, event_statistics, incident_summary
from app.schemas.report import (
    AssetInventoryParams,
    EventStatisticsParams,
    IncidentDetailParams,
    IncidentSummaryParams,
    validate_report_params,
)

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Per-type param validation
# ---------------------------------------------------------------------------


def test_incident_summary_params_require_from_and_to():
    with pytest.raises(ValidationError):
        IncidentSummaryParams.model_validate({})
    p = IncidentSummaryParams.model_validate({"from": "2026-01-01T00:00:00Z", "to": "2026-01-02T00:00:00Z"})
    assert p.severity == []


def test_incident_detail_params_require_incident_id():
    with pytest.raises(ValidationError):
        IncidentDetailParams.model_validate({})
    p = IncidentDetailParams.model_validate({"incident_id": str(uuid.uuid4())})
    assert isinstance(p.incident_id, uuid.UUID)


def test_asset_inventory_params_are_all_optional():
    p = AssetInventoryParams.model_validate({})
    assert p.is_active is None and p.cidr is None


def test_event_statistics_params_require_from_and_to():
    with pytest.raises(ValidationError):
        EventStatisticsParams.model_validate({"severity": ["high"]})


def test_validate_report_params_dispatches_by_type():
    out = validate_report_params(ReportType.ASSET_INVENTORY, {"is_active": True})
    assert out["is_active"] is True
    with pytest.raises(ValidationError):
        validate_report_params(ReportType.INCIDENT_DETAIL, {})


# ---------------------------------------------------------------------------
# build() against seeded fixture data
# ---------------------------------------------------------------------------


async def _cleanup_incidents(db, ids) -> None:
    for iid in ids:
        await db.execute(text("DELETE FROM incident_events WHERE incident_id = :i"), {"i": iid})
        # incident_history is append-only — left in place by design, as in test_incidents.py.
    await db.execute(text("DELETE FROM incidents WHERE id = ANY(:ids)"), {"ids": ids})
    await db.commit()


@pytest.mark.asyncio
async def test_incident_summary_build_matches_hand_calculated_aggregates():
    async with SessionLocal() as db:
        # Fixed far-future anchor, not datetime.now(): incidents created by other
        # tests in the suite land near "now" and would otherwise pollute the
        # exact-count assertions below.
        now = datetime(2099, 6, 15, tzinfo=UTC)
        tag = uuid.uuid4().hex[:8]
        incidents = [
            Incident(title=f"m9-{tag}-1", severity="critical", status=IncidentStatus.RESOLVED, opened_at=now - timedelta(hours=2), acknowledged_at=now - timedelta(hours=1, minutes=50), closed_at=now - timedelta(hours=1), resolution_note="n"),
            Incident(title=f"m9-{tag}-2", severity="high", status=IncidentStatus.NEW, opened_at=now - timedelta(hours=1)),
            Incident(title=f"m9-{tag}-3", severity="high", status=IncidentStatus.NEW, opened_at=now - timedelta(minutes=30)),
        ]
        for inc in incidents:
            db.add(inc)
        await db.commit()
        ids = [inc.id for inc in incidents]

        try:
            data = await incident_summary.build(
                {"from": (now - timedelta(hours=3)).isoformat(), "to": (now + timedelta(minutes=1)).isoformat()}, db
            )
            assert data["total_incidents"] == 3
            assert data["totals_by_severity"] == {"critical": 1, "high": 2}
            assert data["totals_by_status"] == {"resolved": 1, "new": 2}
            # one incident acknowledged after 600s, one resolved after 3600s
            assert data["mtta_seconds"] == pytest.approx(600, abs=1)
            assert data["mttr_seconds"] == pytest.approx(3600, abs=1)
            assert len(data["table"]) == 3
        finally:
            await _cleanup_incidents(db, ids)


@pytest.mark.asyncio
async def test_asset_inventory_build_flags_stale_and_high_risk(monkeypatch):
    from app.models.asset import Asset, AssetPort, PortState, Protocol

    async with SessionLocal() as db:
        now = datetime.now(UTC)
        tag = uuid.uuid4().hex[:6]
        fresh = Asset(ip_address=f"10.77.{ord(tag[0]) % 200}.1", hostname="fresh-host", last_seen=now, first_seen=now)
        stale = Asset(ip_address=f"10.77.{ord(tag[0]) % 200}.2", hostname="stale-host", last_seen=now - timedelta(days=40), first_seen=now - timedelta(days=50))
        db.add_all([fresh, stale])
        await db.flush()
        db.add(AssetPort(asset_id=stale.id, port=3389, protocol=Protocol.TCP, state=PortState.OPEN))
        await db.commit()
        ids = [fresh.id, stale.id]

        try:
            data = await asset_inventory.build({}, db)
            table = {r["hostname"]: r for r in data["table"] if r["hostname"] in ("fresh-host", "stale-host")}
            assert table["fresh-host"]["is_stale"] is False
            assert table["stale-host"]["is_stale"] is True
            assert table["stale-host"]["high_risk_ports"] == [3389]
        finally:
            await db.execute(text("DELETE FROM asset_ports WHERE asset_id = ANY(:ids)"), {"ids": ids})
            await db.execute(text("DELETE FROM assets WHERE id = ANY(:ids)"), {"ids": ids})
            await db.commit()


@pytest.mark.asyncio
async def test_event_statistics_build_counts_match_seeded_events():
    async with SessionLocal() as db:
        now = datetime.now(UTC)
        category = f"m9-test-{uuid.uuid4().hex[:10]}"
        rows = []
        for i in range(5):
            dedup = hashlib.sha256(f"{category}-{i}".encode()).digest()
            rows.append(
                {
                    "ts": now - timedelta(minutes=i), "event_type": "alert", "src_ip": "10.9.9.9",
                    "dst_ip": "10.9.9.10", "src_port": None, "dst_port": None, "proto": "tcp",
                    "signature": "m9 sig", "signature_id": 9400000, "rev": 1, "category": category,
                    "severity": "high", "flow_id": None, "dedup_key": dedup, "raw": "{}",
                }
            )
        for r in rows:
            await db.execute(
                text(
                    """
                    INSERT INTO events (ts, event_type, src_ip, dst_ip, src_port, dst_port, proto,
                        signature, signature_id, rev, category, severity, flow_id, dedup_key, raw)
                    VALUES (:ts, :event_type, :src_ip, :dst_ip, :src_port, :dst_port, :proto,
                        :signature, :signature_id, :rev, :category, :severity, :flow_id, :dedup_key, :raw)
                    """
                ),
                r,
            )
        await db.commit()

        try:
            data = await event_statistics.build(
                {
                    "from": (now - timedelta(hours=1)).isoformat(), "to": (now + timedelta(minutes=1)).isoformat(),
                },
                db,
            )
            # can't isolate to just our category without a match filter in this
            # builder, so assert our signature shows up with the right count
            sig_row = next((s for s in data["top_signatures"] if s["signature"] == "m9 sig"), None)
            assert sig_row is not None
            assert sig_row["count"] == 5
        finally:
            await db.execute(text("DELETE FROM events WHERE category = :c"), {"c": category})
            await db.commit()


# ---------------------------------------------------------------------------
# Path containment on download
# ---------------------------------------------------------------------------


def test_resolve_report_path_stays_under_storage_root():
    report_id = uuid.uuid4()
    path = resolve_report_path(report_id, ReportFormat.PDF)
    root = Path(settings.report_storage_path).resolve()
    assert root in path.resolve().parents
    assert path.name == f"{report_id}.pdf"


def test_resolve_report_path_ignores_any_client_supplied_value():
    """The path is built entirely from a UUID and a fixed extension map —
    there is no code path that joins a user-supplied string into it."""
    report_id = uuid.uuid4()
    path = resolve_report_path(report_id, ReportFormat.CSV)
    assert "../" not in str(path)
    assert str(path).endswith(f"{report_id}.csv")


# ---------------------------------------------------------------------------
# RBAC on report access
# ---------------------------------------------------------------------------


class _FakeDB:
    def __init__(self, report):
        self._report = report

    async def get(self, model, id_):
        if self._report is not None and self._report.id == id_:
            return self._report
        return None


def _user(role=UserRole.ANALYST):
    u = User(username="u", password_hash="x", role=role, is_active=True)
    u.id = uuid.uuid4()
    return u


def _report(owner_id):
    r = Report(report_type=ReportType.EVENT_STATISTICS, title="t", params={}, format=ReportFormat.PDF, requested_by=owner_id)
    r.id = uuid.uuid4()
    r.status = ReportStatus.COMPLETED
    return r


@pytest.mark.asyncio
async def test_owner_can_access_own_report():
    owner = _user()
    report = _report(owner.id)
    result = await _get_owned_report(_FakeDB(report), report.id, owner)
    assert result is report


@pytest.mark.asyncio
async def test_non_owner_analyst_gets_403():
    owner, other = _user(), _user()
    report = _report(owner.id)
    with pytest.raises(HTTPException) as exc:
        await _get_owned_report(_FakeDB(report), report.id, other)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_access_any_report():
    owner = _user()
    admin = _user(role=UserRole.ADMIN)
    report = _report(owner.id)
    result = await _get_owned_report(_FakeDB(report), report.id, admin)
    assert result is report


@pytest.mark.asyncio
async def test_missing_report_is_404():
    user = _user()
    with pytest.raises(HTTPException) as exc:
        await _get_owned_report(_FakeDB(None), uuid.uuid4(), user)
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# Relative window resolution
# ---------------------------------------------------------------------------


def test_resolve_relative_window_computes_absolute_dates():
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    resolved = resolve_relative_window({"window": "last_7_days"}, now)
    assert resolved["to"] == now.isoformat()
    assert datetime.fromisoformat(resolved["from"]) == now - RELATIVE_WINDOWS["last_7_days"]


def test_resolve_relative_window_passes_through_params_without_window_key():
    params = {"incident_id": "abc"}
    assert resolve_relative_window(params, datetime.now(UTC)) == params


def test_two_runs_a_week_apart_produce_different_correct_windows():
    run1 = datetime(2026, 6, 1, tzinfo=UTC)
    run2 = datetime(2026, 6, 8, tzinfo=UTC)
    r1 = resolve_relative_window({"window": "last_7_days"}, run1)
    r2 = resolve_relative_window({"window": "last_7_days"}, run2)
    assert r1["to"] != r2["to"]
    assert datetime.fromisoformat(r1["from"]) == run1 - timedelta(days=7)
    assert datetime.fromisoformat(r2["from"]) == run2 - timedelta(days=7)
