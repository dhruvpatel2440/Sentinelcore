"""U10 `enqueue()` pipeline tests: preferences, severity gate, suppression,
domain allow-list, dedupe under concurrency, caps, locked-type opt-out
immunity, and digest routing. Requires the real test database (same
convention as test_firewall.py / test_reports.py)."""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import text

from app.core.config import settings
from app.db.session import SessionLocal
from app.email.service import Recipient, enqueue, get_or_create_preferences
from app.email.types import EmailType
from app.models.email import EmailDeliveryMode, EmailOutbox, EmailOutboxStatus
from app.models.event import Severity
from app.models.user import User, UserRole

UTC_NOW_SQL = "now()"


async def _make_user(db, *, email: str, role: UserRole = UserRole.ANALYST) -> User:
    user = User(username=f"u-{uuid.uuid4().hex[:8]}", email=email, password_hash="x", role=role, is_active=True)
    db.add(user)
    await db.flush()
    return user


async def _cleanup(db, user_ids: list[uuid.UUID]) -> None:
    if not user_ids:
        return
    await db.execute(text("DELETE FROM email_outbox WHERE recipient_user_id = ANY(:ids)"), {"ids": user_ids})
    await db.execute(text("DELETE FROM email_preferences WHERE user_id = ANY(:ids)"), {"ids": user_ids})
    await db.execute(text("DELETE FROM users WHERE id = ANY(:ids)"), {"ids": user_ids})
    await db.commit()


@pytest.fixture(autouse=True)
def _dry_run_mode(monkeypatch):
    monkeypatch.setattr(settings, "email_mode", "dry_run")
    settings.__dict__.pop("email_mode_resolved", None)
    yield
    settings.__dict__.pop("email_mode_resolved", None)


@pytest.mark.asyncio
async def test_off_mode_is_a_no_op(monkeypatch):
    monkeypatch.setattr(settings, "email_mode", "off")
    settings.__dict__.pop("email_mode_resolved", None)
    async with SessionLocal() as db:
        rows = await enqueue(
            db, email_type=EmailType.E12_REPORT_READY, recipients=[Recipient(email="a@b.com")],
            heading="h", render_context={},
        )
        assert rows == []
    settings.__dict__.pop("email_mode_resolved", None)


@pytest.mark.asyncio
async def test_severity_gate_blocks_below_preference_floor():
    async with SessionLocal() as db:
        user = await _make_user(db, email=f"{uuid.uuid4().hex}@example.com")
        prefs = await get_or_create_preferences(db, user.id)
        prefs.min_severity = Severity.CRITICAL
        await db.commit()
        try:
            rows = await enqueue(
                db, email_type=EmailType.E01_NEW_INCIDENT, recipients=[Recipient(email=user.email, user_id=user.id)],
                heading="h", render_context={"incident_number": 1, "title": "t", "status": "new", "first_seen": "x",
                                              "last_seen": "y", "src_ip_defanged": None, "target": None,
                                              "event_count": 1, "rule_name": "r", "signatures": []},
                severity=Severity.HIGH,
            )
            assert rows == []
        finally:
            await _cleanup(db, [user.id])


@pytest.mark.asyncio
async def test_disabled_preferences_block_non_locked_type():
    async with SessionLocal() as db:
        user = await _make_user(db, email=f"{uuid.uuid4().hex}@example.com")
        prefs = await get_or_create_preferences(db, user.id)
        prefs.enabled = False
        await db.commit()
        try:
            rows = await enqueue(
                db, email_type=EmailType.E12_REPORT_READY, recipients=[Recipient(email=user.email, user_id=user.id)],
                heading="h", render_context={},
            )
            assert rows == []
        finally:
            await _cleanup(db, [user.id])


@pytest.mark.asyncio
async def test_locked_type_ignores_disabled_preferences():
    async with SessionLocal() as db:
        user = await _make_user(db, email=f"{uuid.uuid4().hex}@example.com")
        prefs = await get_or_create_preferences(db, user.id)
        prefs.enabled = False
        await db.commit()
        try:
            rows = await enqueue(
                db, email_type=EmailType.E19_ACCOUNT_PASSWORD, recipients=[Recipient(email=user.email, user_id=user.id)],
                heading="h", render_context={"display_name": "u", "purpose": "reset", "expiry_minutes": 30},
            )
            assert len(rows) == 1
        finally:
            await _cleanup(db, [user.id])


@pytest.mark.asyncio
async def test_suppressed_recipient_is_dropped():
    async with SessionLocal() as db:
        email = f"{uuid.uuid4().hex}@example.com"
        await db.execute(
            text("INSERT INTO email_suppressions (email, reason) VALUES (:email, 'manual')"), {"email": email}
        )
        await db.commit()
        try:
            rows = await enqueue(
                db, email_type=EmailType.E12_REPORT_READY, recipients=[Recipient(email=email)],
                heading="h", render_context={},
            )
            assert rows == []
        finally:
            await db.execute(text("DELETE FROM email_suppressions WHERE email = :email"), {"email": email})
            await db.commit()


@pytest.mark.asyncio
async def test_domain_allow_list_drops_non_allowed_domains(monkeypatch):
    monkeypatch.setattr(settings, "email_allowed_recipient_domains", "allowed.example")
    settings.__dict__.pop("email_allowed_recipient_domains_parsed", None)
    async with SessionLocal() as db:
        try:
            rows = await enqueue(
                db, email_type=EmailType.E12_REPORT_READY, recipients=[Recipient(email="x@not-allowed.example")],
                heading="h", render_context={},
            )
            assert rows == []
            rows = await enqueue(
                db, email_type=EmailType.E12_REPORT_READY, recipients=[Recipient(email="x@allowed.example")],
                heading="h", render_context={},
            )
            assert len(rows) == 1
        finally:
            await db.execute(text("DELETE FROM email_outbox WHERE recipient_email = 'x@allowed.example'"))
            await db.commit()
            settings.__dict__.pop("email_allowed_recipient_domains_parsed", None)


@pytest.mark.asyncio
async def test_dedupe_key_unique_index_survives_20_concurrent_calls():
    async def _one_call():
        async with SessionLocal() as db:
            return await enqueue(
                db, email_type=EmailType.E12_REPORT_READY, recipients=[Recipient(email="concurrent@example.com")],
                heading="h", render_context={}, dedupe_key=lambda r: "test-concurrent-dedupe-key",
            )

    try:
        results = await asyncio.gather(*[_one_call() for _ in range(20)])
        successful = [r for r in results if r]
        assert len(successful) == 1
    finally:
        async with SessionLocal() as db:
            await db.execute(text("DELETE FROM email_outbox WHERE dedupe_key = 'test-concurrent-dedupe-key'"))
            await db.commit()


@pytest.mark.asyncio
async def test_digest_eligible_type_routes_to_digest_flag_when_user_prefers_digest():
    async with SessionLocal() as db:
        user = await _make_user(db, email=f"{uuid.uuid4().hex}@example.com")
        prefs = await get_or_create_preferences(db, user.id)
        prefs.delivery_mode = EmailDeliveryMode.DIGEST
        await db.commit()
        try:
            rows = await enqueue(
                db, email_type=EmailType.E07_BLOCK_APPLIED, recipients=[Recipient(email=user.email, user_id=user.id)],
                heading="h", render_context={
                    "target": "1.2.3.0/24", "direction": "inbound", "protocol": None, "port": None,
                    "ttl_seconds": 600, "expires_at_utc": "x", "expires_at_local": "y", "requester": "bob",
                    "incident_number": None,
                },
            )
            assert len(rows) == 1
            assert rows[0].digest is True
            assert rows[0].status == EmailOutboxStatus.DRY_RUN
        finally:
            await _cleanup(db, [user.id])


@pytest.mark.asyncio
async def test_never_digested_type_ignores_digest_preference():
    async with SessionLocal() as db:
        user = await _make_user(db, email=f"{uuid.uuid4().hex}@example.com")
        prefs = await get_or_create_preferences(db, user.id)
        prefs.delivery_mode = EmailDeliveryMode.DIGEST
        await db.commit()
        try:
            rows = await enqueue(
                db, email_type=EmailType.E19_ACCOUNT_PASSWORD, recipients=[Recipient(email=user.email, user_id=user.id)],
                heading="h", render_context={"display_name": "u", "purpose": "reset", "expiry_minutes": 30},
            )
            assert len(rows) == 1
            assert rows[0].digest is False
        finally:
            await _cleanup(db, [user.id])
