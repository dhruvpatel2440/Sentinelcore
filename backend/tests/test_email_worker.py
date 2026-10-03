"""U10 worker tests: the stuck-row reaper, `SKIP LOCKED` double-pickup
prevention across two concurrent "workers", and dry-run never invoking the
Brevo client. Requires the real test database."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text

from app.core.config import settings
from app.db.session import SessionLocal
from app.email.client import BrevoClient
from app.email.service import Recipient, enqueue
from app.email.types import EmailType
from app.email.worker import drain_once, reap_stuck
from app.models.email import EmailOutbox, EmailOutboxStatus

UTC = timezone.utc


async def _cleanup(email: str) -> None:
    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM email_outbox WHERE recipient_email = :e"), {"e": email})
        await db.commit()


@pytest.mark.asyncio
async def test_reaper_resets_rows_stuck_in_sending():
    email = f"stuck-{uuid.uuid4().hex}@example.com"
    try:
        async with SessionLocal() as db:
            row = EmailOutbox(
                id=uuid.uuid4(), email_type=EmailType.E12_REPORT_READY, recipient_email=email,
                subject="s", html_body="h", text_body="h", status=EmailOutboxStatus.SENDING,
                created_at=datetime.now(UTC) - timedelta(minutes=settings.email_outbox_reaper_stuck_minutes + 1),
            )
            db.add(row)
            await db.commit()

        reaped = await reap_stuck(SessionLocal)
        assert reaped >= 1

        async with SessionLocal() as db:
            fresh = await db.get(EmailOutbox, row.id)
            assert fresh.status == EmailOutboxStatus.QUEUED
    finally:
        await _cleanup(email)


@pytest.mark.asyncio
async def test_recently_sending_row_is_not_reaped():
    email = f"fresh-{uuid.uuid4().hex}@example.com"
    try:
        async with SessionLocal() as db:
            row = EmailOutbox(
                id=uuid.uuid4(), email_type=EmailType.E12_REPORT_READY, recipient_email=email,
                subject="s", html_body="h", text_body="h", status=EmailOutboxStatus.SENDING,
                created_at=datetime.now(UTC),
            )
            db.add(row)
            await db.commit()

        await reap_stuck(SessionLocal)

        async with SessionLocal() as db:
            fresh = await db.get(EmailOutbox, row.id)
            assert fresh.status == EmailOutboxStatus.SENDING
    finally:
        await _cleanup(email)


@pytest.mark.asyncio
async def test_skip_locked_prevents_double_pickup_by_two_drain_passes():
    email = f"skiplocked-{uuid.uuid4().hex}@example.com"
    calls: list[str] = []

    class _RecordingClient(BrevoClient):
        async def send(self, **kwargs):
            calls.append(kwargs["recipient_email"])
            from app.email.client import SendResult

            return SendResult(provider_message_id="fake-id")

    try:
        async with SessionLocal() as db:
            await enqueue(
                db, email_type=EmailType.E12_REPORT_READY, recipients=[Recipient(email=email)],
                heading="h", render_context={},
            )
            # enqueue() in `dry_run`/`off` mode would not leave a `queued`
            # row — force it explicitly so this test exercises the drain
            # path regardless of the configured EMAIL_MODE.
            row = (await db.execute(select(EmailOutbox).where(EmailOutbox.recipient_email == email))).scalar_one()
            row.status = EmailOutboxStatus.QUEUED
            await db.commit()

        import asyncio

        client_a, client_b = _RecordingClient(), _RecordingClient()
        results = await asyncio.gather(
            drain_once(SessionLocal, client_a),
            drain_once(SessionLocal, client_b),
        )
        assert sum(results) == 1
        assert calls.count(email) == 1
    finally:
        await _cleanup(email)


@pytest.mark.asyncio
async def test_dry_run_never_calls_the_brevo_client(monkeypatch):
    monkeypatch.setattr(settings, "email_mode", "dry_run")
    settings.__dict__.pop("email_mode_resolved", None)
    email = f"dryrun-{uuid.uuid4().hex}@example.com"

    called = False

    class _AssertNeverCalled(BrevoClient):
        async def send(self, **kwargs):
            nonlocal called
            called = True
            raise AssertionError("dry_run must never call Brevo")

    try:
        async with SessionLocal() as db:
            rows = await enqueue(
                db, email_type=EmailType.E12_REPORT_READY, recipients=[Recipient(email=email)],
                heading="h", render_context={},
            )
            assert len(rows) == 1
            assert rows[0].status == EmailOutboxStatus.DRY_RUN

        sent = await drain_once(SessionLocal, _AssertNeverCalled())
        assert sent == 0
        assert called is False
    finally:
        settings.__dict__.pop("email_mode_resolved", None)
        await _cleanup(email)
