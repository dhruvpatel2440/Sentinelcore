"""U10 Brevo webhook: wrong secret -> 401, valid bounce -> suppression
inserted, replay is idempotent, malformed payload -> 422. Requires the real
test database and FastAPI TestClient."""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models.email import EmailOutbox, EmailOutboxStatus, EmailSuppression
from app.models.event import Severity  # noqa: F401 — ensures models import before TestClient build

client = TestClient(app)


@pytest.fixture(autouse=True)
def _webhook_secret(monkeypatch):
    monkeypatch.setattr(settings, "brevo_webhook_secret", "test-webhook-shared-secret")


def _post(payload: dict, *, secret: str | None = "test-webhook-shared-secret") -> "Response":
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    return client.post("/api/webhooks/brevo", content=json.dumps(payload), headers=headers)


def test_wrong_secret_is_rejected():
    response = _post({"event": "delivered", "message-id": "x"}, secret="wrong-secret")
    assert response.status_code == 401


def test_missing_secret_is_rejected():
    response = _post({"event": "delivered", "message-id": "x"}, secret=None)
    assert response.status_code == 401


def test_malformed_payload_is_422_not_server_error():
    headers = {"Authorization": "Bearer test-webhook-shared-secret"}
    response = client.post("/api/webhooks/brevo", content="not json at all", headers=headers)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_valid_hard_bounce_inserts_suppression_and_is_idempotent_on_replay():
    email = f"bounce-{uuid.uuid4().hex}@example.com"
    message_id = f"msg-{uuid.uuid4().hex}"
    try:
        async with SessionLocal() as db:
            row = EmailOutbox(
                id=uuid.uuid4(), email_type="E12", recipient_email=email, subject="s", html_body="h",
                text_body="h", status=EmailOutboxStatus.SENT, provider_message_id=message_id,
            )
            db.add(row)
            await db.commit()

        payload = {"event": "hard_bounce", "message-id": message_id, "email": email, "reason": "mailbox full"}
        first = _post(payload)
        assert first.status_code == 200

        async with SessionLocal() as db:
            suppressed = (
                await db.execute(select(EmailSuppression).where(EmailSuppression.email == email))
            ).scalar_one_or_none()
            assert suppressed is not None
            assert suppressed.reason.value == "hard_bounce"

        # Replay the identical event — must not raise, must not duplicate.
        second = _post(payload)
        assert second.status_code == 200

        async with SessionLocal() as db:
            n = (
                await db.execute(text("SELECT count(*) FROM email_suppressions WHERE email = :e"), {"e": email})
            ).scalar_one()
            assert n == 1
    finally:
        async with SessionLocal() as db:
            await db.execute(text("DELETE FROM email_suppressions WHERE email = :e"), {"e": email})
            await db.execute(text("DELETE FROM email_outbox WHERE recipient_email = :e"), {"e": email})
            await db.commit()
