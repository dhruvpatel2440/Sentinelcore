"""U10 BrevoClient tests. Uses `httpx.MockTransport` — the real Brevo API is
never called from automated tests. No DB required."""

from __future__ import annotations

import uuid

import httpx
import pytest

from app.core.config import settings
from app.email.client import BrevoClient, BrevoFatalError, BrevoRetryableError, CircuitBreaker


@pytest.fixture(autouse=True)
def _brevo_settings(monkeypatch):
    monkeypatch.setattr(settings, "brevo_api_key", "test-secret-key-do-not-log")
    monkeypatch.setattr(settings, "email_sender_address", "alerts@sentinel.lab")
    monkeypatch.setattr(settings, "email_sender_name", "SentinelCore")


def _client_with(handler) -> BrevoClient:
    return BrevoClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_success_stores_message_id():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"messageId": "abc-123"})

    client = _client_with(handler)
    result = await client.send(
        outbox_id=uuid.uuid4(), email_type="E01", recipient_email="a@b.com",
        subject="s", html_body="<p>h</p>", text_body="h",
    )
    assert result.provider_message_id == "abc-123"


@pytest.mark.asyncio
async def test_idempotency_key_carries_outbox_id():
    import json as _json

    outbox_id = uuid.uuid4()
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = _json.loads(request.content)
        seen["idempotency_key"] = body.get("headers", {}).get("Idempotency-Key")
        seen["api_key"] = request.headers.get("api-key")
        return httpx.Response(201, json={"messageId": "x"})

    client = _client_with(handler)
    await client.send(
        outbox_id=outbox_id, email_type="E01", recipient_email="a@b.com",
        subject="s", html_body="<p>h</p>", text_body="h",
    )
    assert seen["idempotency_key"] == str(outbox_id)
    assert seen["api_key"] == "test-secret-key-do-not-log"


@pytest.mark.asyncio
async def test_429_with_retry_after_is_retryable_and_reschedules():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "42"})

    client = _client_with(handler)
    with pytest.raises(BrevoRetryableError) as exc_info:
        await client.send(
            outbox_id=uuid.uuid4(), email_type="E01", recipient_email="a@b.com",
            subject="s", html_body="h", text_body="h",
        )
    assert exc_info.value.retry_after_seconds == 42.0


@pytest.mark.asyncio
async def test_5xx_is_retryable():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client = _client_with(handler)
    with pytest.raises(BrevoRetryableError):
        await client.send(
            outbox_id=uuid.uuid4(), email_type="E01", recipient_email="a@b.com",
            subject="s", html_body="h", text_body="h",
        )


@pytest.mark.asyncio
async def test_400_fails_immediately_without_retry():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"message": "bad request"})

    client = _client_with(handler)
    with pytest.raises(BrevoFatalError):
        await client.send(
            outbox_id=uuid.uuid4(), email_type="E01", recipient_email="a@b.com",
            subject="s", html_body="h", text_body="h",
        )


@pytest.mark.asyncio
async def test_401_fails_immediately_and_trips_circuit_breaker(monkeypatch):
    import app.email.client as client_module

    fresh_breaker = CircuitBreaker()
    monkeypatch.setattr(client_module, "circuit_breaker", fresh_breaker)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "unauthorized"})

    client = _client_with(handler)
    with pytest.raises(BrevoFatalError):
        await client.send(
            outbox_id=uuid.uuid4(), email_type="E01", recipient_email="a@b.com",
            subject="s", html_body="h", text_body="h",
        )
    assert fresh_breaker.is_open()


@pytest.mark.asyncio
async def test_timeout_is_retryable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("boom")

    client = _client_with(handler)
    with pytest.raises(BrevoRetryableError):
        await client.send(
            outbox_id=uuid.uuid4(), email_type="E01", recipient_email="a@b.com",
            subject="s", html_body="h", text_body="h",
        )


@pytest.mark.asyncio
async def test_api_key_never_appears_in_error_message():
    def handler(request: httpx.Request) -> httpx.Response:
        # Simulate a provider error message that happened to echo the key back.
        return httpx.Response(500, text=f"upstream rejected key {settings.brevo_api_key}")

    client = _client_with(handler)
    with pytest.raises(BrevoRetryableError) as exc_info:
        await client.send(
            outbox_id=uuid.uuid4(), email_type="E01", recipient_email="a@b.com",
            subject="s", html_body="h", text_body="h",
        )
    assert settings.brevo_api_key not in str(exc_info.value)


def test_circuit_breaker_alerts_once_per_trip():
    breaker = CircuitBreaker()
    breaker.trip()
    assert breaker.is_open()
    assert breaker.should_alert() is True
    assert breaker.should_alert() is False
