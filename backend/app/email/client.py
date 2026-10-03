"""Brevo transactional email HTTP client.

Outbound HTTPS only to `api.brevo.com:443`, explicit timeouts, no redirects,
`verify=True` (httpx defaults already give us the last two — stated here so
a future edit doesn't quietly relax them). The API key lives only in
`settings.brevo_api_key`; `_redact()` scrubs it from anything that might end
up in `last_error` or a log line.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx

from app.core.config import settings

logger = logging.getLogger("sentinelcore.email.client")

BREVO_URL = "https://api.brevo.com/v3/smtp/email"
CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 15.0

# 30s, 2min, 10min, 1h, 6h — index 0 is the delay before attempt 2.
RETRY_DELAYS_SECONDS = [30, 120, 600, 3600, 21600]
MAX_ATTEMPTS = 5
CIRCUIT_BREAKER_MINUTES = 15


def _redact(text: str | None) -> str | None:
    if not text:
        return text
    key = settings.brevo_api_key
    if key and key in text:
        text = text.replace(key, "<redacted>")
    return text


class BrevoRetryableError(Exception):
    """Network error, timeout, 429, or 5xx. The caller should reschedule."""

    def __init__(self, message: str, *, retry_after_seconds: float | None = None) -> None:
        super().__init__(_redact(message))
        self.retry_after_seconds = retry_after_seconds


class BrevoFatalError(Exception):
    """400/401/403 — misconfiguration. Never retried automatically."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(_redact(message))
        self.status_code = status_code


@dataclass
class SendResult:
    provider_message_id: str


class CircuitBreaker:
    """Opened for `CIRCUIT_BREAKER_MINUTES` after a 401/403, so a bad key
    doesn't burn the whole outbox retrying a request that will never
    succeed. The admin alert fires once per trip, not once per blocked
    send."""

    def __init__(self) -> None:
        self._tripped_until: datetime | None = None
        self._alerted_this_trip = False

    def is_open(self) -> bool:
        if self._tripped_until is None:
            return False
        if datetime.now(timezone.utc) >= self._tripped_until:
            self._tripped_until = None
            self._alerted_this_trip = False
            return False
        return True

    def trip(self) -> None:
        self._tripped_until = datetime.now(timezone.utc) + timedelta(minutes=CIRCUIT_BREAKER_MINUTES)

    def should_alert(self) -> bool:
        """True exactly once per trip — caller is expected to send the
        admin alert immediately after checking this."""
        if self._alerted_this_trip:
            return False
        self._alerted_this_trip = True
        return True


circuit_breaker = CircuitBreaker()


class BrevoClient:
    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=httpx.Timeout(connect=CONNECT_TIMEOUT_SECONDS, read=READ_TIMEOUT_SECONDS, write=READ_TIMEOUT_SECONDS, pool=READ_TIMEOUT_SECONDS),
            verify=True,
            follow_redirects=False,
            transport=self._transport,
        )

    async def send(
        self,
        *,
        outbox_id: uuid.UUID,
        email_type: str,
        recipient_email: str,
        subject: str,
        html_body: str,
        text_body: str,
        reply_to: str | None = None,
        attachments: list[dict[str, str]] | None = None,
    ) -> SendResult:
        body: dict = {
            "sender": {"email": settings.email_sender_address, "name": settings.email_sender_name},
            "to": [{"email": recipient_email}],
            "subject": subject,
            "htmlContent": html_body,
            "textContent": text_body,
            "tags": ["sentinelcore", email_type],
            "headers": {"Idempotency-Key": str(outbox_id)},
        }
        if reply_to:
            body["replyTo"] = {"email": reply_to}
        if attachments:
            body["attachment"] = attachments

        headers = {"api-key": settings.brevo_api_key, "content-type": "application/json", "accept": "application/json"}

        start = time.monotonic()
        try:
            async with self._client() as client:
                response = await client.post(BREVO_URL, json=body, headers=headers)
        except httpx.TimeoutException as exc:
            latency_ms = (time.monotonic() - start) * 1000
            logger.error("brevo send timeout type=%s outbox_id=%s latency_ms=%.0f", email_type, outbox_id, latency_ms)
            raise BrevoRetryableError(f"timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            latency_ms = (time.monotonic() - start) * 1000
            logger.error("brevo send network error type=%s outbox_id=%s latency_ms=%.0f", email_type, outbox_id, latency_ms)
            raise BrevoRetryableError(f"network error: {_redact(str(exc))}") from exc

        latency_ms = (time.monotonic() - start) * 1000
        logger.info(
            "brevo send type=%s outbox_id=%s status=%d latency_ms=%.0f",
            email_type, outbox_id, response.status_code, latency_ms,
        )

        if response.status_code in (200, 201):
            try:
                data = response.json()
            except ValueError:
                data = {}
            message_id = data.get("messageId", "")
            return SendResult(provider_message_id=message_id)

        if response.status_code in (401, 403):
            circuit_breaker.trip()
            raise BrevoFatalError(f"auth rejected (status {response.status_code})", status_code=response.status_code)

        if response.status_code == 400:
            raise BrevoFatalError("brevo rejected the request as malformed (status 400)", status_code=400)

        if response.status_code == 429 or response.status_code >= 500:
            retry_after = None
            header_val = response.headers.get("retry-after")
            if header_val:
                try:
                    retry_after = float(header_val)
                except ValueError:
                    retry_after = None
            raise BrevoRetryableError(f"brevo returned status {response.status_code}", retry_after_seconds=retry_after)

        # Any other unexpected status: treat as fatal rather than retry forever.
        raise BrevoFatalError(f"unexpected status {response.status_code}", status_code=response.status_code)
