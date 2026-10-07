"""Regression tests for the audit-driven fixes (spoofable client IP, SSRF,
LIKE wildcards, production secret key)."""

from __future__ import annotations

import pytest
from starlette.requests import Request

from app.api.deps import client_ip
from app.core.config import Settings
from app.core.sql import like_contains
from app.intel.feeds import FeedFetchError, _assert_public_url


def _req(headers: dict[str, str], client=("10.0.0.9", 1234)) -> Request:
    return Request({"type": "http", "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()], "client": client})


def test_client_ip_ignores_forged_leftmost_xff():
    assert client_ip(_req({"x-forwarded-for": "6.6.6.6, 203.0.113.5"})) == "203.0.113.5"


def test_client_ip_falls_back_to_peer():
    assert client_ip(_req({})) == "10.0.0.9"


def test_like_contains_escapes_wildcards():
    assert like_contains("50%_x\\") == "%50\\%\\_x\\\\%"


def test_production_refuses_placeholder_secret():
    with pytest.raises(ValueError):
        Settings(database_url="x", environment="production", secret_key="dev-only-placeholder-change-in-env")
    with pytest.raises(ValueError):
        Settings(database_url="x", environment="production", secret_key="short")
    Settings(database_url="x", environment="production", secret_key="k" * 40)
    Settings(database_url="x", environment="development")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1/feed", "http://169.254.169.254/latest", "http://10.1.2.3/x", "file:///etc/passwd", "ftp://example.com/x"],
)
async def test_feed_url_ssrf_blocked(url):
    with pytest.raises(FeedFetchError):
        await _assert_public_url(url)
