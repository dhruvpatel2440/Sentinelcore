"""Shared test configuration.

The monitored network is pinned so scope tests assert on fixed addresses
rather than on whatever the local .env configures. `monitored_network_parsed`
is a cached_property, so seeding the instance __dict__ populates its cache.
"""

from __future__ import annotations

from ipaddress import ip_network

import pytest
import pytest_asyncio

from app.core.config import settings
from app.db.session import engine

TEST_MONITORED_NETWORK = ip_network("192.168.10.0/24")


@pytest_asyncio.fixture(autouse=True)
async def _dispose_engine_after_test():
    """pytest-asyncio hands each test function its own event loop, but
    `app.db.session.engine` (and its asyncpg connection pool) is created once
    at import time. A connection checked out under one test's loop is unusable
    once that loop closes — disposing the pool after every test forces the
    next DB-touching test to open a fresh connection on its own loop."""
    yield
    await engine.dispose()


@pytest.fixture(autouse=True)
def pinned_monitored_network():
    previous = settings.__dict__.get("monitored_network_parsed")
    settings.__dict__["monitored_network_parsed"] = TEST_MONITORED_NETWORK
    try:
        yield
    finally:
        if previous is None:
            settings.__dict__.pop("monitored_network_parsed", None)
        else:
            settings.__dict__["monitored_network_parsed"] = previous
