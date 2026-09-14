"""Shared test configuration.

The monitored network is pinned so scope tests assert on fixed addresses
rather than on whatever the local .env configures. `monitored_network_parsed`
is a cached_property, so seeding the instance __dict__ populates its cache.
"""

from __future__ import annotations

from ipaddress import ip_network

import pytest

from app.core.config import settings

TEST_MONITORED_NETWORK = ip_network("192.168.10.0/24")


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
