"""Pin the monitored network for tests.

Validation tests assert on specific in-scope and out-of-scope addresses, so
they must not depend on whatever MONITORED_NETWORK the local .env happens to
set — otherwise changing a deployment's network silently breaks the test suite
that guards the deployment.
"""

from __future__ import annotations

from ipaddress import ip_network

import pytest

from helper.config import config

TEST_MONITORED_NETWORK = ip_network("192.168.10.0/24")


@pytest.fixture(autouse=True)
def pinned_monitored_network(monkeypatch):
    monkeypatch.setattr(config, "monitored_network", TEST_MONITORED_NETWORK)
    yield
