"""API-layer scan request validation.

This is the *first* of two independent checks. `helper/tests/test_validation.py`
covers the second — the helper refuses the same inputs even when this layer is
bypassed entirely, which is the M3 requirement.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.asset import ScanRequest


@pytest.mark.parametrize(
    "targets",
    [["192.168.10.0/24"], ["192.168.10.5"], ["192.168.10.0/25", "192.168.10.128/25"]],
)
def test_in_scope_targets_accepted(targets):
    assert ScanRequest(targets=targets).targets == targets


@pytest.mark.parametrize(
    "targets",
    [
        ["8.8.8.8/32"],  # the M3 definition-of-done case
        ["8.8.8.8"],
        ["10.0.0.0/8"],
        ["0.0.0.0/0"],
        ["192.168.0.0/16"],  # supernet of the monitored range
        ["192.168.11.5"],
        ["192.168.10.5", "8.8.8.8"],  # one bad entry poisons the batch
    ],
)
def test_out_of_scope_targets_rejected(targets):
    with pytest.raises(ValidationError):
        ScanRequest(targets=targets)


@pytest.mark.parametrize(
    "targets",
    [["127.0.0.1"], ["169.254.1.1"], ["224.0.0.1"]],
)
def test_loopback_linklocal_multicast_rejected(targets):
    with pytest.raises(ValidationError):
        ScanRequest(targets=targets)


@pytest.mark.parametrize(
    "target",
    [
        "192.168.10.1; rm -rf /",
        "192.168.10.1 && id",
        "$(whoami)",
        "`id`",
        "example.com",
        "localhost",
        "../../etc/passwd",
    ],
)
def test_injection_shaped_targets_rejected(target):
    with pytest.raises(ValidationError):
        ScanRequest(targets=[target])


def test_empty_target_list_rejected():
    with pytest.raises(ValidationError):
        ScanRequest(targets=[])


def test_too_many_targets_rejected():
    with pytest.raises(ValidationError):
        ScanRequest(targets=[f"192.168.10.{i}" for i in range(1, 100)])


def test_targets_none_means_default_monitored_network():
    """None is legal — the route substitutes MONITORED_NETWORK."""
    assert ScanRequest(targets=None).targets is None


def test_defaults():
    request = ScanRequest()
    assert request.ports == "1-1024"
    assert request.mode == "tcp_syn"
