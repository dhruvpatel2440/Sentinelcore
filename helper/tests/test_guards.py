"""M10 protection guard tests.

This module gets tested harder than anything else in the codebase per the M10
spec: exact match, CIDR containment, 0.0.0.0/0, network/broadcast boundaries,
IPv6 forms, and a target equal to the helper's own address must all be
refused, and refused for the *right* reason category.
"""

from __future__ import annotations

import ipaddress

import pytest

from helper import guards
from helper.config import config

# conftest.py pins config.monitored_network to 192.168.10.0/24 for every test.


def net(cidr: str):
    return ipaddress.ip_network(cidr)


@pytest.fixture(autouse=True)
def fixed_guard_state(monkeypatch):
    """Replace the live, subprocess-derived guard state with fixed values so
    these tests do not depend on the routing table of whatever machine runs
    them."""
    monkeypatch.setattr(guards._state, "gateways", frozenset({"192.168.10.1"}))
    monkeypatch.setattr(guards._state, "dns_servers", frozenset({"192.168.10.2"}))
    monkeypatch.setattr(guards._state, "host_ips", frozenset({"192.168.10.5", "fe80::1"}))
    monkeypatch.setattr(config, "protected_ips", frozenset({"192.168.10.9"}))
    yield


def test_exact_gateway_refused():
    protected, reason = guards.is_protected(net("192.168.10.1/32"))
    assert protected
    assert "gateway" in reason


def test_cidr_containing_gateway_refused():
    """A /24 that merely contains the gateway is exactly the bug this guard
    exists to prevent — equality-only checking would let this through."""
    protected, reason = guards.is_protected(net("192.168.10.0/24"))
    assert protected
    assert "gateway" in reason


def test_exact_dns_server_refused():
    protected, reason = guards.is_protected(net("192.168.10.2/32"))
    assert protected
    assert "DNS" in reason


def test_dns_containing_cidr_refused():
    protected, _ = guards.is_protected(net("192.168.10.0/28"))
    assert protected  # contains .1 (gateway) and .2 (dns) either way


def test_own_address_exact_refused():
    protected, reason = guards.is_protected(net("192.168.10.5/32"))
    assert protected
    assert "own address" in reason


def test_own_address_cidr_refused():
    protected, reason = guards.is_protected(net("192.168.10.0/29"))
    assert protected


def test_protected_ips_env_exact_refused():
    protected, reason = guards.is_protected(net("192.168.10.9/32"))
    assert protected
    assert "PROTECTED_IPS" in reason


def test_protected_ips_env_cidr_refused():
    protected, _ = guards.is_protected(net("192.168.10.8/29"))
    assert protected


def test_zero_route_refused():
    """0.0.0.0/0 overlaps every protected address and the entire monitored
    network — it must never sail through as a 'big but valid' CIDR."""
    protected, _ = guards.is_protected(net("0.0.0.0/0"))
    assert protected


def test_network_address_as_protected_ip_refused(monkeypatch):
    monkeypatch.setattr(config, "protected_ips", frozenset({"192.168.10.0"}))
    protected, reason = guards.is_protected(net("192.168.10.0/32"))
    assert protected
    assert "PROTECTED_IPS" in reason


def test_broadcast_address_as_protected_ip_refused(monkeypatch):
    monkeypatch.setattr(config, "protected_ips", frozenset({"192.168.10.255"}))
    protected, reason = guards.is_protected(net("192.168.10.255/32"))
    assert protected
    assert "PROTECTED_IPS" in reason


def test_out_of_scope_target_refused():
    protected, reason = guards.is_protected(net("8.8.8.8/32"))
    assert protected
    assert "outside the monitored network" in reason


def test_adjacent_out_of_scope_cidr_refused():
    """A CIDR disjoint from every protected address but outside the monitored
    /24 must still be refused on scope grounds alone."""
    protected, reason = guards.is_protected(net("192.168.11.0/24"))
    assert protected
    assert "outside the monitored network" in reason


def test_supernet_containing_monitored_network_refused():
    """A supernet that fully contains the monitored /24 (and, incidentally,
    the gateway inside it) is refused — for whichever reason fires first,
    since either is sufficient to stop it."""
    protected, _ = guards.is_protected(net("192.168.0.0/16"))
    assert protected


def test_ipv6_target_does_not_crash_against_ipv4_protected_set():
    """An IPv6 target must never be compared against IPv4-only protected
    entries in a way that raises — mismatched families simply do not overlap."""
    protected, reason = guards.is_protected(net("fe80::5/128"))
    assert protected is False
    assert reason is None


def test_ipv6_target_matches_ipv6_host_ip():
    protected, reason = guards.is_protected(net("fe80::1/128"))
    assert protected
    assert "own address" in reason


def test_safe_target_inside_scope_is_allowed():
    protected, reason = guards.is_protected(net("192.168.10.50/32"))
    assert protected is False
    assert reason is None


def test_refresh_now_repopulates_state_without_raising():
    guards.refresh_now()
    snap = guards._state.snapshot()
    assert isinstance(snap["gateways"], frozenset)
