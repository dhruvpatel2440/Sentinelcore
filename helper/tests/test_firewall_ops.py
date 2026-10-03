"""M10 firewall op tests: registration, param validation, guard wiring, and
real-iptables idempotency/reconciliation against the dedicated SENTINELCORE
chain. Runs against the actual `iptables` binary — this container already
has NET_ADMIN and root, the same way M4's suricata tests exercise the real
`suricata -T` binary rather than mocking it.
"""

from __future__ import annotations

import uuid

import pytest

from helper import guards
from helper.config import config
from helper.ops import OPS
from helper.ops import firewall as fwops
from helper.validation import (
    ValidationError,
    validate_action_id,
    validate_direction,
    validate_protocol_port,
)

pytestmark = pytest.mark.skipif(config.iptables_path is None, reason="iptables not available in this environment")


@pytest.fixture(autouse=True)
def clear_guard_state(monkeypatch):
    """Isolate fw op tests from guard concerns — those are covered exhaustively
    in test_guards.py — and from whatever the real host routing table is."""
    monkeypatch.setattr(guards._state, "gateways", frozenset())
    monkeypatch.setattr(guards._state, "dns_servers", frozenset())
    monkeypatch.setattr(guards._state, "host_ips", frozenset())
    monkeypatch.setattr(config, "protected_ips", frozenset())
    yield


@pytest.fixture
def clean_chain():
    fwops.ensure_chain()
    yield
    for line in fwops._list_raw_rules():
        parsed = fwops._parse_managed_rule(line)
        if parsed:
            fwops._delete_by_action_id(parsed["action_id"])


def new_action_id() -> str:
    return str(uuid.uuid4())


@pytest.mark.parametrize("op", ["fw_apply", "fw_revoke", "fw_list", "fw_reconcile", "fw_check_target"])
def test_all_m10_ops_are_registered(op):
    assert op in OPS


def test_no_generic_command_op_exists():
    forbidden = {"exec", "run", "shell", "command", "system", "eval"}
    assert forbidden.isdisjoint(OPS)


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------


def test_validate_action_id_accepts_uuid():
    aid = new_action_id()
    assert validate_action_id(aid) == aid


@pytest.mark.parametrize("bad", ["not-a-uuid", "", 12345, None, "'; DROP TABLE x; --"])
def test_validate_action_id_rejects_non_uuid(bad):
    with pytest.raises(ValidationError):
        validate_action_id(bad)


def test_validate_direction_accepts_known_values():
    for d in ("inbound", "outbound", "both"):
        assert validate_direction(d) == d


@pytest.mark.parametrize("bad", ["up", "", None, "INBOUND"])
def test_validate_direction_rejects_unknown(bad):
    with pytest.raises(ValidationError):
        validate_direction(bad)


def test_validate_protocol_port_accepts_none():
    assert validate_protocol_port(None, None) == (None, None)


def test_validate_protocol_port_accepts_tcp_and_port():
    assert validate_protocol_port("tcp", 22) == ("tcp", 22)


@pytest.mark.parametrize("bad_protocol", ["icmp", "", 5, "TCP"])
def test_validate_protocol_port_rejects_bad_protocol(bad_protocol):
    with pytest.raises(ValidationError):
        validate_protocol_port(bad_protocol, None)


@pytest.mark.parametrize("bad_port", [0, -1, 65536, "22", True])
def test_validate_protocol_port_rejects_bad_port(bad_port):
    with pytest.raises(ValidationError):
        validate_protocol_port("tcp", bad_port)


def test_validate_protocol_port_requires_protocol_with_port():
    with pytest.raises(ValidationError):
        validate_protocol_port(None, 22)


# --------------------------------------------------------------------------
# fw_check_target — read-only guard evaluation
# --------------------------------------------------------------------------


def test_fw_check_target_allows_safe_target():
    result = fwops.fw_check_target({"target": "192.168.10.50"})
    assert result["allowed"] is True
    assert result["reason"] is None


def test_fw_check_target_refuses_protected(monkeypatch):
    monkeypatch.setattr(config, "protected_ips", frozenset({"192.168.10.9"}))
    result = fwops.fw_check_target({"target": "192.168.10.9"})
    assert result["allowed"] is False
    assert "PROTECTED_IPS" in result["reason"]


def test_fw_check_target_never_touches_iptables(monkeypatch):
    """A pure guard check must never spawn a subprocess — this is what lets
    the frontend call it on every keystroke of the target field."""

    def _boom(*a, **k):
        raise AssertionError("fw_check_target must not execute a subprocess")

    monkeypatch.setattr("helper.ops.firewall.run", _boom)
    fwops.fw_check_target({"target": "192.168.10.50"})


# --------------------------------------------------------------------------
# fw_apply / fw_list / fw_revoke — real iptables, dedicated chain
# --------------------------------------------------------------------------


def test_apply_creates_a_managed_rule(clean_chain):
    aid = new_action_id()
    result = fwops.fw_apply({"action_id": aid, "target": "192.168.10.77/32", "direction": "inbound"})
    assert result["applied"] is True
    listed = fwops.fw_list({})["rules"]
    assert any(r["action_id"] == aid and r["tag"] == "in" for r in listed)


def test_apply_is_idempotent(clean_chain):
    aid = new_action_id()
    fwops.fw_apply({"action_id": aid, "target": "192.168.10.78/32", "direction": "inbound"})
    fwops.fw_apply({"action_id": aid, "target": "192.168.10.78/32", "direction": "inbound"})
    listed = [r for r in fwops.fw_list({})["rules"] if r["action_id"] == aid]
    assert len(listed) == 1


def test_apply_both_directions_creates_two_rules(clean_chain):
    aid = new_action_id()
    fwops.fw_apply({"action_id": aid, "target": "192.168.10.79/32", "direction": "both"})
    tags = {r["tag"] for r in fwops.fw_list({})["rules"] if r["action_id"] == aid}
    assert tags == {"in", "out"}


def test_apply_with_protocol_and_port(clean_chain):
    aid = new_action_id()
    fwops.fw_apply(
        {"action_id": aid, "target": "192.168.10.80/32", "direction": "inbound", "protocol": "tcp", "port": 22}
    )
    rule = next(r for r in fwops.fw_list({})["rules"] if r["action_id"] == aid)
    assert rule["protocol"] == "tcp"
    assert rule["port"] == 22


def test_apply_refuses_protected_target(clean_chain, monkeypatch):
    monkeypatch.setattr(config, "protected_ips", frozenset({"192.168.10.1"}))
    with pytest.raises(ValidationError) as exc_info:
        fwops.fw_apply({"action_id": new_action_id(), "target": "192.168.10.1/32", "direction": "inbound"})
    assert exc_info.value.code == "protected_target"


def test_apply_refuses_out_of_scope_target(clean_chain):
    with pytest.raises(ValidationError):
        fwops.fw_apply({"action_id": new_action_id(), "target": "8.8.8.8/32", "direction": "inbound"})


def test_revoke_removes_the_rule(clean_chain):
    aid = new_action_id()
    fwops.fw_apply({"action_id": aid, "target": "192.168.10.81/32", "direction": "both"})
    result = fwops.fw_revoke({"action_id": aid})
    assert set(result["removed"]) == {"in", "out"}
    assert not any(r["action_id"] == aid for r in fwops.fw_list({})["rules"])


def test_revoke_is_idempotent_on_absent_action_id(clean_chain):
    """Revoking an action_id with no matching rule still succeeds — the
    desired end state (no such rule) is already true."""
    result = fwops.fw_revoke({"action_id": new_action_id()})
    assert result["revoked"] is True
    assert result["removed"] == []


# --------------------------------------------------------------------------
# fw_reconcile — drift in both directions
# --------------------------------------------------------------------------


def test_reconcile_removes_orphans(clean_chain):
    aid = new_action_id()
    fwops.fw_apply({"action_id": aid, "target": "192.168.10.82/32", "direction": "inbound"})
    result = fwops.fw_reconcile({"expected": []})
    assert aid in result["orphans_removed"]
    assert not any(r["action_id"] == aid for r in fwops.fw_list({})["rules"])


def test_reconcile_reports_missing():
    missing_id = new_action_id()
    result = fwops.fw_reconcile({"expected": [missing_id]})
    assert missing_id in result["missing"]


def test_reconcile_leaves_expected_rules_alone(clean_chain):
    aid = new_action_id()
    fwops.fw_apply({"action_id": aid, "target": "192.168.10.83/32", "direction": "inbound"})
    result = fwops.fw_reconcile({"expected": [aid]})
    assert aid not in result["orphans_removed"]
    assert aid not in result["missing"]
    assert any(r["action_id"] == aid for r in fwops.fw_list({})["rules"])
