"""Input validation for privileged operations.

This module assumes **the caller is hostile**. The threat model for the helper
is a compromised API container: the backend validates too, but nothing here
trusts that it did. Every value is re-derived from first principles.

Nothing in this file builds a string that is handed to a shell. Validators
return structured values; the op handlers turn those into argv lists.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from helper.config import config


class ValidationError(Exception):
    """Rejected input. `code` is a stable identifier the API can branch on."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

MAX_TARGETS = 64
MAX_TARGET_HOSTS = 4096  # a /20; refuse to sweep the internet by accident


def validate_target(raw: str) -> ipaddress.IPv4Network:
    """Parse one target and prove it is inside the monitored scope."""
    if not isinstance(raw, str):
        raise ValidationError("invalid_target", "Target must be a string")

    candidate = raw.strip()
    if not candidate or len(candidate) > 64:
        raise ValidationError("invalid_target", "Target is empty or too long")

    # Reject anything that is not plainly an address or CIDR *before* parsing,
    # so hostnames (which would imply DNS resolution) never get that far.
    if not re.fullmatch(r"[0-9.]+(/\d{1,2})?", candidate):
        raise ValidationError(
            "invalid_target", f"Target must be an IPv4 address or CIDR: {candidate!r}"
        )

    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError as exc:
        raise ValidationError("invalid_target", f"Unparseable target: {candidate!r}") from exc

    if not isinstance(network, ipaddress.IPv4Network):
        raise ValidationError("invalid_target", "Only IPv4 targets are supported")

    if network.num_addresses > MAX_TARGET_HOSTS:
        raise ValidationError(
            "target_too_large",
            f"Target {candidate} covers {network.num_addresses} addresses "
            f"(limit {MAX_TARGET_HOSTS})",
        )

    # Categorical refusals — these are never legitimate scan targets and are
    # checked independently of the monitored-network containment below.
    if network.is_loopback:
        raise ValidationError("forbidden_target", "Loopback addresses cannot be scanned")
    if network.is_link_local:
        raise ValidationError("forbidden_target", "Link-local addresses cannot be scanned")
    if network.is_multicast:
        raise ValidationError("forbidden_target", "Multicast addresses cannot be scanned")
    if network.is_reserved:
        raise ValidationError("forbidden_target", "Reserved addresses cannot be scanned")

    # Containment: the whole network must sit inside MONITORED_NETWORK.
    # `subnet_of` is the correct test — an overlap check would let a caller
    # pass a supernet like 0.0.0.0/0 and scan everything.
    monitored = config.monitored_network
    if not network.subnet_of(monitored):
        raise ValidationError(
            "target_out_of_scope",
            f"Target {candidate} is outside the monitored network {monitored}",
        )

    return network


def validate_targets(raw: object) -> list[ipaddress.IPv4Network]:
    if not isinstance(raw, list) or not raw:
        raise ValidationError("invalid_target", "targets must be a non-empty list")
    if len(raw) > MAX_TARGETS:
        raise ValidationError("invalid_target", f"Too many targets (limit {MAX_TARGETS})")

    networks = [validate_target(item) for item in raw]

    total = sum(n.num_addresses for n in networks)
    if total > MAX_TARGET_HOSTS:
        raise ValidationError(
            "target_too_large", f"Targets cover {total} addresses (limit {MAX_TARGET_HOSTS})"
        )
    return networks


# --------------------------------------------------------------------------
# Ports
# --------------------------------------------------------------------------

# Deliberately strict: digits, single hyphens, single commas. Nothing else.
# A value like "1-1024; rm -rf /" fails here and is never seen again.
_PORT_SPEC_RE = re.compile(r"\A\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*\Z")

MAX_PORT_COUNT = 65535
MAX_PORT_RANGES = 64


@dataclass(frozen=True)
class PortSpec:
    """A validated port specification and its canonical textual form."""

    ranges: tuple[tuple[int, int], ...]

    @property
    def count(self) -> int:
        return sum(hi - lo + 1 for lo, hi in self.ranges)

    def to_nmap(self) -> str:
        """Canonical re-serialisation. The caller's original string is never
        forwarded — only this regenerated form built from validated ints."""
        return ",".join(f"{lo}-{hi}" if lo != hi else str(lo) for lo, hi in self.ranges)


def validate_ports(raw: object) -> PortSpec:
    if not isinstance(raw, str):
        raise ValidationError("invalid_ports", "ports must be a string")

    spec = raw.strip()
    if not spec:
        raise ValidationError("invalid_ports", "ports must not be empty")
    if len(spec) > 512:
        raise ValidationError("invalid_ports", "port specification is too long")

    if not _PORT_SPEC_RE.match(spec):
        raise ValidationError(
            "invalid_ports",
            "ports must match digits, ranges and commas only (e.g. 22,80,1-1024)",
        )

    parts = spec.split(",")
    if len(parts) > MAX_PORT_RANGES:
        raise ValidationError("invalid_ports", f"Too many port ranges (limit {MAX_PORT_RANGES})")

    ranges: list[tuple[int, int]] = []
    for part in parts:
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
        else:
            lo = hi = int(part)

        if not (1 <= lo <= 65535) or not (1 <= hi <= 65535):
            raise ValidationError("invalid_ports", f"Port out of range 1-65535: {part}")
        if lo > hi:
            raise ValidationError("invalid_ports", f"Port range is reversed: {part}")
        ranges.append((lo, hi))

    result = PortSpec(tuple(ranges))
    if result.count > MAX_PORT_COUNT:
        raise ValidationError("invalid_ports", "Port specification covers too many ports")
    return result


# --------------------------------------------------------------------------
# Scan modes
# --------------------------------------------------------------------------

# The caller supplies a *name*, never flags. Adding a capability means editing
# this table — which is a reviewable change — not passing a new argument.
SCAN_MODES: dict[str, tuple[str, ...]] = {
    # SYN scan: fast, needs raw sockets, which is exactly why it lives here.
    "tcp_syn": ("-sS",),
    "tcp_connect": ("-sT",),
    "udp": ("-sU",),
    # Host discovery only — no port scan.
    "ping": ("-sn",),
    # Service/version detection layered on a SYN scan.
    "service_version": ("-sS", "-sV", "--version-intensity", "2"),
}


def validate_mode(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, str):
        raise ValidationError("invalid_mode", "mode must be a string")
    flags = SCAN_MODES.get(raw)
    if flags is None:
        raise ValidationError(
            "invalid_mode",
            f"Unknown scan mode {raw!r}. Allowed: {', '.join(sorted(SCAN_MODES))}",
        )
    return flags


# --------------------------------------------------------------------------
# Rule filenames (used by M4's suricata_write_rules)
# --------------------------------------------------------------------------

_RULES_FILENAME_RE = re.compile(r"\A[a-zA-Z0-9_-]+\.rules\Z")


def validate_rules_filename(raw: object) -> str:
    """No separators, no traversal, no absolute paths — a bare basename only.

    Deliberately does *not* strip surrounding whitespace. A filename arriving
    with a trailing newline is a probe, not a typo; normalising it away would
    mean accepting input we do not understand.
    """
    if not isinstance(raw, str):
        raise ValidationError("invalid_filename", "filename must be a string")
    name = raw
    if not _RULES_FILENAME_RE.match(name):
        raise ValidationError(
            "invalid_filename",
            "filename must match ^[a-zA-Z0-9_-]+\\.rules$ with no path separators",
        )
    return name


# --------------------------------------------------------------------------
# Firewall (M10)
# --------------------------------------------------------------------------

_ACTION_ID_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")

DIRECTIONS = ("inbound", "outbound", "both")
PROTOCOLS = ("tcp", "udp")


def validate_action_id(raw: object) -> str:
    """Canonical lowercase UUID — this string becomes the iptables comment
    tag, so it must be constrained tightly enough to search for reliably."""
    if not isinstance(raw, str):
        raise ValidationError("invalid_action_id", "action_id must be a string")
    value = raw.strip().lower()
    if not _ACTION_ID_RE.match(value):
        raise ValidationError("invalid_action_id", "action_id must be a UUID")
    return value


def validate_direction(raw: object) -> str:
    if not isinstance(raw, str) or raw not in DIRECTIONS:
        raise ValidationError(
            "invalid_direction", f"direction must be one of {', '.join(DIRECTIONS)}"
        )
    return raw


def validate_protocol_port(protocol_raw: object, port_raw: object) -> tuple[str | None, int | None]:
    protocol: str | None = None
    if protocol_raw is not None:
        if not isinstance(protocol_raw, str) or protocol_raw not in PROTOCOLS:
            raise ValidationError("invalid_protocol", f"protocol must be one of {', '.join(PROTOCOLS)}")
        protocol = protocol_raw

    port: int | None = None
    if port_raw is not None:
        if isinstance(port_raw, bool) or not isinstance(port_raw, int):
            raise ValidationError("invalid_port", "port must be an integer")
        if not (1 <= port_raw <= 65535):
            raise ValidationError("invalid_port", "port must be between 1 and 65535")
        port = port_raw

    if port is not None and protocol is None:
        raise ValidationError("invalid_protocol", "a port requires a protocol (tcp or udp)")

    return protocol, port


_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def validate_sha256(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValidationError("invalid_checksum", "checksum must be a string")
    value = raw.strip().lower()
    if not _SHA256_RE.match(value):
        raise ValidationError("invalid_checksum", "checksum must be 64 lowercase hex characters")
    return value
