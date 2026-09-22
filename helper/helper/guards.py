"""The protection guard for M10 firewall containment.

Everything this module checks is computed independently of the caller — the
gateway comes from the kernel routing table, DNS servers from resolv.conf,
and the host's own addresses from the live interface list. A compromised API
container, or a config value that has drifted from reality, cannot talk this
process into blocking infrastructure the platform needs to reach the network
it watches.

`is_protected()` is the single choke point every fw_apply call passes
through, and it checks CIDR *overlap*, not exact-IP equality: a /24 that
happens to contain the gateway is exactly the kind of rule that takes a
network down, and would sail through an equality check.
"""

from __future__ import annotations

import ipaddress
import logging
import struct
import threading
import time
from pathlib import Path

from helper.config import config

logger = logging.getLogger("helper.guards")

_REFRESH_INTERVAL_SECONDS = 60


def _hex_route_to_ip(hexaddr: str) -> str | None:
    """/proc/net/route stores addresses as little-endian hex text."""
    try:
        value = int(hexaddr, 16)
    except ValueError:
        return None
    return ".".join(str(b) for b in struct.pack("<L", value))


def read_gateways() -> frozenset[str]:
    """Default gateway(s), read straight from the kernel routing table."""
    gateways: set[str] = set()
    try:
        lines = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError as exc:
        logger.warning("could not read /proc/net/route: %s", exc)
        return frozenset()

    for line in lines:
        fields = line.split()
        if len(fields) < 8:
            continue
        _iface, dest, gateway, _flags, _refcnt, _use, _metric, mask = fields[:8]
        if dest != "00000000" or mask != "00000000":
            continue  # not a default route
        ip = _hex_route_to_ip(gateway)
        if ip and ip != "0.0.0.0":
            gateways.add(ip)
    return frozenset(gateways)


def read_dns_servers() -> frozenset[str]:
    """resolv.conf plus any configured override, deduplicated and validated."""
    candidates: set[str] = set(config.dns_override)
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    candidates.add(parts[1])
    except OSError as exc:
        logger.warning("could not read /etc/resolv.conf: %s", exc)

    valid: set[str] = set()
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        valid.add(candidate)
    return frozenset(valid)


def read_host_ips() -> frozenset[str]:
    """Every address on every interface of this host, IPv4 and IPv6.

    Uses `ip -o addr show` — the same iproute2 binary M3/M4 already require —
    rather than a raw-socket ioctl, so both address families are covered
    without extra platform-specific code.
    """
    from helper.executor import ExecutionError, run

    if config.ip_path is None:
        logger.warning("`ip` binary unavailable; host-IP guard set is empty")
        return frozenset()
    try:
        result = run([config.ip_path, "-o", "addr", "show"], timeout=10, exclusive=False)
    except ExecutionError as exc:
        logger.warning("could not enumerate host addresses: %s", exc)
        return frozenset()

    ips: set[str] = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        for i, token in enumerate(parts):
            if token in ("inet", "inet6") and i + 1 < len(parts):
                addr = parts[i + 1].split("/")[0]
                try:
                    ipaddress.ip_address(addr)
                except ValueError:
                    continue
                ips.add(addr)
    return frozenset(ips)


class _GuardState:
    """Refreshed on a timer, never on the request path — a guard check must
    be fast and must never block on a subprocess mid-request."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.gateways: frozenset[str] = frozenset()
        self.dns_servers: frozenset[str] = frozenset()
        self.host_ips: frozenset[str] = frozenset()
        self.refresh()

    def refresh(self) -> None:
        gateways = read_gateways()
        dns_servers = read_dns_servers()
        host_ips = read_host_ips()
        with self._lock:
            self.gateways = gateways
            self.dns_servers = dns_servers
            self.host_ips = host_ips
        logger.info(
            "guard refresh: gateways=%s dns=%s host_ips=%s",
            sorted(gateways),
            sorted(dns_servers),
            sorted(host_ips),
        )

    def snapshot(self) -> dict[str, frozenset[str]]:
        with self._lock:
            return {
                "gateways": self.gateways,
                "dns_servers": self.dns_servers,
                "host_ips": self.host_ips,
            }


_state = _GuardState()


def start_refresh_thread() -> None:
    def _loop() -> None:
        while True:
            time.sleep(_REFRESH_INTERVAL_SECONDS)
            try:
                _state.refresh()
            except Exception:
                logger.exception("guard refresh failed")

    threading.Thread(target=_loop, name="guard-refresh", daemon=True).start()


def refresh_now() -> None:
    """Exposed for tests and for an explicit reconciliation-triggered refresh."""
    _state.refresh()


def _overlaps(network: ipaddress.IPv4Network | ipaddress.IPv6Network, other_str: str) -> bool:
    try:
        other = ipaddress.ip_network(other_str)
    except ValueError:
        return False
    if other.version != network.version:
        return False
    return network.overlaps(other)


def is_protected(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> tuple[bool, str | None]:
    """(is_protected, reason). Checks overlap against every protected set."""
    snap = _state.snapshot()

    for gw in snap["gateways"]:
        if _overlaps(network, gw):
            return True, f"{gw} is the default gateway"
    for dns in snap["dns_servers"]:
        if _overlaps(network, dns):
            return True, f"{dns} is a configured DNS server"
    for ip in snap["host_ips"]:
        if _overlaps(network, ip):
            return True, f"{ip} is this platform's own address"
    for ip in config.protected_ips:
        if _overlaps(network, ip):
            return True, f"{ip} is in PROTECTED_IPS"

    if network.version == 4 and not network.subnet_of(config.monitored_network):
        return True, f"{network} is outside the monitored network {config.monitored_network}"

    return False, None
