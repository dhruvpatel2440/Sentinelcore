"""Read-only discovery of this host's network layout (via iproute2 and /etc)."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path

from .common import run

_VIRTUAL_PREFIXES = ("docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "lxc")


@dataclass
class Interface:
    name: str
    state: str = "UNKNOWN"
    mac: str = ""
    flags: list[str] = field(default_factory=list)
    addresses: list[tuple[str, int]] = field(default_factory=list)  # (ip, prefixlen)

    @property
    def is_loopback(self) -> bool:
        return self.name == "lo" or "LOOPBACK" in self.flags

    @property
    def is_virtual(self) -> bool:
        return self.name.startswith(_VIRTUAL_PREFIXES)

    @property
    def promiscuous(self) -> bool:
        return "PROMISC" in self.flags

    def first_network(self) -> str | None:
        for ip, prefix in self.addresses:
            return str(ipaddress.ip_interface(f"{ip}/{prefix}").network)
        return None

    def describe(self) -> str:
        addrs = ", ".join(f"{ip}/{p}" for ip, p in self.addresses) or "no IPv4 address"
        return f"{self.state.lower()}, {addrs}"


def list_interfaces() -> list[Interface]:
    res = run(["ip", "-j", "addr", "show"], check=False)
    if res.returncode != 0 or not res.stdout.strip():
        return []
    out: list[Interface] = []
    for entry in json.loads(res.stdout):
        iface = Interface(
            name=entry.get("ifname", ""),
            state=entry.get("operstate", "UNKNOWN"),
            mac=entry.get("address", ""),
            flags=list(entry.get("flags", [])),
        )
        for info in entry.get("addr_info", []):
            if info.get("family") == "inet" and "local" in info:
                iface.addresses.append((info["local"], int(info.get("prefixlen", 32))))
        out.append(iface)
    return out


def capture_candidates(interfaces: list[Interface]) -> list[Interface]:
    return [i for i in interfaces if not i.is_loopback and not i.is_virtual]


def default_route() -> tuple[str | None, str | None]:
    """(gateway ip, interface name) of the IPv4 default route, if any."""
    res = run(["ip", "-j", "-4", "route", "show", "default"], check=False)
    if res.returncode != 0 or not res.stdout.strip():
        return None, None
    try:
        routes = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None, None
    if not routes:
        return None, None
    best = min(routes, key=lambda r: r.get("metric", 0))
    return best.get("gateway"), best.get("dev")


def dns_servers(paths: tuple[str, ...] = ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf")) -> list[str]:
    """Real upstream resolvers. The 127.0.0.53 systemd stub is skipped on purpose."""
    found: list[str] = []
    for path in paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in re.finditer(r"^\s*nameserver\s+(\S+)", text, flags=re.MULTILINE):
            try:
                ip = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if isinstance(ip, ipaddress.IPv4Address) and not ip.is_loopback and str(ip) not in found:
                found.append(str(ip))
        if found:
            break
    return found


def host_addresses(interfaces: list[Interface]) -> list[str]:
    """Every non-loopback IPv4 address of this host, excluding container bridges."""
    addrs: list[str] = []
    for iface in interfaces:
        if iface.is_loopback or iface.is_virtual:
            continue
        for ip, _ in iface.addresses:
            if ip not in addrs:
                addrs.append(ip)
    return addrs


def host_name() -> str:
    return socket.gethostname()


def suggested_protected_ips(interfaces: list[Interface]) -> list[str]:
    """Gateway + DNS + this host's own addresses, de-duplicated, order stable."""
    gateway, _ = default_route()
    out: list[str] = []
    for ip in [gateway, *dns_servers(), *host_addresses(interfaces)]:
        if ip and ip not in out:
            out.append(ip)
    return out
