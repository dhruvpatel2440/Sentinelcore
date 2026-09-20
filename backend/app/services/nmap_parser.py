"""Parse nmap XML output.

XML, never regex over human-readable output: nmap's text format is meant for
people and changes between versions, while `-oX` is a stable contract. Parsing
with `xml.etree` also means a hostile hostname cannot smuggle anything through
a pattern match.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from xml.etree import ElementTree

logger = logging.getLogger("sentinelcore.nmap_parser")


class NmapParseError(Exception):
    pass


@dataclass
class ParsedPort:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class ParsedHost:
    ip_address: str
    mac_address: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    os_guess: str | None = None
    ports: list[ParsedPort] = field(default_factory=list)


def parse_nmap_xml(xml_text: str) -> list[ParsedHost]:
    """Return the hosts nmap reported as up. Unknown elements are ignored."""
    if not xml_text or not xml_text.strip():
        raise NmapParseError("nmap produced no XML output")

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise NmapParseError(f"nmap XML is malformed: {exc}") from exc

    hosts: list[ParsedHost] = []

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip_address = None
        mac_address = None
        vendor = None

        for addr in host_el.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                ip_address = addr.get("addr")
            elif addr_type == "mac":
                mac_address = (addr.get("addr") or "").lower() or None
                vendor = addr.get("vendor")

        if not ip_address:
            # No IPv4 address means nothing we can key an asset on.
            continue

        host = ParsedHost(
            ip_address=ip_address,
            mac_address=mac_address,
            vendor=vendor,
            hostname=_first_hostname(host_el),
            os_guess=_best_os_guess(host_el),
        )

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                parsed = _parse_port(port_el)
                if parsed is not None:
                    host.ports.append(parsed)

        hosts.append(host)

    logger.info("parsed %d host(s) from nmap XML", len(hosts))
    return hosts


def _first_hostname(host_el: ElementTree.Element) -> str | None:
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is None:
        return None
    for hostname_el in hostnames_el.findall("hostname"):
        name = hostname_el.get("name")
        if name:
            return name[:255]
    return None


def _best_os_guess(host_el: ElementTree.Element) -> str | None:
    """Highest-accuracy OS match, if nmap offered one."""
    os_el = host_el.find("os")
    if os_el is None:
        return None

    best_name = None
    best_accuracy = -1
    for match in os_el.findall("osmatch"):
        try:
            accuracy = int(match.get("accuracy", "0"))
        except ValueError:
            accuracy = 0
        if accuracy > best_accuracy:
            best_accuracy = accuracy
            best_name = match.get("name")

    return best_name[:128] if best_name else None


def _parse_port(port_el: ElementTree.Element) -> ParsedPort | None:
    try:
        port_number = int(port_el.get("portid", ""))
    except ValueError:
        return None
    if not (1 <= port_number <= 65535):
        return None

    protocol = (port_el.get("protocol") or "").lower()
    if protocol not in {"tcp", "udp"}:
        return None

    state_el = port_el.find("state")
    state = (state_el.get("state") if state_el is not None else None) or "closed"
    # nmap emits compound states like "open|filtered"; take the first.
    state = state.split("|")[0]
    if state not in {"open", "filtered", "closed"}:
        return None

    service_el = port_el.find("service")
    service = product = version = None
    if service_el is not None:
        service = _truncate(service_el.get("name"), 64)
        product = _truncate(service_el.get("product"), 128)
        version = _truncate(service_el.get("version"), 64)

    return ParsedPort(
        port=port_number,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
    )


def _truncate(value: str | None, limit: int) -> str | None:
    if not value:
        return None
    return value[:limit]
