"""Parser tests against a recorded nmap XML fixture."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.nmap_parser import NmapParseError, parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


@pytest.fixture(scope="module")
def hosts():
    return parse_nmap_xml(FIXTURE.read_text())


def test_only_hosts_that_are_up_are_returned(hosts):
    ips = {h.ip_address for h in hosts}
    assert ips == {"192.168.10.5", "192.168.10.42"}
    assert "192.168.10.99" not in ips  # status=down


def test_mac_and_vendor_extracted(hosts):
    gateway = next(h for h in hosts if h.ip_address == "192.168.10.5")
    assert gateway.mac_address == "00:1a:2b:3c:4d:5e"
    assert gateway.vendor == "Cisco Systems"


def test_mac_is_lowercased(hosts):
    gateway = next(h for h in hosts if h.ip_address == "192.168.10.5")
    assert gateway.mac_address == gateway.mac_address.lower()


def test_hostname_extracted(hosts):
    gateway = next(h for h in hosts if h.ip_address == "192.168.10.5")
    assert gateway.hostname == "gateway.lan"


def test_missing_hostname_is_none_not_empty(hosts):
    host = next(h for h in hosts if h.ip_address == "192.168.10.42")
    assert host.hostname is None


def test_highest_accuracy_os_match_wins(hosts):
    gateway = next(h for h in hosts if h.ip_address == "192.168.10.5")
    assert gateway.os_guess == "Linux 5.15 - 6.1"  # 94% beats 88%


def test_ports_and_service_details(hosts):
    gateway = next(h for h in hosts if h.ip_address == "192.168.10.5")
    by_port = {p.port: p for p in gateway.ports}

    assert by_port[22].state == "open"
    assert by_port[22].service == "ssh"
    assert by_port[22].product == "OpenSSH"
    assert by_port[22].version == "8.9p1"

    assert by_port[80].product == "nginx"
    assert by_port[3306].state == "filtered"


def test_compound_state_takes_first_value(hosts):
    """nmap emits 'open|filtered' for unanswered UDP; we store 'open'."""
    host = next(h for h in hosts if h.ip_address == "192.168.10.42")
    udp = next(p for p in host.ports if p.protocol == "udp")
    assert udp.state == "open"
    assert udp.port == 53


def test_both_protocols_parsed(hosts):
    host = next(h for h in hosts if h.ip_address == "192.168.10.42")
    assert {p.protocol for p in host.ports} == {"tcp", "udp"}


def test_empty_input_raises():
    for bad in ["", "   ", "\n"]:
        with pytest.raises(NmapParseError):
            parse_nmap_xml(bad)


def test_malformed_xml_raises_not_crashes():
    with pytest.raises(NmapParseError, match="malformed"):
        parse_nmap_xml("<nmaprun><host><unclosed>")


def test_unknown_elements_are_ignored():
    xml = """<?xml version="1.0"?>
    <nmaprun><somethingnew foo="bar"/>
      <host><status state="up"/>
        <address addr="192.168.10.7" addrtype="ipv4"/>
        <futuretag/>
      </host>
    </nmaprun>"""
    parsed = parse_nmap_xml(xml)
    assert len(parsed) == 1 and parsed[0].ip_address == "192.168.10.7"


def test_host_without_ipv4_is_skipped():
    xml = """<?xml version="1.0"?>
    <nmaprun><host><status state="up"/>
      <address addr="fe80::1" addrtype="ipv6"/>
    </host></nmaprun>"""
    assert parse_nmap_xml(xml) == []


def test_out_of_range_and_bad_ports_are_dropped():
    xml = """<?xml version="1.0"?>
    <nmaprun><host><status state="up"/>
      <address addr="192.168.10.7" addrtype="ipv4"/>
      <ports>
        <port protocol="tcp" portid="0"><state state="open"/></port>
        <port protocol="tcp" portid="99999"><state state="open"/></port>
        <port protocol="tcp" portid="notanumber"><state state="open"/></port>
        <port protocol="sctp" portid="80"><state state="open"/></port>
        <port protocol="tcp" portid="22"><state state="open"/></port>
      </ports>
    </host></nmaprun>"""
    parsed = parse_nmap_xml(xml)
    assert [p.port for p in parsed[0].ports] == [22]
