"""U11 PCAP detection engine: entropy/threshold logic (pure, no DB) plus one
end-to-end persistence check against the real database, following the
pattern in test_incidents.py / test_correlation.py.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, text

from app.db.session import SessionLocal
from app.models.event import Severity
from app.models.incident import Incident
from app.models.pcap import ArtifactType, PcapFile, PcapStatus
from app.pcap.detection import (
    _registrable_domain,
    _shannon_entropy,
    create_incidents_for_findings,
    detect_beaconing,
    detect_dns_tunneling,
    detect_port_scan,
)

UTC = timezone.utc


def _artifact(value: str, flow_id=None, packet_number=1, ts=None, artifact_type=ArtifactType.DNS_QUERY):
    return SimpleNamespace(artifact_type=artifact_type, value=value, flow_id=flow_id, packet_number=packet_number, ts=ts)


def _flow(src_ip="10.0.0.5", dst_ip="93.184.216.34", dst_port=53, packet_count=2, start_ts=None, flow_id=None):
    return SimpleNamespace(
        id=flow_id or uuid.uuid4(), src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
        packet_count=packet_count, start_ts=start_ts,
    )


# ---------------------------------------------------------------------------
# entropy / domain helpers
# ---------------------------------------------------------------------------


def test_shannon_entropy_of_uniform_hex_is_high():
    assert _shannon_entropy("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") > 3.5


def test_shannon_entropy_of_repeated_char_is_zero():
    assert _shannon_entropy("aaaaaaaa") == 0.0


def test_registrable_domain_takes_last_two_labels():
    assert _registrable_domain("a1b2c3tunnel.evil-example.net.") == "evil-example.net"
    assert _registrable_domain("www.google.com") == "google.com"


# ---------------------------------------------------------------------------
# DNS tunneling
# ---------------------------------------------------------------------------


def test_detect_dns_tunneling_fires_on_encoded_subdomains():
    flow_id = uuid.uuid4()
    flows_by_id = {flow_id: _flow()}
    queries = [
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6tunnel.evil-example.net",
        "9f8e7d6c5b4a3928170615049382716ftunnel.evil-example.net",
        "00112233445566778899aabbccddeefftunnel.evil-example.net",
        "ffeeddccbbaa99887766554433221100tunnel.evil-example.net",
    ]
    artifacts = [_artifact(q, flow_id=flow_id, ts=datetime.now(UTC)) for q in queries]

    findings = detect_dns_tunneling(artifacts, flows_by_id)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.signature_id == "PCAP-DNS-TUNNEL-001"
    assert finding.evidence["domain"] == "evil-example.net"
    assert finding.evidence["unique_query_count"] == 4
    assert finding.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    assert finding.score > 0


def test_detect_dns_tunneling_ignores_ordinary_hostnames():
    flow_id = uuid.uuid4()
    flows_by_id = {flow_id: _flow()}
    queries = ["www.google.com", "mail.google.com", "api.google.com", "docs.google.com"]
    artifacts = [_artifact(q, flow_id=flow_id, ts=datetime.now(UTC)) for q in queries]

    findings = detect_dns_tunneling(artifacts, flows_by_id)

    assert findings == []


def test_detect_dns_tunneling_ignores_few_queries_even_if_long():
    # Only 2 unique queries — below the MIN_UNIQUE_QUERIES bar, even though
    # the labels themselves are long/high-entropy.
    flow_id = uuid.uuid4()
    flows_by_id = {flow_id: _flow()}
    queries = [
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6tunnel.evil-example.net",
        "9f8e7d6c5b4a3928170615049382716ftunnel.evil-example.net",
    ]
    artifacts = [_artifact(q, flow_id=flow_id, ts=datetime.now(UTC)) for q in queries]

    assert detect_dns_tunneling(artifacts, flows_by_id) == []


# ---------------------------------------------------------------------------
# Port scan
# ---------------------------------------------------------------------------


def test_detect_port_scan_fires_on_many_distinct_ports():
    flows = [_flow(src_ip="10.0.0.9", dst_ip="10.0.0.1", dst_port=p, packet_count=1) for p in range(1, 20)]

    findings = detect_port_scan(flows)

    assert len(findings) == 1
    assert findings[0].signature_id == "PCAP-PORT-SCAN-001"
    assert findings[0].evidence["distinct_port_count"] == 19


def test_detect_port_scan_ignores_normal_conversation():
    # One real flow with many packets — not scan-shaped.
    flows = [_flow(src_ip="10.0.0.9", dst_ip="10.0.0.1", dst_port=443, packet_count=500)]

    assert detect_port_scan(flows) == []


def test_detect_port_scan_ignores_few_ports_even_with_tiny_flows():
    flows = [_flow(src_ip="10.0.0.9", dst_ip="10.0.0.1", dst_port=p, packet_count=1) for p in range(1, 5)]

    assert detect_port_scan(flows) == []


# ---------------------------------------------------------------------------
# Beaconing
# ---------------------------------------------------------------------------


def test_detect_beaconing_fires_on_regular_interval():
    base = datetime(2026, 1, 1, tzinfo=UTC)
    flows = [
        _flow(src_ip="10.0.0.9", dst_ip="203.0.113.5", dst_port=443, start_ts=base + timedelta(seconds=60 * i))
        for i in range(8)
    ]

    findings = detect_beaconing(flows)

    assert len(findings) == 1
    assert findings[0].signature_id == "PCAP-BEACON-001"
    assert findings[0].evidence["flow_count"] == 8


def test_detect_beaconing_ignores_irregular_intervals():
    base = datetime(2026, 1, 1, tzinfo=UTC)
    offsets = [0, 5, 400, 410, 4000, 4005, 90000, 90010]
    flows = [
        _flow(src_ip="10.0.0.9", dst_ip="203.0.113.5", dst_port=443, start_ts=base + timedelta(seconds=o))
        for o in offsets
    ]

    assert detect_beaconing(flows) == []


def test_detect_beaconing_ignores_too_few_flows():
    base = datetime(2026, 1, 1, tzinfo=UTC)
    flows = [
        _flow(src_ip="10.0.0.9", dst_ip="203.0.113.5", dst_port=443, start_ts=base + timedelta(seconds=60 * i))
        for i in range(3)
    ]

    assert detect_beaconing(flows) == []


# ---------------------------------------------------------------------------
# End-to-end persistence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_incidents_for_findings_persists_evidence_and_links_pcap():
    async with SessionLocal() as db:
        pcap = PcapFile(
            filename="e2e-detection.pcap",
            stored_path="/tmp/e2e-detection.pcap",
            sha256=uuid.uuid4().hex + uuid.uuid4().hex,
            size_bytes=1,
            status=PcapStatus.PARSED,
        )
        db.add(pcap)
        await db.flush()
        pcap_id = pcap.id

        created = []
        try:
            from app.pcap.detection import Finding

            finding = Finding(
                signature_id="PCAP-DNS-TUNNEL-001",
                name="DNS tunneling via high-entropy subdomains",
                severity=Severity.HIGH,
                score=72,
                description="4 distinct DNS queries to evil-example.net ...",
                src_ip="10.0.0.5",
                dst_ip="93.184.216.34",
                evidence={"domain": "evil-example.net", "unique_query_count": 4},
            )

            created = await create_incidents_for_findings(db, pcap, [finding])
            assert len(created) == 1
            incident_id = created[0].id

            await db.refresh(pcap)
            assert pcap.incident_id == incident_id

            incident = await db.get(Incident, incident_id)
            assert incident.signature_name == "PCAP-DNS-TUNNEL-001 — DNS tunneling via high-entropy subdomains"
            assert incident.evidence["domain"] == "evil-example.net"
            assert incident.severity == Severity.HIGH
            assert incident.score == 72

            history_action = await db.scalar(
                text("SELECT action FROM incident_history WHERE incident_id = :i"), {"i": incident_id}
            )
            assert history_action == "created"
        finally:
            # incident_history is append-only by DB trigger — even a cascading
            # DELETE off incidents is rejected (see test_incidents.py's
            # _cleanup), so the incident/history rows are left behind,
            # harmless and uniquely tagged. Only the pcap_files row (which
            # this test created directly) is cleaned up.
            await db.execute(text("UPDATE pcap_files SET incident_id = NULL WHERE id = :p"), {"p": pcap_id})
            await db.execute(delete(PcapFile).where(PcapFile.id == pcap_id))
            await db.commit()
