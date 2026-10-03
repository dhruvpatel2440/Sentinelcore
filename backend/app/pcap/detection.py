"""U11 — signature-based detection over one capture's already-parsed
`pcap_flows` / `pcap_artifacts` rows.

Runs once, right after `app/pcap/generator.py::parse_pcap` finishes a
capture. Each detector below returns zero or more `Finding`s; a capture that
doesn't cross a detector's threshold produces no finding at all (not a
low-severity one) — ordinary traffic must never turn into an incident.
"""

from __future__ import annotations

import math
import statistics
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.scoring import SEVERITY_BASE_SCORE, SCORE_MAX, SCORE_MIN
from app.models.event import Severity
from app.models.incident import HistoryAction, Incident, IncidentHistory
from app.models.pcap import ArtifactType, PcapArtifact, PcapFile, PcapFlow

# ---------------------------------------------------------------------------
# DNS tunneling
# ---------------------------------------------------------------------------

DNS_TUNNEL_MIN_UNIQUE_QUERIES = 3
DNS_TUNNEL_MIN_AVG_LABEL_LEN = 20
DNS_TUNNEL_MIN_AVG_ENTROPY = 3.0  # bits/char; ordinary hostnames sit well below this
DNS_TUNNEL_SAMPLE_CAP = 10

# ---------------------------------------------------------------------------
# Port scan
# ---------------------------------------------------------------------------

PORT_SCAN_MIN_DISTINCT_PORTS = 15
PORT_SCAN_MAX_AVG_PACKETS_PER_FLOW = 4  # scan traffic is SYN-only/near-empty, not a real conversation
PORT_SCAN_SAMPLE_CAP = 20

# ---------------------------------------------------------------------------
# Beaconing
# ---------------------------------------------------------------------------

BEACON_MIN_FLOW_COUNT = 6
BEACON_MAX_COEFFICIENT_OF_VARIATION = 0.25  # low jitter between repeats = regular callback


@dataclass(frozen=True)
class Finding:
    signature_id: str
    name: str
    severity: Severity
    score: int
    description: str
    src_ip: str | None
    dst_ip: str | None
    evidence: dict[str, Any] = field(default_factory=dict)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _registrable_domain(name: str) -> str:
    # No public-suffix list here: a plain "last two labels" heuristic is
    # wrong for multi-part TLDs (co.uk) but good enough to group queries by
    # attacker-controlled domain for this detector's purpose.
    labels = name.rstrip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def _leftmost_label(name: str) -> str:
    labels = name.rstrip(".").split(".")
    return labels[0] if labels else name


def _overshoot_bonus(value: float, threshold: float, *, per_doubling: int = 5, cap: int = 20) -> int:
    if threshold <= 0 or value <= threshold:
        return 0
    doublings = math.log2(value / threshold)
    return min(int(doublings * per_doubling), cap)


def _clamp_score(score: int) -> int:
    return max(SCORE_MIN, min(SCORE_MAX, score))


def detect_dns_tunneling(artifacts: list[PcapArtifact], flows_by_id: dict[uuid.UUID, PcapFlow]) -> list[Finding]:
    dns_artifacts = [a for a in artifacts if a.artifact_type == ArtifactType.DNS_QUERY]
    by_domain: dict[str, list[PcapArtifact]] = defaultdict(list)
    for a in dns_artifacts:
        by_domain[_registrable_domain(a.value)].append(a)

    findings: list[Finding] = []
    for domain, group in by_domain.items():
        labels = [_leftmost_label(a.value) for a in group]
        unique_queries = len({a.value for a in group})
        avg_len = statistics.mean(len(l) for l in labels)
        avg_entropy = statistics.mean(_shannon_entropy(l) for l in labels)

        if (
            unique_queries < DNS_TUNNEL_MIN_UNIQUE_QUERIES
            or avg_len < DNS_TUNNEL_MIN_AVG_LABEL_LEN
            or avg_entropy < DNS_TUNNEL_MIN_AVG_ENTROPY
        ):
            continue

        flow_ips = {
            (flows_by_id[a.flow_id].src_ip, flows_by_id[a.flow_id].dst_ip)
            for a in group
            if a.flow_id in flows_by_id
        }
        src_ip = next(iter({p[0] for p in flow_ips}), None)
        dst_ip = next(iter({p[1] for p in flow_ips}), None)

        timestamps = [a.ts for a in group if a.ts is not None]
        base_score = SEVERITY_BASE_SCORE[Severity.MEDIUM]
        bonus = _overshoot_bonus(unique_queries, DNS_TUNNEL_MIN_UNIQUE_QUERIES) + _overshoot_bonus(
            avg_entropy, DNS_TUNNEL_MIN_AVG_ENTROPY, per_doubling=10, cap=15
        )
        score = _clamp_score(base_score + bonus)
        severity = Severity.CRITICAL if score >= 85 else Severity.HIGH if score >= 65 else Severity.MEDIUM

        findings.append(
            Finding(
                signature_id="PCAP-DNS-TUNNEL-001",
                name="DNS tunneling via high-entropy subdomains",
                severity=severity,
                score=score,
                description=(
                    f"{unique_queries} distinct DNS queries to {domain} used subdomain labels averaging "
                    f"{avg_len:.0f} characters with {avg_entropy:.1f} bits/char of entropy — far above ordinary "
                    f"hostnames (typically under {DNS_TUNNEL_MIN_AVG_LABEL_LEN} characters, under "
                    f"{DNS_TUNNEL_MIN_AVG_ENTROPY:.1f} bits/char). This pattern — long, high-entropy, mostly-unique "
                    f"labels under one domain — is consistent with data being encoded into DNS queries to "
                    f"exfiltrate it or tunnel a C2 channel past egress filtering."
                ),
                src_ip=str(src_ip) if src_ip else None,
                dst_ip=str(dst_ip) if dst_ip else None,
                evidence={
                    "domain": domain,
                    "unique_query_count": unique_queries,
                    "avg_label_length": round(avg_len, 1),
                    "avg_entropy_bits_per_char": round(avg_entropy, 2),
                    "sample_queries": sorted({a.value for a in group})[:DNS_TUNNEL_SAMPLE_CAP],
                    "first_seen": min(timestamps).isoformat() if timestamps else None,
                    "last_seen": max(timestamps).isoformat() if timestamps else None,
                    "packet_numbers": [a.packet_number for a in group if a.packet_number is not None][:DNS_TUNNEL_SAMPLE_CAP],
                },
            )
        )
    return findings


def detect_port_scan(flows: list[PcapFlow]) -> list[Finding]:
    by_src: dict[str, list[PcapFlow]] = defaultdict(list)
    for f in flows:
        by_src[str(f.src_ip)].append(f)

    findings: list[Finding] = []
    for src_ip, group in by_src.items():
        distinct_ports = {f.dst_port for f in group if f.dst_port is not None}
        avg_packets = statistics.mean(f.packet_count for f in group)

        if len(distinct_ports) < PORT_SCAN_MIN_DISTINCT_PORTS or avg_packets > PORT_SCAN_MAX_AVG_PACKETS_PER_FLOW:
            continue

        dst_ips = {str(f.dst_ip) for f in group}
        score = _clamp_score(
            SEVERITY_BASE_SCORE[Severity.MEDIUM] + _overshoot_bonus(len(distinct_ports), PORT_SCAN_MIN_DISTINCT_PORTS)
        )
        severity = Severity.HIGH if score >= 65 else Severity.MEDIUM

        findings.append(
            Finding(
                signature_id="PCAP-PORT-SCAN-001",
                name="Port scan — many destination ports, near-empty flows",
                severity=severity,
                score=score,
                description=(
                    f"{src_ip} touched {len(distinct_ports)} distinct destination ports across "
                    f"{len(dst_ips)} host(s), averaging only {avg_packets:.1f} packets per flow — consistent with "
                    f"a port scan (probing for open services) rather than real application traffic."
                ),
                src_ip=src_ip,
                dst_ip=next(iter(dst_ips)) if len(dst_ips) == 1 else None,
                evidence={
                    "distinct_port_count": len(distinct_ports),
                    "ports": sorted(distinct_ports)[:PORT_SCAN_SAMPLE_CAP],
                    "destination_hosts": sorted(dst_ips)[:PORT_SCAN_SAMPLE_CAP],
                    "avg_packets_per_flow": round(avg_packets, 2),
                    "flow_count": len(group),
                },
            )
        )
    return findings


def detect_beaconing(flows: list[PcapFlow]) -> list[Finding]:
    by_pair: dict[tuple[str, str, int | None], list[PcapFlow]] = defaultdict(list)
    for f in flows:
        if f.start_ts is None:
            continue
        by_pair[(str(f.src_ip), str(f.dst_ip), f.dst_port)].append(f)

    findings: list[Finding] = []
    for (src_ip, dst_ip, dst_port), group in by_pair.items():
        if len(group) < BEACON_MIN_FLOW_COUNT:
            continue

        starts = sorted(f.start_ts for f in group)
        intervals = [(b - a).total_seconds() for a, b in zip(starts, starts[1:])]
        if len(intervals) < 2 or statistics.mean(intervals) <= 0:
            continue

        mean_interval = statistics.mean(intervals)
        stdev_interval = statistics.pstdev(intervals)
        coeff_variation = stdev_interval / mean_interval

        if coeff_variation > BEACON_MAX_COEFFICIENT_OF_VARIATION:
            continue

        score = _clamp_score(
            SEVERITY_BASE_SCORE[Severity.MEDIUM] + _overshoot_bonus(len(group), BEACON_MIN_FLOW_COUNT)
        )
        severity = Severity.HIGH if score >= 65 else Severity.MEDIUM

        findings.append(
            Finding(
                signature_id="PCAP-BEACON-001",
                name="Periodic beaconing to a single destination",
                severity=severity,
                score=score,
                description=(
                    f"{src_ip} opened {len(group)} separate connections to {dst_ip}:{dst_port} at a regular "
                    f"~{mean_interval:.0f}s interval (coefficient of variation {coeff_variation:.2f}) — the kind of "
                    f"low-jitter, repeated callback pattern associated with C2 beaconing rather than ordinary, "
                    f"irregular application traffic."
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                evidence={
                    "flow_count": len(group),
                    "dst_port": dst_port,
                    "avg_interval_seconds": round(mean_interval, 1),
                    "coefficient_of_variation": round(coeff_variation, 3),
                    "first_seen": starts[0].isoformat(),
                    "last_seen": starts[-1].isoformat(),
                },
            )
        )
    return findings


async def run_detections(db: AsyncSession, pcap_id: uuid.UUID) -> list[Finding]:
    flows = (await db.execute(select(PcapFlow).where(PcapFlow.pcap_id == pcap_id))).scalars().all()
    artifacts = (await db.execute(select(PcapArtifact).where(PcapArtifact.pcap_id == pcap_id))).scalars().all()
    flows_by_id = {f.id: f for f in flows}

    findings: list[Finding] = []
    findings += detect_dns_tunneling(artifacts, flows_by_id)
    findings += detect_port_scan(flows)
    findings += detect_beaconing(flows)
    return findings


_SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


async def create_incidents_for_findings(db: AsyncSession, pcap: PcapFile, findings: list[Finding]) -> list[Incident]:
    created: list[Incident] = []
    for finding in findings:
        incident = Incident(
            title=f"{finding.name} — {finding.src_ip or finding.dst_ip or pcap.filename}",
            description=finding.description,
            severity=finding.severity,
            score=finding.score,
            src_ip=finding.src_ip,
            dst_ip=finding.dst_ip,
            signature_name=f"{finding.signature_id} — {finding.name}",
            evidence=finding.evidence,
            first_event_ts=datetime.now(timezone.utc),
            last_event_ts=datetime.now(timezone.utc),
        )
        db.add(incident)
        await db.flush()

        db.add(
            IncidentHistory(
                incident_id=incident.id,
                user_id=None,
                action=HistoryAction.CREATED,
                note=f"Created from PCAP {pcap.filename} ({pcap.id}): {finding.description}",
            )
        )
        created.append(incident)

    if created:
        primary = max(created, key=lambda i: _SEVERITY_RANK[i.severity])
        pcap.incident_id = primary.id
        await db.commit()

    return created
