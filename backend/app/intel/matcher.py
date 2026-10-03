"""M12 matcher: the hot-path lookup hooked into M5's enrichment pass.

Matching runs on every event, so the steady-state path never touches
PostgreSQL: a Redis hash for exact matches, an in-process list of networks for
CIDR indicators, refreshed only when a version counter changes. PostgreSQL is
only touched on an actual hit, to write the evidence trail.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy import Text, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Severity
from app.models.ioc import Ioc, IocType

logger = logging.getLogger("sentinelcore.intel.matcher")

VERSION_KEY = "ioc:version"
EXACT_HASH_KEY = "ioc:exact"
CIDR_LIST_KEY = "ioc:cidr"
HITS_CHANNEL = "ioc:hits"

_SEVERITY_RANK = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


def _escalate(current: str, candidate: str | None) -> str:
    """Never downgrades — an event whose own severity is already higher than
    the matched IOC's keeps its severity."""
    if not candidate:
        return current
    return candidate if _SEVERITY_RANK.get(candidate, 0) > _SEVERITY_RANK.get(current, 0) else current


@dataclass(frozen=True)
class IocRef:
    id: str
    severity: str
    confidence: int
    threat_type: str | None
    ioc_type: str

    def to_json(self) -> str:
        return json.dumps(
            {"id": self.id, "severity": self.severity, "confidence": self.confidence,
             "threat_type": self.threat_type, "ioc_type": self.ioc_type}
        )

    @classmethod
    def from_json(cls, raw: bytes | str) -> "IocRef":
        data = json.loads(raw)
        return cls(**data)


@dataclass(frozen=True)
class MatchHit:
    ioc_id: str
    severity: str
    matched_value: str
    matched_field: str


async def bump_version(redis: aioredis.Redis | None = None) -> None:
    from app.core.redis import get_redis

    r = redis or get_redis()
    await r.incr(VERSION_KEY)


async def rebuild_index(db: AsyncSession, redis: aioredis.Redis) -> int:
    """Full rebuild of the Redis-backed lookup from `ioc`. Called after a feed
    refresh and from manual CRUD so a change is visible within one version
    cycle rather than waiting for the next scheduled refresh."""
    now = datetime.now(timezone.utc)
    rows = (
        await db.execute(
            select(Ioc).where(Ioc.is_active.is_(True)).where((Ioc.expires_at.is_(None)) | (Ioc.expires_at > now))
        )
    ).scalars().all()

    exact_mapping: dict[str, str] = {}
    cidrs: list[dict[str, Any]] = []

    for ioc in rows:
        ref = IocRef(
            id=str(ioc.id), severity=ioc.severity.value, confidence=ioc.confidence,
            threat_type=ioc.threat_type, ioc_type=ioc.ioc_type.value,
        )
        if ioc.ioc_type == IocType.CIDR:
            cidrs.append({"network": ioc.indicator, **ref.__dict__})
        else:
            exact_mapping[ioc.indicator] = ref.to_json()

    pipe = redis.pipeline()
    pipe.delete(EXACT_HASH_KEY)
    if exact_mapping:
        pipe.hset(EXACT_HASH_KEY, mapping=exact_mapping)
    pipe.set(CIDR_LIST_KEY, json.dumps(cidrs))
    await pipe.execute()
    await bump_version(redis)

    logger.info("ioc index rebuilt: %d exact, %d cidr", len(exact_mapping), len(cidrs))
    return len(exact_mapping) + len(cidrs)


class Matcher:
    """Per-process cache of the CIDR list, refreshed on version change.
    Exact lookups always hit Redis directly — a single HGET is already O(1)
    and needs no local cache."""

    def __init__(self) -> None:
        self._loaded_version: int | None = None
        self._cidrs: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, IocRef]] = []

    async def _ensure_fresh(self, redis: aioredis.Redis) -> None:
        raw_version = await redis.get(VERSION_KEY)
        version = int(raw_version) if raw_version else 0
        if version == self._loaded_version:
            return

        raw_cidrs = await redis.get(CIDR_LIST_KEY)
        entries = json.loads(raw_cidrs) if raw_cidrs else []
        parsed = []
        for entry in entries:
            try:
                network = ipaddress.ip_network(entry["network"])
            except ValueError:
                continue
            ref = IocRef(
                id=entry["id"], severity=entry["severity"], confidence=entry["confidence"],
                threat_type=entry.get("threat_type"), ioc_type=entry["ioc_type"],
            )
            parsed.append((network, ref))

        self._cidrs = parsed
        self._loaded_version = version

    def _match_cidr(self, ip: str) -> IocRef | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for network, ref in self._cidrs:
            if addr in network:
                return ref
        return None

    async def lookup(self, redis: aioredis.Redis, value: str) -> IocRef | None:
        """Exact-match lookup for a single normalized value (used by the
        `/lookup` endpoint and bulk paths, not the per-event hot path)."""
        raw = await redis.hget(EXACT_HASH_KEY, value)
        return IocRef.from_json(raw) if raw else None

    async def match_fields(self, redis: aioredis.Redis, fields: dict[str, str | None]) -> list[MatchHit]:
        """`fields` maps matched_field name -> raw value (src_ip, dst_ip,
        dns_query, tls_sni, http_host). Exact hash first, then CIDR
        containment for the two IP fields."""
        await self._ensure_fresh(redis)
        hits: list[MatchHit] = []

        exact_lookups = {field: value for field, value in fields.items() if value}
        if not exact_lookups:
            return hits

        pipe = redis.pipeline()
        keys = list(exact_lookups.keys())
        for value in exact_lookups.values():
            pipe.hget(EXACT_HASH_KEY, value)
        results = await pipe.execute()

        for field, raw in zip(keys, results):
            if raw:
                ref = IocRef.from_json(raw)
                hits.append(MatchHit(ioc_id=ref.id, severity=ref.severity, matched_value=exact_lookups[field], matched_field=field))

        for field in ("src_ip", "dst_ip"):
            value = fields.get(field)
            if not value:
                continue
            ref = self._match_cidr(value)
            if ref:
                hits.append(MatchHit(ioc_id=ref.id, severity=ref.severity, matched_value=value, matched_field=field))

        return hits


_matcher = Matcher()


def extract_indicator_fields(raw: dict[str, Any], src_ip: str | None, dst_ip: str | None) -> dict[str, str | None]:
    """Pull matchable indicators out of an EVE record. DNS/TLS/HTTP fields
    are attacker-influenced strings — used only as lookup keys here, never
    rendered, so no escaping concern at this layer."""
    dns = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}
    tls = raw.get("tls") if isinstance(raw.get("tls"), dict) else {}
    http = raw.get("http") if isinstance(raw.get("http"), dict) else {}

    dns_query = dns.get("rrname")
    if not dns_query and isinstance(dns.get("queries"), list) and dns["queries"]:
        dns_query = dns["queries"][0].get("rrname")

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dns_query": dns_query.lower().rstrip(".") if isinstance(dns_query, str) else None,
        "tls_sni": tls.get("sni").lower() if isinstance(tls.get("sni"), str) else None,
        "http_host": http.get("hostname").lower() if isinstance(http.get("hostname"), str) else None,
    }


async def match_event_row(redis: aioredis.Redis, row: dict[str, Any]) -> list[MatchHit]:
    """Match one about-to-be-inserted event row and mutate it in place with
    `ioc_match` / `ioc_severity`, escalating `severity` but never downgrading
    it. Returns the hits so the caller can write the evidence trail once the
    row's real `id` is known (post-insert)."""
    fields = extract_indicator_fields(row.get("raw") or {}, row.get("src_ip"), row.get("dst_ip"))
    hits = await _matcher.match_fields(redis, fields)

    if hits:
        top_severity = max((h.severity for h in hits), key=lambda s: _SEVERITY_RANK.get(s, 0))
        row["ioc_match"] = True
        row["ioc_severity"] = top_severity
        row["severity"] = _escalate(row["severity"], top_severity)
    else:
        row["ioc_match"] = False

    return hits


async def publish_hits(redis: aioredis.Redis, event_id: int, hits: list[MatchHit]) -> None:
    for hit in hits:
        await redis.publish(
            HITS_CHANNEL,
            json.dumps({"event_id": event_id, "ioc_id": hit.ioc_id, "severity": hit.severity, "matched_field": hit.matched_field}),
        )


async def match_pcap_artifacts(db: AsyncSession, redis: aioredis.Redis, pcap_id: Any) -> int:
    """Retrospective matching of one capture's artifacts against current
    intel, run once after M11 parsing completes."""
    from app.models.pcap import ArtifactType, PcapArtifact
    from app.models.ioc import IocMatch

    field_by_artifact_type = {
        ArtifactType.DNS_QUERY: "dns_query",
        ArtifactType.TLS_SNI: "tls_sni",
        ArtifactType.HTTP_REQUEST: "http_host",
    }

    artifacts = (
        await db.execute(
            select(PcapArtifact).where(
                PcapArtifact.pcap_id == pcap_id,
                PcapArtifact.artifact_type.in_(list(field_by_artifact_type.keys())),
            )
        )
    ).scalars().all()

    matches = 0
    for artifact in artifacts:
        field = field_by_artifact_type[artifact.artifact_type]
        value = artifact.value.lower() if artifact.artifact_type != ArtifactType.HTTP_REQUEST else artifact.value
        hits = await _matcher.match_fields(redis, {field: value})
        for hit in hits:
            db.add(
                IocMatch(
                    ioc_id=hit.ioc_id, pcap_artifact_id=artifact.id,
                    matched_value=hit.matched_value, matched_field=hit.matched_field,
                )
            )
            matches += 1

    if matches:
        await db.commit()
    return matches


async def retrohunt(
    db: AsyncSession, redis: aioredis.Redis, *, ioc_id: Any | None, source_id: Any | None, days: int
) -> int:
    """Scan the last `days` of events against a specific IOC or a whole
    source. Answers "were we already talking to it?" the moment a new
    indicator lands — the first question after any new threat intel."""
    from datetime import timedelta

    from app.models.event import Event
    from app.models.ioc import IocMatch

    since = datetime.now(timezone.utc) - timedelta(days=days)

    ioc_stmt = select(Ioc)
    if ioc_id:
        ioc_stmt = ioc_stmt.where(Ioc.id == ioc_id)
    elif source_id:
        ioc_stmt = ioc_stmt.where(Ioc.source_id == source_id)
    iocs = (await db.execute(ioc_stmt)).scalars().all()

    matches = 0
    for ioc in iocs:
        if ioc.ioc_type == IocType.CIDR:
            continue  # exact-match retro-hunt only; CIDR sweep is a full table scan best left to the live matcher

        stmt = select(Event).where(
            Event.ts >= since,
            (Event.src_ip == ioc.indicator) | (Event.dst_ip == ioc.indicator)
            if ioc.ioc_type == IocType.IP
            else cast(Event.raw, Text).ilike(f"%{ioc.indicator}%"),
        )
        events = (await db.execute(stmt.limit(10_000))).scalars().all()
        for event in events:
            if ioc.ioc_type == IocType.IP:
                matched_field = "src_ip" if event.src_ip == ioc.indicator else "dst_ip"
            else:
                matched_field = "raw"
            db.add(
                IocMatch(
                    ioc_id=ioc.id, event_id=event.id, matched_value=ioc.indicator, matched_field=matched_field, ts=event.ts,
                )
            )
            matches += 1

    if matches:
        await db.commit()
    return matches
