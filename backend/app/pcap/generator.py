"""M11 — orchestrates parsing a queued capture: metadata, the combined
field-extraction pass, asset enrichment, and truncation bookkeeping. Runs in
the worker container, never inline on an API request — a 400MB capture must
never block the upload response."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.models.asset import Asset
from app.models.pcap import PcapArtifact, PcapFile, PcapFlow, PcapStatus
from app.pcap import parser

logger = logging.getLogger("sentinelcore.pcap.generator")


async def _asset_map(db: AsyncSession) -> dict[str, uuid.UUID]:
    rows = (await db.execute(select(Asset.id, Asset.ip_address))).all()
    return {str(ip): asset_id for asset_id, ip in rows}


def _epoch_to_dt(value: float | None) -> datetime | None:
    return datetime.fromtimestamp(value, tz=timezone.utc) if value is not None else None


async def parse_pcap(pcap_id: uuid.UUID, sessionmaker: async_sessionmaker[AsyncSession], redis: aioredis.Redis) -> None:
    async with sessionmaker() as db:
        pcap = await db.get(PcapFile, pcap_id)
        if pcap is None or pcap.status != PcapStatus.UPLOADED:
            return
        pcap.status = PcapStatus.PARSING
        await db.commit()

    path = Path(pcap.stored_path)
    try:
        await redis.set(f"pcap:progress:{pcap_id}", 5)
        metadata = await parser.parse_metadata(path)
        await redis.set(f"pcap:progress:{pcap_id}", 15)

        result = await parser.run_field_extraction(path, pcap_id=str(pcap_id), redis=redis)
        await redis.set(f"pcap:progress:{pcap_id}", 90)

        async with sessionmaker() as db:
            asset_map = await _asset_map(db)

            flows = sorted(result.flows.values(), key=lambda f: f.byte_count, reverse=True)
            truncated = len(flows) > settings.max_flows_per_pcap
            flows = flows[: settings.max_flows_per_pcap]

            # stream key (protocol, stream_id) -> new PcapFlow.id, needed to
            # link artifacts to the flow they were observed on.
            flow_id_by_stream: dict[tuple[str, int], uuid.UUID] = {}
            flow_rows = []
            for f in flows:
                flow_id = uuid.uuid4()
                flow_id_by_stream[(f.protocol, f.stream_id)] = flow_id
                flow_rows.append(
                    {
                        "id": flow_id, "pcap_id": pcap_id, "stream_id": f.stream_id, "protocol": f.protocol,
                        "src_ip": f.src_ip or "0.0.0.0", "src_port": f.src_port, "dst_ip": f.dst_ip or "0.0.0.0",
                        "dst_port": f.dst_port, "packet_count": f.packet_count, "byte_count": f.byte_count,
                        "start_ts": _epoch_to_dt(f.start_ts), "end_ts": _epoch_to_dt(f.end_ts),
                        "duration_ms": int((f.end_ts - f.start_ts) * 1000) if f.start_ts and f.end_ts else None,
                        "app_protocol": next(iter(f.app_protocols), None),
                        "summary": f"{f.packet_count} packets, {f.byte_count} bytes",
                        "src_asset_id": asset_map.get(f.src_ip or ""), "dst_asset_id": asset_map.get(f.dst_ip or ""),
                    }
                )
            if flow_rows:
                await db.execute(pg_insert(PcapFlow), flow_rows)

            artifact_rows = []
            for a in result.artifacts:
                stream_key = a.pop("stream_key", None)
                flow_id = flow_id_by_stream.get(stream_key) if stream_key else None
                artifact_rows.append(
                    {
                        "id": uuid.uuid4(), "pcap_id": pcap_id, "flow_id": flow_id,
                        "artifact_type": a["artifact_type"], "value": a["value"][:4000],
                        "detail": a.get("detail"), "packet_number": a.get("packet_number"),
                        "ts": _epoch_to_dt(a.get("ts")),
                    }
                )
            if artifact_rows:
                await db.execute(pg_insert(PcapArtifact), artifact_rows)

            pcap = await db.get(PcapFile, pcap_id)
            pcap.status = PcapStatus.PARSED
            pcap.packet_count = metadata["packet_count"]
            pcap.link_type = metadata["link_type"]
            pcap.first_packet_ts = metadata["first_packet_ts"]
            pcap.last_packet_ts = metadata["last_packet_ts"]
            pcap.duration_seconds = metadata["duration_seconds"]
            pcap.flow_truncated = truncated
            pcap.parsed_at = datetime.now(timezone.utc)
            await db.commit()

        await redis.set(f"pcap:progress:{pcap_id}", 100)
        logger.info(
            "pcap %s parsed: %d flows (truncated=%s), %d artifacts",
            pcap_id, len(flow_rows), truncated, len(artifact_rows),
        )

    except Exception as exc:  # noqa: BLE001 — must always resolve the row
        logger.error("pcap %s parse failed: %s", pcap_id, exc)
        async with sessionmaker() as db:
            pcap = await db.get(PcapFile, pcap_id)
            if pcap is not None:
                pcap.status = PcapStatus.FAILED
                pcap.error = str(exc)[:4000]
                await db.commit()


async def reconcile_stuck_pcaps(sessionmaker: async_sessionmaker[AsyncSession]) -> int:
    """Startup safety net: a worker crash mid-parse must not leave a row in
    `parsing` forever."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.pcap_parse_timeout_seconds * 2)
    async with sessionmaker() as db:
        stuck = (
            await db.execute(
                select(PcapFile).where(PcapFile.status == PcapStatus.PARSING, PcapFile.uploaded_at < cutoff)
            )
        ).scalars().all()
        for pcap in stuck:
            pcap.status = PcapStatus.FAILED
            pcap.error = "worker restarted mid-parse"
        if stuck:
            await db.commit()
        return len(stuck)


async def enforce_pcap_retention(sessionmaker: async_sessionmaker[AsyncSession]) -> int:
    """Deletes captures past PCAP_RETENTION_DAYS unless attached to an open
    incident — an open investigation's evidence must not vanish underneath it."""
    from app.models.incident import TERMINAL_STATUSES, Incident

    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.pcap_retention_days)
    async with sessionmaker() as db:
        candidates = (
            await db.execute(select(PcapFile).where(PcapFile.uploaded_at <= cutoff))
        ).scalars().all()

        removed = 0
        for pcap in candidates:
            if pcap.incident_id is not None:
                incident = await db.get(Incident, pcap.incident_id)
                if incident is not None and incident.status not in TERMINAL_STATUSES:
                    continue
            try:
                Path(pcap.stored_path).unlink(missing_ok=True)
            except OSError as exc:
                logger.warning("could not remove expired pcap file %s: %s", pcap.stored_path, exc)
            await db.delete(pcap)
            removed += 1
        if removed:
            await db.commit()
        return removed


async def run_forever(
    sessionmaker: async_sessionmaker[AsyncSession], redis: aioredis.Redis, stop: asyncio.Event
) -> None:
    logger.info("pcap parser starting, queue=%s", settings.pcap_queue_key)
    reconciled = await reconcile_stuck_pcaps(sessionmaker)
    if reconciled:
        logger.info("reconciled %d stuck pcap(s) on startup", reconciled)

    while not stop.is_set():
        try:
            item = await redis.brpop(settings.pcap_queue_key, timeout=5)
        except Exception as exc:  # noqa: BLE001
            logger.error("pcap queue read failed: %s", exc)
            await asyncio.sleep(1)
            continue

        if item is None:
            continue
        _, raw_id = item
        try:
            pcap_id = uuid.UUID(raw_id.decode() if isinstance(raw_id, bytes) else raw_id)
            await parse_pcap(pcap_id, sessionmaker, redis)
        except Exception as exc:  # noqa: BLE001 — one bad queue item must not kill the loop
            logger.error("failed to process pcap queue item %r: %s", raw_id, exc)
