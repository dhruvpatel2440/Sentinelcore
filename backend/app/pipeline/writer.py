"""Consume the Redis Stream and batch-insert into `events`.

At-least-once delivery with idempotency:
  * XREADGROUP so an unacked batch is redelivered after a crash
  * INSERT ... ON CONFLICT (dedup_key, ts) DO NOTHING makes replay harmless
  * XACK only AFTER the transaction commits — acking first turns a rollback
    into silent data loss
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import ResponseError
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import SessionLocal
from app.models.asset import Asset
from app.models.event import Event
from app.pipeline.normalize import NormalizeError, normalize
from app.pipeline.tailer import METRICS_KEY, STREAM_KEY

logger = logging.getLogger("sentinelcore.pipeline.writer")

GROUP_NAME = "events-writer"
CONSUMER_NAME = "writer-1"

BATCH_SIZE = 500
BATCH_TIMEOUT_MS = 2000

ASSET_CACHE_KEY = "pipeline:asset_map"
ASSET_CACHE_TTL_SECONDS = 300

# Redelivery of anything pending for longer than this (a crashed consumer).
CLAIM_MIN_IDLE_MS = 60_000


class EventWriter:
    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self._stopping = False

        self.events_written = 0
        self.duplicates_skipped = 0
        self.parse_errors = 0
        self.batches = 0

        self._asset_map: dict[str, str] = {}
        self._asset_map_loaded_at = 0.0

    def stop(self) -> None:
        self._stopping = True

    # ------------------------------------------------------------------
    # Consumer group
    # ------------------------------------------------------------------

    async def ensure_group(self) -> None:
        try:
            await self.redis.xgroup_create(STREAM_KEY, GROUP_NAME, id="0", mkstream=True)
            logger.info("created consumer group %s on %s", GROUP_NAME, STREAM_KEY)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
            logger.info("consumer group %s already exists", GROUP_NAME)

    # ------------------------------------------------------------------
    # Asset enrichment
    # ------------------------------------------------------------------

    async def _refresh_asset_map(self, db: AsyncSession) -> None:
        """IP → asset_id, cached on a TTL. M3 invalidates it after a scan."""
        now = time.monotonic()
        if self._asset_map and (now - self._asset_map_loaded_at) < ASSET_CACHE_TTL_SECONDS:
            invalidated = await self.redis.get(f"{ASSET_CACHE_KEY}:dirty")
            if not invalidated:
                return
            await self.redis.delete(f"{ASSET_CACHE_KEY}:dirty")

        rows = (await db.execute(select(Asset.id, Asset.ip_address))).all()
        self._asset_map = {str(ip): str(asset_id) for asset_id, ip in rows}
        self._asset_map_loaded_at = now
        logger.debug("asset map refreshed: %d entries", len(self._asset_map))

    def _enrich(self, row: dict[str, Any]) -> dict[str, Any]:
        row["src_asset_id"] = self._asset_map.get(row.get("src_ip") or "")
        row["dst_asset_id"] = self._asset_map.get(row.get("dst_ip") or "")
        return row

    # ------------------------------------------------------------------
    # Batch handling
    # ------------------------------------------------------------------

    def _decode(self, fields: dict) -> dict[str, Any] | None:
        raw = fields.get(b"record") or fields.get("record")
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.parse_errors += 1
            return None

    async def _write_batch(self, db: AsyncSession, entries: list[tuple[bytes, dict]]) -> list[bytes]:
        """Insert a batch and return the message ids safe to acknowledge.

        Unparseable records are acked too: they will never succeed on retry,
        and leaving them pending would block the group forever.
        """
        rows: list[dict[str, Any]] = []
        ack_ids: list[bytes] = []

        for message_id, fields in entries:
            ack_ids.append(message_id)
            record = self._decode(fields)
            if record is None:
                continue
            try:
                event = normalize(record)
            except NormalizeError as exc:
                logger.debug("skipping unnormalizable record: %s", exc)
                self.parse_errors += 1
                continue
            if event is None:
                continue  # deliberately ignored type (stats, fileinfo, ...)
            rows.append(self._enrich(event.as_row()))

        if not rows:
            return ack_ids

        # Deduplicate within the batch itself: ON CONFLICT cannot resolve two
        # conflicting rows in the same INSERT statement.
        seen: set[bytes] = set()
        unique_rows = []
        for row in rows:
            if row["dedup_key"] in seen:
                self.duplicates_skipped += 1
                continue
            seen.add(row["dedup_key"])
            unique_rows.append(row)

        stmt = pg_insert(Event).values(unique_rows)
        stmt = stmt.on_conflict_do_nothing(index_elements=["dedup_key", "ts"])
        result = await db.execute(stmt)
        await db.commit()

        inserted = result.rowcount if result.rowcount is not None else len(unique_rows)
        self.events_written += inserted
        self.duplicates_skipped += len(unique_rows) - inserted
        self.batches += 1

        return ack_ids

    async def _publish_metrics(self) -> None:
        try:
            length = await self.redis.xlen(STREAM_KEY)
        except Exception:  # noqa: BLE001
            length = -1
        try:
            pending = await self.redis.xpending(STREAM_KEY, GROUP_NAME)
            pending_count = pending.get("pending", 0) if isinstance(pending, dict) else 0
        except Exception:  # noqa: BLE001
            pending_count = 0

        try:
            await self.redis.hset(
                METRICS_KEY,
                mapping={
                    "events_written": self.events_written,
                    "duplicates_skipped": self.duplicates_skipped,
                    "writer_parse_errors": self.parse_errors,
                    "stream_length": length,
                    "pending": pending_count,
                    "last_write_ts": time.time(),
                    "writer_heartbeat": time.time(),
                },
            )
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def _claim_stale(self) -> list[tuple[bytes, dict]]:
        """Reclaim messages left pending by a failed or crashed consumer.

        XREADGROUP with '>' only ever returns NEW messages, so a batch that was
        deliberately left unacked (a database outage, a crash mid-batch) is
        never retried by the normal read path — it would sit pending forever
        and the events in it would be silently lost. XAUTOCLAIM is what closes
        that hole and makes at-least-once delivery actually hold.
        """
        try:
            result = await self.redis.xautoclaim(
                STREAM_KEY,
                GROUP_NAME,
                CONSUMER_NAME,
                min_idle_time=CLAIM_MIN_IDLE_MS,
                count=BATCH_SIZE,
            )
        except ResponseError as exc:
            if "NOGROUP" in str(exc):
                await self.ensure_group()
            return []
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not reclaim pending messages: %s", exc)
            return []

        # redis-py returns (cursor, messages) on Redis <7 and
        # (cursor, messages, deleted) on >=7.
        messages = result[1] if isinstance(result, (list, tuple)) and len(result) >= 2 else []
        if messages:
            logger.info("reclaimed %d stale pending message(s) for retry", len(messages))
        return list(messages)

    async def run(self) -> None:
        await self.ensure_group()
        logger.info("writer starting (batch=%d timeout=%dms)", BATCH_SIZE, BATCH_TIMEOUT_MS)

        last_claim_check = 0.0

        while not self._stopping:
            # Periodically sweep for stranded messages before reading new ones,
            # so a recovered outage drains rather than stalling forever.
            now = time.monotonic()
            if now - last_claim_check > 30:
                last_claim_check = now
                reclaimed = await self._claim_stale()
                if reclaimed:
                    await self._process(reclaimed)
                    continue

            try:
                response = await self.redis.xreadgroup(
                    GROUP_NAME,
                    CONSUMER_NAME,
                    {STREAM_KEY: ">"},
                    count=BATCH_SIZE,
                    block=BATCH_TIMEOUT_MS,
                )
            except ResponseError as exc:
                if "NOGROUP" in str(exc):
                    await self.ensure_group()
                    continue
                raise
            except Exception as exc:  # noqa: BLE001
                logger.error("stream read failed: %s", exc)
                await asyncio.sleep(2.0)
                continue

            if not response:
                await self._publish_metrics()
                continue

            entries: list[tuple[bytes, dict]] = []
            for _stream, messages in response:
                entries.extend(messages)

            if not entries:
                continue

            await self._process(entries)

        logger.info("writer stopped")

    async def _process(self, entries: list[tuple[bytes, dict]]) -> None:
        """Write one batch and ack it. Shared by the new-message and
        reclaimed-message paths so both get identical commit-then-ack ordering."""
        try:
            async with SessionLocal() as db:
                await self._refresh_asset_map(db)
                ack_ids = await self._write_batch(db, entries)

            # XACK strictly AFTER the commit above. Acking first would turn a
            # rollback into silent data loss.
            if ack_ids:
                await self.redis.xack(STREAM_KEY, GROUP_NAME, *ack_ids)

            await self._publish_metrics()

        except Exception as exc:  # noqa: BLE001
            # Nothing is acked, so the batch stays pending and _claim_stale
            # will retry it once it goes idle. A database outage buffers in the
            # stream instead of losing events.
            logger.error(
                "batch write failed, leaving %d message(s) pending for retry: %s",
                len(entries),
                exc,
            )
            await asyncio.sleep(2.0)


async def run_writer(redis: aioredis.Redis) -> None:
    await EventWriter(redis).run()
