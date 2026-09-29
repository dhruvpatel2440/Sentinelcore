"""Tail eve.json into a Redis Stream.

The buffer exists so a slow or unavailable database cannot stall the reader and
let Suricata's log grow unbounded.

Rotation is the single most common cause of silent event loss, so it is handled
explicitly rather than hoped about:

  * logrotate `create`       — path gets a NEW inode. Detected via (st_dev,
                               st_ino); the old handle is drained first, then
                               reopened at offset 0.
  * logrotate `copytruncate` — SAME inode, size reset to 0. Detected via
                               st_size < offset; seek back to 0.

Both are handled, so either rotation strategy is safe (see
docker/suricata/logrotate.conf).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger("sentinelcore.pipeline.tailer")

STREAM_KEY = "stream:events"
OFFSET_KEY = "pipeline:eve:offset"
METRICS_KEY = "pipeline:metrics"

# Cap the buffer so an unavailable consumer cannot exhaust Redis memory.
STREAM_MAXLEN = 500_000

BATCH_LINES = 500
IDLE_SLEEP_SECONDS = 0.5
MAX_LINE_BYTES = 1024 * 1024


@dataclass
class FileIdentity:
    dev: int
    ino: int

    @classmethod
    def of(cls, stat: os.stat_result) -> FileIdentity:
        return cls(dev=stat.st_dev, ino=stat.st_ino)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, FileIdentity) and self.dev == other.dev and self.ino == other.ino
        )


class EveTailer:
    def __init__(self, path: str | Path, redis: aioredis.Redis) -> None:
        self.path = Path(path)
        self.redis = redis
        self._handle = None
        self._identity: FileIdentity | None = None
        self._offset = 0
        self._stopping = False

        self.lines_read = 0
        self.parse_errors = 0
        self.rotations = 0

    # ------------------------------------------------------------------
    # Offset persistence
    # ------------------------------------------------------------------

    async def _load_offset(self) -> tuple[int, FileIdentity | None]:
        """Resume where the last run stopped, rather than replaying or skipping."""
        try:
            raw = await self.redis.get(OFFSET_KEY)
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not read persisted offset: %s", exc)
            return 0, None
        if not raw:
            return 0, None
        try:
            saved = json.loads(raw)
            identity = FileIdentity(dev=int(saved["dev"]), ino=int(saved["ino"]))
            return int(saved["offset"]), identity
        except (ValueError, KeyError, TypeError):
            logger.warning("persisted offset is malformed; starting from 0")
            return 0, None

    async def _save_offset(self) -> None:
        if self._identity is None:
            return
        payload = json.dumps(
            {"offset": self._offset, "dev": self._identity.dev, "ino": self._identity.ino}
        )
        try:
            await self.redis.set(OFFSET_KEY, payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not persist offset: %s", exc)

    # ------------------------------------------------------------------
    # File handling
    # ------------------------------------------------------------------

    def _close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            finally:
                self._handle = None

    async def _open(self) -> bool:
        """Open the log and position the cursor. False when it does not exist yet."""
        try:
            stat = self.path.stat()
        except (OSError, FileNotFoundError):
            return False

        identity = FileIdentity.of(stat)
        saved_offset, saved_identity = await self._load_offset()

        self._close()
        self._handle = self.path.open("rb")
        self._identity = identity

        if saved_identity is not None and saved_identity == identity:
            # Same file as last run: resume, unless it shrank underneath us.
            self._offset = min(saved_offset, stat.st_size)
            if saved_offset > stat.st_size:
                logger.warning(
                    "persisted offset %d exceeds file size %d; treating as truncation",
                    saved_offset,
                    stat.st_size,
                )
                self._offset = 0
        else:
            # Different inode (or first run). A new file starts at 0; there is
            # no safe way to resume into a file we have never seen.
            self._offset = 0

        self._handle.seek(self._offset)
        logger.info(
            "opened %s at offset %d (dev=%d ino=%d)",
            self.path,
            self._offset,
            identity.dev,
            identity.ino,
        )
        return True

    def _rotation_state(self) -> str:
        """'same' | 'rotated' | 'truncated' | 'missing'."""
        try:
            stat = self.path.stat()
        except (OSError, FileNotFoundError):
            return "missing"

        if self._identity is not None and FileIdentity.of(stat) != self._identity:
            return "rotated"
        if stat.st_size < self._offset:
            return "truncated"
        return "same"

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def _read_lines(self, limit: int) -> list[bytes]:
        """Read up to `limit` COMPLETE lines. A trailing partial line is left
        in place, with the offset unadvanced, so the next pass re-reads it."""
        if self._handle is None:
            return []

        lines: list[bytes] = []
        while len(lines) < limit:
            position = self._handle.tell()
            line = self._handle.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if not line.endswith(b"\n"):
                # Partial write in progress — rewind and wait for the newline.
                self._handle.seek(position)
                break
            lines.append(line)
            self._offset = self._handle.tell()
        return lines

    async def _publish(self, lines: list[bytes]) -> int:
        """Push raw records onto the stream. Malformed lines are counted, not fatal."""
        published = 0
        pipe = self.redis.pipeline(transaction=False)

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                # Parsed only to validate; the raw bytes are what we forward.
                json.loads(stripped)
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Suricata can emit a partial line if killed mid-write.
                self.parse_errors += 1
                continue

            pipe.xadd(
                STREAM_KEY,
                {b"record": stripped},
                maxlen=STREAM_MAXLEN,
                approximate=True,
            )
            published += 1

        if published:
            await pipe.execute()
        return published

    async def _publish_metrics(self) -> None:
        try:
            await self.redis.hset(
                METRICS_KEY,
                mapping={
                    "lines_read": self.lines_read,
                    "parse_errors": self.parse_errors,
                    "rotations": self.rotations,
                    "tailer_heartbeat": asyncio.get_running_loop().time(),
                    "tailer_offset": self._offset,
                },
            )
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def stop(self) -> None:
        self._stopping = True

    async def run(self) -> None:
        logger.info("tailer starting on %s", self.path)

        while not self._stopping:
            if self._handle is None:
                if not await self._open():
                    logger.info("waiting for %s to appear", self.path)
                    await asyncio.sleep(2.0)
                    continue

            lines = self._read_lines(BATCH_LINES)

            if lines:
                self.lines_read += len(lines)
                await self._publish(lines)
                # Offset is persisted only AFTER the records are on the stream,
                # so a crash re-reads rather than skips. dedup_key makes the
                # replay harmless.
                await self._save_offset()
                await self._publish_metrics()
                continue

            # Nothing new — check whether the file moved under us.
            state = self._rotation_state()

            if state == "rotated":
                # Drain the remaining lines from the OLD handle before
                # reopening, or everything written between the last read and
                # the rename is lost forever.
                drained = self._read_lines(BATCH_LINES * 10)
                if drained:
                    self.lines_read += len(drained)
                    await self._publish(drained)
                    logger.info("drained %d line(s) from the rotated file", len(drained))

                self.rotations += 1
                logger.info("log rotation detected; reopening %s", self.path)
                self._close()
                self._identity = None
                self._offset = 0
                await self._save_offset()
                continue

            if state == "truncated":
                self.rotations += 1
                logger.info("truncation detected (copytruncate); seeking to 0")
                self._offset = 0
                if self._handle is not None:
                    self._handle.seek(0)
                await self._save_offset()
                continue

            if state == "missing":
                logger.warning("%s disappeared; waiting for it to return", self.path)
                self._close()
                self._identity = None
                await asyncio.sleep(2.0)
                continue

            await self._publish_metrics()
            await asyncio.sleep(IDLE_SLEEP_SECONDS)

        self._close()
        logger.info("tailer stopped")


async def run_tailer(redis: aioredis.Redis) -> None:
    tailer = EveTailer(settings.suricata_eve_log, redis)
    await tailer.run()
