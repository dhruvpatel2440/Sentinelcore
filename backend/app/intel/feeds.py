"""M12 feed ingestion.

A feed is third-party input into a security control — treat it as untrustworthy
as any other network input. Fetched over HTTPS with certificate verification,
a timeout and a response-size cap; parsed with a row cap; every indicator
normalized before it ever reaches the `ioc` table.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis import get_redis
from app.intel.matcher import rebuild_index
from app.intel.normalize import NormalizationError, normalize
from app.models.ioc import Ioc, IocSource, SourceFormat

logger = logging.getLogger("sentinelcore.intel.feeds")


class FeedFetchError(Exception):
    pass


async def _fetch_body(url: str) -> str:
    """Stream the response so a feed cannot be a decompression/size bomb."""
    max_bytes = settings.intel_feed_max_response_mb * 1024 * 1024
    timeout = httpx.Timeout(settings.intel_feed_timeout_seconds)

    # verify=True (the default) enforces certificate validation.
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        async with client.stream("GET", url) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise FeedFetchError(f"response exceeded {settings.intel_feed_max_response_mb}MB cap")
                chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _parse_csv(body: str, config: dict) -> list[dict]:
    delimiter = config.get("delimiter", ",")
    skip_rows = int(config.get("skip_rows", 0))
    indicator_col = config.get("indicator_column", 0)
    confidence_col = config.get("confidence_column")

    reader = csv.reader(io.StringIO(body), delimiter=delimiter)
    rows = list(reader)[skip_rows:][: settings.intel_feed_row_cap]

    out = []
    for row in rows:
        if not row or (isinstance(indicator_col, int) and indicator_col >= len(row)):
            continue
        indicator = row[indicator_col] if isinstance(indicator_col, int) else None
        if not indicator or indicator.startswith("#"):
            continue
        entry = {"indicator": indicator.strip()}
        if confidence_col is not None and isinstance(confidence_col, int) and confidence_col < len(row):
            try:
                entry["confidence"] = int(row[confidence_col])
            except ValueError:
                pass
        out.append(entry)
    return out


def _parse_txt(body: str, config: dict) -> list[dict]:
    lines = body.splitlines()[: settings.intel_feed_row_cap]
    out = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append({"indicator": line})
    return out


def _parse_json(body: str, config: dict) -> list[dict]:
    data = json.loads(body)
    items = data if isinstance(data, list) else data.get(config.get("list_key", "indicators"), [])
    indicator_key = config.get("indicator_key", "indicator")
    confidence_key = config.get("confidence_key")
    threat_type_key = config.get("threat_type_key")

    out = []
    for item in items[: settings.intel_feed_row_cap]:
        if not isinstance(item, dict) or indicator_key not in item:
            continue
        entry = {"indicator": str(item[indicator_key]).strip()}
        if confidence_key and confidence_key in item:
            try:
                entry["confidence"] = int(item[confidence_key])
            except (TypeError, ValueError):
                pass
        if threat_type_key and threat_type_key in item:
            entry["threat_type"] = str(item[threat_type_key])
        out.append(entry)
    return out


_PARSERS = {
    SourceFormat.CSV: _parse_csv,
    SourceFormat.TXT: _parse_txt,
    SourceFormat.JSON: _parse_json,
    # MISP/STIX intentionally out of scope for v1 parsing depth; treated as
    # JSON-shaped feeds with a caller-supplied parser_config until then.
    SourceFormat.MISP: _parse_json,
    SourceFormat.STIX: _parse_json,
}


async def expire_stale_iocs(db: AsyncSession, redis: aioredis.Redis | None = None) -> int:
    """Deactivate IOCs past `expires_at`. Absence from a feed's latest fetch
    is never treated as a retraction — a truncated download looks identical
    to a real one, so only an explicit expiry removes an indicator."""
    from sqlalchemy import update

    now = datetime.now(timezone.utc)
    result = await db.execute(
        update(Ioc)
        .where(Ioc.is_active.is_(True), Ioc.expires_at.is_not(None), Ioc.expires_at <= now)
        .values(is_active=False)
    )
    await db.commit()
    if result.rowcount:
        await rebuild_index(db, redis or get_redis())
    return result.rowcount or 0


async def refresh_source(db: AsyncSession, source: IocSource, redis: aioredis.Redis | None = None) -> dict:
    """Fetch, normalize and upsert one source. Never raises — failures are
    recorded on the source row so a broken feed never stops the others."""
    now = datetime.now(timezone.utc)
    accepted = 0
    rejected = 0

    try:
        body = await _fetch_body(source.url)
        parser = _PARSERS.get(source.format)
        if parser is None:
            raise FeedFetchError(f"no parser for format {source.format}")
        rows = parser(body, source.parser_config or {})

        for row in rows:
            try:
                normalized = normalize(row["indicator"])
            except NormalizationError as exc:
                rejected += 1
                logger.info("feed %s rejected '%s': %s", source.name, row["indicator"], exc.reason)
                continue

            confidence = row.get("confidence", source.default_confidence)
            threat_type = row.get("threat_type")
            expires_at = now + timedelta(days=source.ttl_days)

            existing = (
                await db.execute(
                    select(Ioc).where(
                        Ioc.indicator == normalized.value,
                        Ioc.ioc_type == normalized.ioc_type,
                        Ioc.source_id == source.id,
                    )
                )
            ).scalar_one_or_none()

            if existing is not None:
                existing.last_seen = now
                existing.confidence = confidence
                existing.expires_at = expires_at
                existing.is_active = True
                if threat_type:
                    existing.threat_type = threat_type
            else:
                db.add(
                    Ioc(
                        indicator=normalized.value,
                        ioc_type=normalized.ioc_type,
                        cidr_shadow=normalized.cidr_shadow,
                        source_id=source.id,
                        confidence=confidence,
                        severity=source.default_severity,
                        threat_type=threat_type,
                        first_seen=now,
                        last_seen=now,
                        expires_at=expires_at,
                        is_active=True,
                    )
                )
            accepted += 1

        count = (
            await db.execute(select(Ioc).where(Ioc.source_id == source.id, Ioc.is_active.is_(True)))
        ).scalars().all()

        source.last_status = "ok"
        source.last_error = None
        source.last_fetch_at = now
        source.indicator_count = len(count)
        await db.commit()
        await rebuild_index(db, redis or get_redis())

        logger.info("feed %s refreshed: %d accepted, %d rejected", source.name, accepted, rejected)
        return {"accepted": accepted, "rejected": rejected}

    except Exception as exc:  # noqa: BLE001 — one broken feed must never stop the others
        await db.rollback()
        source.last_status = "error"
        source.last_error = str(exc)[:2000]
        source.last_fetch_at = now
        await db.commit()
        logger.error("feed %s refresh failed: %s", source.name, exc)
        return {"accepted": 0, "rejected": 0, "error": str(exc)}
