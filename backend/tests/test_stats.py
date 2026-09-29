"""U05 — dashboard top-talkers stats.

Same seed/cleanup pattern as test_correlation.py: real DB, synthetic rows
tagged with a per-test-unique `category`, deleted afterwards. The Redis
facet-cache is cleared before each test since the cache key does not
include `category` (top-talkers windows by time only, same as
`/events/facets`) — without clearing it, two tests hitting the same
window/by/limit/exclude_infra combo within the 30s TTL bucket would read
each other's stale results.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text

import pytest_asyncio

from app.api.routes.stats import TopTalkersBy, get_top_talkers
from app.core import redis as redis_module
from app.core.redis import get_redis
from app.db.session import SessionLocal
from app.models.user import User, UserRole

UTC = timezone.utc


@pytest_asyncio.fixture(autouse=True)
async def _reset_redis_client_after_test():
    """`get_redis()` is a process-wide singleton bound to whichever event
    loop first created it. pytest-asyncio (strict mode) gives every test
    function its own loop, so the module-level client must be torn down and
    forced to lazily recreate on the next test's loop — same reasoning as
    conftest.py's `_dispose_engine_after_test` for the DB engine."""
    yield
    if redis_module._client is not None:
        await redis_module._client.aclose()
        redis_module._client = None


async def _insert_events(db, category: str, events: list[dict]) -> list[int]:
    ids = []
    for i, e in enumerate(events):
        dedup = hashlib.sha256(f"{category}-{i}-{uuid.uuid4()}".encode()).digest()
        row = {
            "ts": e["ts"],
            "event_type": e.get("event_type", "alert"),
            "src_ip": e.get("src_ip"),
            "dst_ip": e.get("dst_ip"),
            "src_port": e.get("src_port"),
            "dst_port": e.get("dst_port"),
            "proto": e.get("proto", "tcp"),
            "signature": e.get("signature", "test signature"),
            "signature_id": e.get("signature_id", 9300000),
            "rev": 1,
            "category": category,
            "severity": e.get("severity", "medium"),
            "flow_id": e.get("flow_id"),
            "ioc_match": e.get("ioc_match", False),
            "dedup_key": dedup,
            "raw": "{}",
        }
        result = await db.execute(
            text(
                """
                INSERT INTO events (ts, event_type, src_ip, dst_ip, src_port, dst_port, proto,
                    signature, signature_id, rev, category, severity, flow_id, ioc_match, dedup_key, raw)
                VALUES (:ts, :event_type, :src_ip, :dst_ip, :src_port, :dst_port, :proto,
                    :signature, :signature_id, :rev, :category, :severity, :flow_id, :ioc_match, :dedup_key, :raw)
                RETURNING id
                """
            ),
            row,
        )
        ids.append(result.scalar_one())
    await db.commit()
    return ids


async def _cleanup_events(db, category: str) -> None:
    # If the test body raised mid-transaction, the session is left in
    # Postgres's "aborted" state and any further statement (including this
    # cleanup DELETE) is rejected until rolled back — which would silently
    # orphan this category's rows for every future test run to trip over.
    await db.rollback()
    await db.execute(text("DELETE FROM events WHERE category = :c"), {"c": category})
    await db.commit()


async def _clear_top_talkers_cache() -> None:
    redis = get_redis()
    async for key in redis.scan_iter(match="stats:top-talkers:*"):
        await redis.delete(key)


async def _admin_user(db) -> User:
    user = (await db.execute(select(User).where(User.role == UserRole.ADMIN))).scalars().first()
    assert user is not None, "expected a seeded admin user"
    return user


@pytest.mark.asyncio
async def test_top_talkers_orders_by_count_desc_and_counts_correctly():
    category = f"u05-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        await _insert_events(
            db,
            category,
            [
                {"ts": now, "src_ip": "203.0.113.10"},
                {"ts": now, "src_ip": "203.0.113.10"},
                {"ts": now, "src_ip": "203.0.113.10"},
                {"ts": now, "src_ip": "203.0.113.20"},
            ],
        )
        try:
            await _clear_top_talkers_cache()
            result = await get_top_talkers(
                window="1h", limit=10, by=TopTalkersBy.SRC, exclude_infra=False, db=db, _=admin
            )
            by_value = {item.value: item.count for item in result.items}
            assert by_value.get("203.0.113.10") == 3
            assert by_value.get("203.0.113.20") == 1
            assert result.items[0].value == "203.0.113.10"
            assert result.by == "src"
            assert result.window == "1h"
        finally:
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_top_talkers_window_boundary_excludes_older_events():
    category = f"u05-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        await _insert_events(
            db,
            category,
            [
                {"ts": now, "src_ip": "203.0.113.30"},
                # Outside a 1h window but inside 24h — must not appear in the 1h query.
                {"ts": now - timedelta(hours=2), "src_ip": "203.0.113.40"},
            ],
        )
        try:
            await _clear_top_talkers_cache()
            result = await get_top_talkers(
                window="1h", limit=10, by=TopTalkersBy.SRC, exclude_infra=False, db=db, _=admin
            )
            values = {item.value for item in result.items}
            assert "203.0.113.30" in values
            assert "203.0.113.40" not in values
        finally:
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_top_talkers_reports_worst_severity_and_ioc_match():
    category = f"u05-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        await _insert_events(
            db,
            category,
            [
                {"ts": now, "src_ip": "203.0.113.50", "severity": "low", "ioc_match": False},
                {"ts": now, "src_ip": "203.0.113.50", "severity": "critical", "ioc_match": True},
            ],
        )
        try:
            await _clear_top_talkers_cache()
            result = await get_top_talkers(
                window="1h", limit=10, by=TopTalkersBy.SRC, exclude_infra=False, db=db, _=admin
            )
            item = next(i for i in result.items if i.value == "203.0.113.50")
            assert item.count == 2
            assert item.max_severity == "critical"
            assert item.ioc_match is True
        finally:
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_top_talkers_by_signature():
    category = f"u05-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        await _insert_events(
            db,
            category,
            [
                {"ts": now, "src_ip": "203.0.113.60", "signature": f"{category}-sig-A"},
                {"ts": now, "src_ip": "203.0.113.61", "signature": f"{category}-sig-A"},
                {"ts": now, "src_ip": "203.0.113.62", "signature": f"{category}-sig-B"},
            ],
        )
        try:
            await _clear_top_talkers_cache()
            result = await get_top_talkers(
                window="1h", limit=10, by=TopTalkersBy.SIGNATURE, exclude_infra=False, db=db, _=admin
            )
            by_value = {item.value: item.count for item in result.items}
            assert by_value.get(f"{category}-sig-A") == 2
            assert by_value.get(f"{category}-sig-B") == 1
        finally:
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_exclude_infra_removes_protected_ips():
    from app.core.config import settings

    infra_ips = list(settings.protected_ips_parsed)
    if not infra_ips:
        pytest.skip("no PROTECTED_IPS configured in this environment")
    infra_ip = str(infra_ips[0])

    category = f"u05-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        await _insert_events(
            db,
            category,
            [
                {"ts": now, "src_ip": infra_ip},
                {"ts": now, "src_ip": "203.0.113.70"},
            ],
        )
        try:
            await _clear_top_talkers_cache()
            included = await get_top_talkers(
                window="1h", limit=50, by=TopTalkersBy.SRC, exclude_infra=False, db=db, _=admin
            )
            assert infra_ip in {i.value for i in included.items}

            await _clear_top_talkers_cache()
            excluded = await get_top_talkers(
                window="1h", limit=50, by=TopTalkersBy.SRC, exclude_infra=True, db=db, _=admin
            )
            assert infra_ip not in {i.value for i in excluded.items}
            assert "203.0.113.70" in {i.value for i in excluded.items}
        finally:
            await _cleanup_events(db, category)


@pytest.mark.asyncio
async def test_cache_hit_marks_second_call_as_cached():
    category = f"u05-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        await _insert_events(db, category, [{"ts": now, "src_ip": "203.0.113.80"}])
        try:
            await _clear_top_talkers_cache()
            first = await get_top_talkers(
                window="1h", limit=10, by=TopTalkersBy.SRC, exclude_infra=False, db=db, _=admin
            )
            second = await get_top_talkers(
                window="1h", limit=10, by=TopTalkersBy.SRC, exclude_infra=False, db=db, _=admin
            )
            assert first.cached is False
            assert second.cached is True
        finally:
            await _cleanup_events(db, category)
            await _clear_top_talkers_cache()
