"""M6 event search: cursor codec, keyset boundary logic, window cap, CIDR SQL,
and saved-search ownership enforcement.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy.dialects import postgresql

from app.api.routes.events import _resolve_window, _get_owned_saved_search
from app.core.config import settings
from app.models.event import Event
from app.models.saved_search import SavedSearch
from app.models.user import User, UserRole
from app.services.event_search import (
    CursorError,
    EventFilters,
    apply_cursor,
    apply_filters,
    decode_cursor,
    encode_cursor,
    validate_cidr,
)
from sqlalchemy import select

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Cursor encode/decode round trip
# ---------------------------------------------------------------------------


def test_cursor_round_trip():
    ts = datetime(2026, 1, 15, 12, 30, 0, tzinfo=UTC)
    cursor = encode_cursor(ts, 12345)
    decoded_ts, decoded_id = decode_cursor(cursor)
    assert decoded_ts == ts
    assert decoded_id == 12345


def test_cursor_is_opaque_base64_not_raw_json():
    cursor = encode_cursor(datetime.now(UTC), 1)
    assert "{" not in cursor  # not readable JSON on the wire


@pytest.mark.parametrize("bad", ["not-base64!!", "", "aGVsbG8=", "e30="])
def test_malformed_cursor_raises_cursor_error(bad):
    with pytest.raises(CursorError):
        decode_cursor(bad)


# ---------------------------------------------------------------------------
# Keyset boundary correctness with identical timestamps
# ---------------------------------------------------------------------------


def test_keyset_boundary_with_duplicate_timestamps_no_skip_no_repeat():
    """Simulates the exact failure mode OFFSET-based paging has: many rows
    sharing one `ts`. The (ts, id) tuple comparison must never skip or repeat
    a row across a page boundary."""
    tied_ts = datetime(2026, 1, 1, tzinfo=UTC)
    # Descending id within the tie, as ORDER BY ts DESC, id DESC produces.
    rows = [(tied_ts, i) for i in range(10, 0, -1)]

    page_size = 4
    seen: list[tuple[datetime, int]] = []
    cursor = None
    for _ in range(10):  # generous upper bound on pages
        if cursor is None:
            page = rows[:page_size]
        else:
            cursor_ts, cursor_id = cursor
            remaining = [r for r in rows if (r[0], r[1]) < (cursor_ts, cursor_id)]
            page = remaining[:page_size]
        if not page:
            break
        seen.extend(page)
        cursor = page[-1]

    assert seen == rows
    assert len(seen) == len(set(seen))  # no repeats


def test_apply_cursor_descending_filters_strictly_less_than_tuple():
    filters_ts = datetime(2026, 1, 1, tzinfo=UTC)
    cursor = encode_cursor(filters_ts, 500)
    stmt = apply_cursor(select(Event), cursor=cursor, sort_desc=True)
    compiled = str(stmt.compile(dialect=postgresql.dialect())).replace("\n", " ")
    assert "(events.ts, events.id) <" in compiled


def test_apply_cursor_ascending_filters_strictly_greater_than_tuple():
    filters_ts = datetime(2026, 1, 1, tzinfo=UTC)
    cursor = encode_cursor(filters_ts, 500)
    stmt = apply_cursor(select(Event), cursor=cursor, sort_desc=False)
    compiled = str(stmt.compile(dialect=postgresql.dialect())).replace("\n", " ")
    assert "(events.ts, events.id) >" in compiled


def test_no_cursor_is_a_no_op():
    stmt = apply_cursor(select(Event), cursor=None, sort_desc=True)
    compiled = str(stmt.compile(dialect=postgresql.dialect()))
    assert "WHERE" not in compiled


# ---------------------------------------------------------------------------
# Window-cap rejection
# ---------------------------------------------------------------------------


def test_default_window_is_last_24h():
    from_ts, to_ts = _resolve_window(None, None)
    assert to_ts - from_ts == timedelta(hours=24)


def test_window_within_cap_is_accepted():
    to_ts = datetime.now(UTC)
    from_ts = to_ts - timedelta(days=settings.max_search_window_days - 1)
    resolved_from, resolved_to = _resolve_window(from_ts, to_ts)
    assert resolved_from == from_ts


def test_window_wider_than_cap_is_rejected():
    to_ts = datetime.now(UTC)
    from_ts = to_ts - timedelta(days=settings.max_search_window_days + 1)
    with pytest.raises(HTTPException) as exc:
        _resolve_window(from_ts, to_ts)
    assert exc.value.status_code == 422


def test_inverted_window_is_rejected():
    now = datetime.now(UTC)
    with pytest.raises(HTTPException) as exc:
        _resolve_window(now, now - timedelta(hours=1))
    assert exc.value.status_code == 422


def test_window_always_applied_even_with_no_other_filters():
    """`ts` must never be optional at the SQL level, or partition pruning is lost."""
    filters = EventFilters(from_ts=datetime.now(UTC) - timedelta(hours=1), to_ts=datetime.now(UTC))
    stmt = apply_filters(select(Event), filters)
    compiled = str(stmt.compile(dialect=postgresql.dialect()))
    assert "events.ts >=" in compiled
    assert "events.ts <" in compiled


# ---------------------------------------------------------------------------
# CIDR filter SQL
# ---------------------------------------------------------------------------


def test_valid_cidr_and_ip_accepted():
    assert validate_cidr("192.168.10.0/24") == "192.168.10.0/24"
    assert validate_cidr("192.168.10.5") == "192.168.10.5"


def test_invalid_cidr_rejected():
    with pytest.raises(ValueError):
        validate_cidr("not-an-ip")


def test_src_ip_filter_uses_containment_operator():
    filters = EventFilters(
        from_ts=datetime.now(UTC) - timedelta(hours=1),
        to_ts=datetime.now(UTC),
        src_ip="192.168.10.0/24",
    )
    stmt = apply_filters(select(Event), filters)
    compiled = str(stmt.compile(dialect=postgresql.dialect()))
    assert "<<=" in compiled
    assert "events.src_ip" in compiled


def test_ip_filter_matches_either_direction():
    filters = EventFilters(
        from_ts=datetime.now(UTC) - timedelta(hours=1),
        to_ts=datetime.now(UTC),
        ip="192.168.10.5",
    )
    stmt = apply_filters(select(Event), filters)
    compiled = str(stmt.compile(dialect=postgresql.dialect()))
    assert compiled.count("<<=") == 2
    assert "events.src_ip" in compiled and "events.dst_ip" in compiled


# ---------------------------------------------------------------------------
# Saved-search ownership enforcement
# ---------------------------------------------------------------------------


class _FakeDB:
    def __init__(self, obj):
        self._obj = obj

    async def get(self, model, id_):
        if self._obj is not None and self._obj.id == id_:
            return self._obj
        return None


def _user(role=UserRole.ANALYST) -> User:
    u = User(username="analyst-1", password_hash="x", role=role, is_active=True)
    u.id = uuid.uuid4()
    return u


def _saved_search(owner_id: uuid.UUID) -> SavedSearch:
    s = SavedSearch(user_id=owner_id, name="my search", filters={}, is_shared=False)
    s.id = uuid.uuid4()
    return s


@pytest.mark.asyncio
async def test_owner_can_access_own_saved_search():
    owner = _user()
    saved = _saved_search(owner.id)
    db = _FakeDB(saved)
    result = await _get_owned_saved_search(db, saved.id, owner)
    assert result is saved


@pytest.mark.asyncio
async def test_non_owner_gets_403():
    owner = _user()
    other = _user()
    saved = _saved_search(owner.id)
    db = _FakeDB(saved)
    with pytest.raises(HTTPException) as exc:
        await _get_owned_saved_search(db, saved.id, other)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_missing_saved_search_is_404():
    user = _user()
    db = _FakeDB(None)
    with pytest.raises(HTTPException) as exc:
        await _get_owned_saved_search(db, uuid.uuid4(), user)
    assert exc.value.status_code == 404
