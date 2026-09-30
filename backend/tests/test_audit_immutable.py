"""U02: append-only enforcement + hash-chain tests for audit_log.

Runs against the real Postgres (migration 0012_audit_immutable already
applied), same pattern as test_firewall.py — a control that only a mock can
bypass is not a control.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.api.deps import require_role
from app.db.session import SessionLocal
from app.models.user import User, UserRole
from app.services import audit


async def _admin_user(db) -> User:
    user = (await db.execute(select(User).where(User.role == UserRole.ADMIN))).scalars().first()
    assert user is not None, "expected a seeded admin user"
    return user


# ---------------------------------------------------------------------------
# The trigger blocks UPDATE / DELETE / TRUNCATE, even for the table owner
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_raw_update_rejected():
    async with SessionLocal() as db:
        with pytest.raises(DBAPIError, match="append-only"):
            await db.execute(text("UPDATE audit_log SET action = 'x' WHERE id = (SELECT id FROM audit_log LIMIT 1)"))
        await db.rollback()


@pytest.mark.asyncio
async def test_raw_delete_rejected():
    async with SessionLocal() as db:
        with pytest.raises(DBAPIError, match="append-only"):
            await db.execute(text("DELETE FROM audit_log WHERE id = (SELECT id FROM audit_log LIMIT 1)"))
        await db.rollback()


@pytest.mark.asyncio
async def test_raw_truncate_rejected():
    async with SessionLocal() as db:
        with pytest.raises(DBAPIError, match="append-only"):
            await db.execute(text("TRUNCATE audit_log"))
        await db.rollback()


# ---------------------------------------------------------------------------
# record() still inserts and links the hash chain correctly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_inserts_and_links_chain():
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        head_before = (
            await db.execute(text("SELECT last_hash FROM audit_chain_head WHERE id = 1"))
        ).one()

        entry1 = await audit.record(db, action="test.chain.1", user=admin)
        await db.flush()
        assert entry1.prev_hash == head_before.last_hash
        assert entry1.row_hash is not None

        entry2 = await audit.record(db, action="test.chain.2", user=admin)
        await db.commit()

        assert entry2.prev_hash == entry1.row_hash
        assert entry2.row_hash != entry1.row_hash

    async with SessionLocal() as db:
        result = await audit.verify_chain(db)
        assert result["ok"] is True
        assert result["first_break_id"] is None


# ---------------------------------------------------------------------------
# Tamper evidence: a DB-owner-level edit that bypasses the trigger is still
# caught by the hash chain.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tampering_as_db_owner_is_detected_by_verify_chain():
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        head_before = (
            await db.execute(text("SELECT last_id, last_hash FROM audit_chain_head WHERE id = 1"))
        ).one()

        entry1 = await audit.record(db, action="test.tamper.1", user=admin)
        entry2 = await audit.record(db, action="test.tamper.2", user=admin)
        await db.commit()
        tampered_id, trailing_id = entry1.id, entry2.id

    async with SessionLocal() as db:
        assert (await audit.verify_chain(db))["ok"] is True

    try:
        async with SessionLocal() as db:
            # Only a DB owner/superuser can do this — it is the scenario the
            # hash chain exists for, distinct from the app-level trigger.
            await db.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete"))
            await db.execute(
                text("UPDATE audit_log SET action = 'tampered' WHERE id = :id"), {"id": tampered_id}
            )
            await db.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete"))
            await db.commit()

        async with SessionLocal() as db:
            result = await audit.verify_chain(db)
        assert result["ok"] is False
        assert result["first_break_id"] == tampered_id
    finally:
        # Restore exact prior state so later tests (and later verify calls)
        # see a clean chain again.
        async with SessionLocal() as db:
            await db.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete"))
            await db.execute(
                text("DELETE FROM audit_log WHERE id = ANY(:ids)"), {"ids": [tampered_id, trailing_id]}
            )
            await db.execute(
                text("UPDATE audit_chain_head SET last_id = :lid, last_hash = :lhash WHERE id = 1"),
                {"lid": head_before.last_id, "lhash": head_before.last_hash},
            )
            await db.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete"))
            await db.commit()

    async with SessionLocal() as db:
        assert (await audit.verify_chain(db))["ok"] is True


# ---------------------------------------------------------------------------
# Concurrency: 20 concurrent record() calls still produce a valid chain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_record_calls_produce_valid_chain():
    async def _one(i: int) -> None:
        async with SessionLocal() as db:
            admin = await _admin_user(db)
            await audit.record(db, action=f"test.concurrent.{i}", user=admin)
            await db.commit()

    await asyncio.gather(*(_one(i) for i in range(20)))

    async with SessionLocal() as db:
        result = await audit.verify_chain(db)
        assert result["ok"] is True
        assert result["first_break_id"] is None


# ---------------------------------------------------------------------------
# RBAC: /audit/verify is admin-only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [UserRole.VIEWER, UserRole.ANALYST])
async def test_verify_endpoint_denied_for_non_admin(role):
    dep = require_role("admin")
    with pytest.raises(HTTPException) as exc:
        await dep(user=User(username=f"{role.value}-user", password_hash="x", role=role, is_active=True))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_verify_endpoint_allowed_for_admin():
    dep = require_role("admin")
    admin_user = User(username="admin-user", password_hash="x", role=UserRole.ADMIN, is_active=True)
    assert await dep(user=admin_user) is admin_user
