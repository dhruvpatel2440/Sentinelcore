"""M10 firewall tests: TTL bounds at both layers, idempotent apply/revoke
against the real privileged helper, the expiry worker, and reconciliation in
both drift directions. The protection guard itself is unit-tested exhaustively
in helper/tests/test_guards.py — these tests exercise the layer above it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.firewall_action import FirewallAction, FirewallActionStatus
from app.models.user import User, UserRole
from app.schemas.firewall import FirewallActionCreate
from app.services import firewall
from app.services.firewall import FirewallGuardRejected, MaxActiveBlocksReached

UTC = timezone.utc


async def _admin_user(db) -> User:
    user = (await db.execute(select(User).where(User.role == UserRole.ADMIN))).scalars().first()
    assert user is not None, "expected a seeded admin user"
    return user


async def _cleanup(db, action_ids: list[uuid.UUID]) -> None:
    if not action_ids:
        return
    await db.execute(text("DELETE FROM firewall_actions WHERE id = ANY(:ids)"), {"ids": action_ids})
    await db.commit()


# ---------------------------------------------------------------------------
# TTL bounds — pydantic layer
# ---------------------------------------------------------------------------


def test_ttl_below_minimum_rejected_by_schema():
    with pytest.raises(ValidationError):
        FirewallActionCreate(target="10.0.0.1/32", direction="inbound", ttl_seconds=10, reason="x")


def test_ttl_above_maximum_rejected_by_schema():
    with pytest.raises(ValidationError):
        FirewallActionCreate(target="10.0.0.1/32", direction="inbound", ttl_seconds=999_999, reason="x")


def test_ttl_negative_rejected_by_schema():
    with pytest.raises(ValidationError):
        FirewallActionCreate(target="10.0.0.1/32", direction="inbound", ttl_seconds=-5, reason="x")


def test_missing_reason_rejected_by_schema():
    with pytest.raises(ValidationError):
        FirewallActionCreate(target="10.0.0.1/32", direction="inbound", ttl_seconds=300, reason="")


def test_bad_protocol_rejected_by_schema():
    with pytest.raises(ValidationError):
        FirewallActionCreate(target="10.0.0.1/32", direction="inbound", ttl_seconds=300, reason="x", protocol="icmp")


def test_garbage_target_rejected_by_schema():
    with pytest.raises(ValidationError):
        FirewallActionCreate(target="not-an-ip", direction="inbound", ttl_seconds=300, reason="x")


# ---------------------------------------------------------------------------
# TTL bounds — database CHECK constraint (bypassing pydantic entirely)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ttl_bounds_enforced_by_db_check_constraint_directly():
    """A control that can be bypassed by a direct insert is not a control —
    this inserts straight past pydantic to prove the DB itself refuses it."""
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        now = datetime.now(UTC)
        bad = FirewallAction(
            target="10.0.0.1/32", direction="inbound", reason="direct insert bypassing pydantic",
            ttl_seconds=10, expires_at=now + timedelta(seconds=10),
            status=FirewallActionStatus.PENDING, created_by=admin.id,
        )
        db.add(bad)
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


@pytest.mark.asyncio
async def test_ttl_above_max_rejected_by_db_check_constraint_directly():
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        now = datetime.now(UTC)
        bad = FirewallAction(
            target="10.0.0.1/32", direction="inbound", reason="direct insert",
            ttl_seconds=999_999, expires_at=now + timedelta(seconds=999_999),
            status=FirewallActionStatus.PENDING, created_by=admin.id,
        )
        db.add(bad)
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


# ---------------------------------------------------------------------------
# apply()/revoke() against the real helper — guard rejection, idempotency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_is_refused_for_a_protected_ip_and_marks_failed():
    protected_ips = settings.protected_ips_parsed
    if not protected_ips:
        pytest.skip("PROTECTED_IPS is not configured in this environment")
    target_ip = str(sorted(protected_ips)[0])

    async with SessionLocal() as db:
        admin = await _admin_user(db)
        payload = FirewallActionCreate(
            target=f"{target_ip}/32", direction="inbound", ttl_seconds=300, reason="test: protected ip"
        )
        created_ids: list[uuid.UUID] = []
        try:
            with pytest.raises(FirewallGuardRejected):
                await firewall.apply(db, payload=payload, user=admin)

            row = (
                await db.execute(
                    select(FirewallAction).where(FirewallAction.reason == "test: protected ip").order_by(FirewallAction.created_at.desc())
                )
            ).scalars().first()
            assert row is not None
            created_ids.append(row.id)
            assert row.status == FirewallActionStatus.FAILED
            assert row.error is not None
        finally:
            await _cleanup(db, created_ids)


@pytest.mark.asyncio
async def test_apply_then_revoke_lifecycle_against_real_helper():
    """Applies a real DROP rule via the helper, confirms it is idempotent,
    then revokes it — end to end against the live SENTINELCORE chain."""
    from app.services import helper_client

    net = settings.monitored_network
    # Deliberately not a protected IP: pick a high host address in the real
    # (unpinned — this test intentionally uses the real env, not the pinned
    # 192.168.10.0/24 test network, since the helper enforces its own scope).
    import ipaddress

    real_net = ipaddress.ip_network(net, strict=False)
    target = f"{real_net.network_address + 220}/32"
    if ipaddress.ip_address(str(real_net.network_address + 220)) in settings.protected_ips_parsed:
        pytest.skip("chosen test target collides with a configured protected IP")

    async with SessionLocal() as db:
        admin = await _admin_user(db)
        payload = FirewallActionCreate(target=target, direction="inbound", ttl_seconds=300, reason="test: lifecycle")
        try:
            action = await firewall.apply(db, payload=payload, user=admin)
        except helper_client.HelperUnavailable:
            pytest.skip("privileged helper is not reachable in this environment")

        try:
            assert action.status == FirewallActionStatus.ACTIVE
            assert action.applied_at is not None

            # Idempotent: re-running fw_apply for the same action_id must not
            # duplicate the kernel rule or raise.
            result = await helper_client.call(
                "fw_apply",
                {"action_id": str(action.id), "target": target, "direction": "inbound", "protocol": None, "port": None},
            )
            assert result["applied"] is True

            listed = await helper_client.call("fw_list", {})
            matches = [r for r in listed["rules"] if r["action_id"] == str(action.id)]
            assert len(matches) == 1

            revoked = await firewall.revoke(db, action, user=admin, reason="test cleanup")
            assert revoked.status == FirewallActionStatus.REVOKED
            assert revoked.revoked_by == admin.id

            listed_after = await helper_client.call("fw_list", {})
            assert not any(r["action_id"] == str(action.id) for r in listed_after["rules"])
        finally:
            await _cleanup(db, [action.id])


@pytest.mark.asyncio
async def test_max_active_blocks_enforced(monkeypatch):
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        current = await firewall._active_count(db)
        monkeypatch.setattr(settings, "max_active_blocks", current)  # already "at" the limit

        payload = FirewallActionCreate(target="10.0.0.1/32", direction="inbound", ttl_seconds=300, reason="test: over limit")
        with pytest.raises(MaxActiveBlocksReached):
            await firewall.apply(db, payload=payload, user=admin)


@pytest.mark.asyncio
async def test_extend_caps_at_ttl_maximum():
    from app.models.firewall_action import TTL_MAX_SECONDS

    async with SessionLocal() as db:
        admin = await _admin_user(db)
        now = datetime.now(UTC)
        action = FirewallAction(
            target="10.0.0.5/32", direction="inbound", reason="test: extend cap",
            ttl_seconds=TTL_MAX_SECONDS - 100, expires_at=now + timedelta(seconds=TTL_MAX_SECONDS - 100),
            status=FirewallActionStatus.ACTIVE, created_by=admin.id, created_at=now, applied_at=now,
        )
        db.add(action)
        await db.commit()
        await db.refresh(action)

        try:
            extended = await firewall.extend(db, action, additional_seconds=10_000, user=admin)
            assert extended.ttl_seconds == TTL_MAX_SECONDS
            assert extended.expires_at == action.created_at + timedelta(seconds=TTL_MAX_SECONDS)
        finally:
            await _cleanup(db, [action.id])


@pytest.mark.asyncio
async def test_extend_refuses_non_active_action():
    async with SessionLocal() as db:
        admin = await _admin_user(db)
        now = datetime.now(UTC)
        action = FirewallAction(
            target="10.0.0.6/32", direction="inbound", reason="test: extend refused",
            ttl_seconds=300, expires_at=now, status=FirewallActionStatus.REVOKED,
            created_by=admin.id, created_at=now,
        )
        db.add(action)
        await db.commit()
        await db.refresh(action)
        try:
            with pytest.raises(ValueError):
                await firewall.extend(db, action, additional_seconds=60, user=admin)
        finally:
            await _cleanup(db, [action.id])


# ---------------------------------------------------------------------------
# Expiry worker
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expiry_pass_expires_a_due_action_and_removes_the_kernel_rule():
    import ipaddress

    from app.services import helper_client

    real_net = ipaddress.ip_network(settings.monitored_network, strict=False)
    target_ip = real_net.network_address + 221
    if target_ip in settings.protected_ips_parsed:
        pytest.skip("chosen test target collides with a configured protected IP")
    target = f"{target_ip}/32"

    async with SessionLocal() as db:
        admin = await _admin_user(db)
        payload = FirewallActionCreate(target=target, direction="inbound", ttl_seconds=60, reason="test: expiry")
        try:
            action = await firewall.apply(db, payload=payload, user=admin)
        except helper_client.HelperUnavailable:
            pytest.skip("privileged helper is not reachable in this environment")

        try:
            # Force it due without waiting out a real TTL.
            action.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            await db.commit()

            expired_count = await firewall.run_expiry_pass(db)
            assert expired_count >= 1

            await db.refresh(action)
            assert action.status == FirewallActionStatus.EXPIRED

            listed = await helper_client.call("fw_list", {})
            assert not any(r["action_id"] == str(action.id) for r in listed["rules"])
        finally:
            await _cleanup(db, [action.id])


# ---------------------------------------------------------------------------
# Reconciliation — both drift directions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reconcile_removes_kernel_orphan_with_no_db_row():
    import ipaddress

    from app.services import helper_client

    real_net = ipaddress.ip_network(settings.monitored_network, strict=False)
    target_ip = real_net.network_address + 222
    if target_ip in settings.protected_ips_parsed:
        pytest.skip("chosen test target collides with a configured protected IP")

    orphan_action_id = str(uuid.uuid4())
    try:
        await helper_client.call(
            "fw_apply",
            {"action_id": orphan_action_id, "target": f"{target_ip}/32", "direction": "inbound", "protocol": None, "port": None},
        )
    except helper_client.HelperUnavailable:
        pytest.skip("privileged helper is not reachable in this environment")

    async with SessionLocal() as db:
        result = await firewall.reconcile(db)
        assert orphan_action_id in result.get("orphans_removed", [])

    listed = await helper_client.call("fw_list", {})
    assert not any(r["action_id"] == orphan_action_id for r in listed["rules"])


@pytest.mark.asyncio
async def test_reconcile_reapplies_a_db_row_with_no_kernel_rule():
    import ipaddress

    from app.services import helper_client

    real_net = ipaddress.ip_network(settings.monitored_network, strict=False)
    target_ip = real_net.network_address + 223
    if target_ip in settings.protected_ips_parsed:
        pytest.skip("chosen test target collides with a configured protected IP")
    target = f"{target_ip}/32"

    async with SessionLocal() as db:
        admin = await _admin_user(db)
        now = datetime.now(UTC)
        # An "active" row the kernel has never seen — simulates drift after a
        # host reboot wiped the (deliberately non-persistent) iptables rules.
        action = FirewallAction(
            target=target, direction="inbound", reason="test: missing re-apply",
            ttl_seconds=300, expires_at=now + timedelta(seconds=300),
            status=FirewallActionStatus.ACTIVE, created_by=admin.id, created_at=now, applied_at=now,
        )
        db.add(action)
        await db.commit()
        await db.refresh(action)

        try:
            try:
                result = await firewall.reconcile(db)
            except helper_client.HelperUnavailable:
                pytest.skip("privileged helper is not reachable in this environment")

            assert str(action.id) in result.get("reapplied", [])

            listed = await helper_client.call("fw_list", {})
            assert any(r["action_id"] == str(action.id) for r in listed["rules"])

            await helper_client.call("fw_revoke", {"action_id": str(action.id)})
        finally:
            await _cleanup(db, [action.id])
