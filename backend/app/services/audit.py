"""Audit trail writer and hash-chain verifier.

`CLAUDE.md`: every write action is logged to `audit_log`. Call `record()` from
inside the same transaction as the action it describes, so a rolled-back action
does not leave a phantom audit entry.

`audit_log` is append-only at the database level (migration
`0012_audit_immutable`: a trigger rejects UPDATE/DELETE/TRUNCATE). On top of
that, every row carries a SHA-256 hash chain (`prev_hash`/`row_hash`) so that
tampering which bypasses the trigger — a superuser dropping it, or restoring
from an edited backup — is still detectable by walking the chain
(`verify_chain`, exposed as `GET /api/audit/verify`).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User

_DEFAULT_VERIFY_BATCH = 1000


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    # nginx sets X-Forwarded-For; take the left-most entry (the original client).
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip() or None
    return request.client.host if request.client else None


def _canonical_detail(detail: dict[str, Any] | None) -> str:
    """Deterministic serialisation of `detail` for hashing.

    `sort_keys=True` makes key order irrelevant; `default=str` covers values
    (UUID, datetime) that occasionally end up in `detail` before JSONB
    round-trips them to plain str/int/bool/list/dict on read-back.
    """
    if detail is None:
        return ""
    return json.dumps(detail, sort_keys=True, default=str)


def _compute_row_hash(
    *,
    prev_hash: str | None,
    row_id: int,
    created_at: datetime,
    user_id: uuid.UUID | None,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    detail: dict[str, Any] | None,
) -> str:
    payload = "|".join(
        [
            prev_hash or "",
            str(row_id),
            created_at.isoformat(),
            str(user_id) if user_id else "",
            action,
            resource_type or "",
            resource_id or "",
            _canonical_detail(detail),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def record(
    db: AsyncSession,
    *,
    action: str,
    user: User | None = None,
    username: str | None = None,
    resource_type: str | None = None,
    resource_id: str | uuid.UUID | None = None,
    outcome: str = "success",
    detail: dict[str, Any] | None = None,
    error: str | None = None,
    request: Request | None = None,
) -> AuditLog:
    """Add an audit row to `db`, linked into the hash chain. The caller owns the commit.

    Locks the single `audit_chain_head` row for the duration of the
    surrounding transaction so concurrent `record()` calls serialise instead
    of racing to read the same "last hash".
    """
    head = (
        await db.execute(text("SELECT last_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE"))
    ).one()
    prev_hash: str | None = head.last_hash

    new_id = (await db.execute(text("SELECT nextval('audit_log_id_seq')"))).scalar_one()
    created_at = datetime.now(timezone.utc)
    resource_id_str = str(resource_id) if resource_id is not None else None

    row_hash = _compute_row_hash(
        prev_hash=prev_hash,
        row_id=new_id,
        created_at=created_at,
        user_id=user.id if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id_str,
        detail=detail,
    )

    entry = AuditLog(
        id=new_id,
        user_id=user.id if user else None,
        username=username or (user.username if user else None),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id_str,
        outcome=outcome,
        detail=detail,
        error=error,
        ip_address=_client_ip(request),
        user_agent=(request.headers.get("user-agent") if request else None),
        created_at=created_at,
        prev_hash=prev_hash,
        row_hash=row_hash,
    )
    db.add(entry)

    await db.execute(
        text("UPDATE audit_chain_head SET last_id = :id, last_hash = :hash WHERE id = 1"),
        {"id": new_id, "hash": row_hash},
    )
    return entry


async def verify_chain(db: AsyncSession, *, batch_size: int = _DEFAULT_VERIFY_BATCH) -> dict[str, Any]:
    """Walk `audit_log` in id order and recompute every `row_hash`.

    Rows written before migration `0012_audit_immutable` have `row_hash IS
    NULL` and are skipped; the chain is defined to start at the first
    non-null row. Streams in batches of `batch_size` — never loads the whole
    table into memory.
    """
    checked = 0
    prev_hash: str | None = None
    chain_started = False
    last_seen_id = 0

    while True:
        result = await db.execute(
            select(
                AuditLog.id,
                AuditLog.user_id,
                AuditLog.action,
                AuditLog.resource_type,
                AuditLog.resource_id,
                AuditLog.detail,
                AuditLog.created_at,
                AuditLog.prev_hash,
                AuditLog.row_hash,
            )
            .where(AuditLog.id > last_seen_id)
            .order_by(AuditLog.id)
            .limit(batch_size)
        )
        rows = result.all()
        if not rows:
            break

        for row in rows:
            last_seen_id = row.id

            if row.row_hash is None:
                # Pre-0012 row: no hash was ever computed for it. The chain
                # has not started yet.
                continue

            if not chain_started:
                chain_started = True
                # Trust this row's own prev_hash as the chain's starting
                # point — it was computed against whatever (possibly NULL)
                # head existed when the trigger/chain went live.
                prev_hash = row.prev_hash

            expected = _compute_row_hash(
                prev_hash=prev_hash,
                row_id=row.id,
                created_at=row.created_at,
                user_id=row.user_id,
                action=row.action,
                resource_type=row.resource_type,
                resource_id=row.resource_id,
                detail=row.detail,
            )
            checked += 1
            if expected != row.row_hash:
                return {"ok": False, "checked": checked, "first_break_id": row.id}
            prev_hash = row.row_hash

    return {"ok": True, "checked": checked, "first_break_id": None}
