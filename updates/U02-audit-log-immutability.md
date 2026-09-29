# U02 — Make the audit log genuinely append-only — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore — FastAPI (async) + SQLAlchemy 2.0/asyncpg + Alembic + PostgreSQL. Read `CLAUDE.md` first. The latest migration is `0011_m12_intel.py`; this becomes `0012`.

## Problem

The proposal promises an **immutable, append-only audit trail**. Today `audit_log` (model: `backend/app/models/audit_log.py`, created in `0001_m1_users_and_audit_log.py`) is an ordinary table: anyone with DB credentials, or a bug in the app, can `UPDATE` or `DELETE` rows. A log that can be rewritten is not evidence.

## Goal

The database itself must refuse `UPDATE`, `DELETE` and `TRUNCATE` on `audit_log`, for the application role and for accident-prone humans, while inserts keep working.

## Tasks

### 1. Audit first — do not skip

- `grep -rn "audit_log\|AuditLog" backend/` and list every place that reads or writes it.
- Confirm **nothing** deletes or updates audit rows (retention jobs in `backend/app/pipeline/retention.py`, report cleanup, user deletion cascades, tests/fixtures).
- If a foreign key from `audit_log.user_id` to `users` uses `ON DELETE SET NULL` / `CASCADE`, that is an implicit UPDATE/DELETE and will collide with the trigger. Resolve it by storing `username` (denormalised) in the audit row and dropping the cascading FK, or by making the FK `ON DELETE NO ACTION` and soft-deleting users. Report which you chose and why.

### 2. Migration `0012_audit_immutable.py`

- Create a trigger function `audit_log_block_mutation()` that `RAISE EXCEPTION 'audit_log is append-only'` (use a specific `ERRCODE`).
- `BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW` trigger, plus `BEFORE TRUNCATE ON audit_log FOR EACH STATEMENT` trigger.
- `REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC;` and from the app role. Grant only `INSERT, SELECT` to the app role.
- Downgrade drops the triggers and function (downgrade must work, tests use it).
- Partitioned tables: if `audit_log` is partitioned, attach the triggers correctly (check PG version behaviour) — it currently is not, so just verify.

### 3. Tamper evidence (hash chain)

Add two columns via the same migration: `prev_hash` and `row_hash` (both `CHAR(64)`, nullable for existing rows).

- `row_hash = sha256(prev_hash || id || created_at || user_id || action || target || details_json)`.
- Compute in `services/audit.py::record()` inside the same transaction, using `SELECT ... ORDER BY created_at DESC, id DESC LIMIT 1 FOR UPDATE` on the last row (or a single-row `audit_chain_head` table) so concurrent writers serialise.
- Add `GET /api/audit/verify` (admin only): walks the chain, returns `{ok, checked, first_break_id|null}`. Stream in batches; never load the whole table.

### 4. Tests (`backend/tests/test_audit_immutable.py`)

- `UPDATE`, `DELETE`, `TRUNCATE` via a raw connection all raise.
- `INSERT` still works and `record()` links `prev_hash` correctly.
- Tampering with a row as the DB owner (temporarily disable trigger in test) makes `/audit/verify` report the first broken id.
- 20 concurrent `record()` calls produce a valid chain.
- RBAC: verify endpoint is admin-only.

### 5. Extend `scripts/e2e_test.py`

Add an "Invariant" check that connects with the app credentials and confirms `DELETE FROM audit_log` fails.

## Constraints

- No `shell=True`, no string-built SQL — use bound parameters / SQLAlchemy Core.
- Do not edit or delete existing migrations 0001–0011.
- Existing rows keep `NULL` hashes; the verifier starts the chain at the first non-null row and says so.

## Done when

- `alembic upgrade head` and `alembic downgrade -1` both work on a clean DB.
- New tests pass, old tests still pass.
- Manually running `DELETE FROM audit_log;` as the app role fails.
- A short note is added to `docs/threat-model.md` (or the U07 draft) under "Repudiation".
