"""U02: append-only enforcement + hash chain for audit_log

`audit_log` is meant to be evidence. Today it is an ordinary table: any bug
or anyone with DB credentials can UPDATE/DELETE rows. This migration adds two
independent layers:

1. A BEFORE UPDATE/DELETE/TRUNCATE trigger that raises unconditionally.
   Verified against a live DB (see U02 report): a plain `REVOKE ... FROM
   CURRENT_USER` does **not** stop the table owner (owner privileges bypass
   GRANT/REVOKE) — the trigger is what actually blocks the owner, including
   this application's own DB role, since there is only one configured
   Postgres role in this deployment. The REVOKE statements are kept anyway
   as belt-and-braces for the day a separate least-privilege app role is
   introduced.
2. A SHA-256 hash chain (`prev_hash`, `row_hash`) so that even a superuser
   who disables the trigger (`SESSION_REPLICATION_ROLE=replica`) or drops it
   leaves tamper evidence: `GET /api/audit/verify` will find the break.

`audit_log.user_id` had `ON DELETE SET NULL` to `users.id`. That FK is an
implicit UPDATE on this table triggered by an action on a *different* table
(deleting a user) — it would collide with the new trigger the moment an
admin deletes a user. `username` is already denormalised onto the row
(`app/models/audit_log.py`), so the FK is dropped outright rather than
downgraded to `ON DELETE NO ACTION` (which would just turn "delete a user"
into a 500 the first time that user has any audit history).

Revision ID: 0012_audit_immutable
Revises: 0011_m12_intel
Create Date: 2026-09-29
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012_audit_immutable"
down_revision: Union[str, None] = "0011_m12_intel"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE audit_log DROP CONSTRAINT audit_log_user_id_fkey")

    op.add_column("audit_log", sa.Column("prev_hash", sa.CHAR(64), nullable=True))
    op.add_column("audit_log", sa.Column("row_hash", sa.CHAR(64), nullable=True))

    # Singleton head-of-chain row. A dedicated table (rather than
    # `SELECT ... ORDER BY id DESC LIMIT 1 FOR UPDATE` on audit_log itself)
    # means concurrent writers serialise on one small row instead of a scan,
    # and it works even while audit_log has zero rows.
    op.create_table(
        "audit_chain_head",
        sa.Column("id", sa.SmallInteger(), primary_key=True),
        sa.Column("last_id", sa.BigInteger(), nullable=True),
        sa.Column("last_hash", sa.CHAR(64), nullable=True),
        sa.CheckConstraint("id = 1", name="ck_audit_chain_head_singleton"),
    )
    op.execute("INSERT INTO audit_chain_head (id, last_id, last_hash) VALUES (1, NULL, NULL)")

    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_log_block_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION USING
                MESSAGE = 'audit_log is append-only',
                ERRCODE = 'SC001';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update_delete
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation();
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_truncate
        BEFORE TRUNCATE ON audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION audit_log_block_mutation();
        """
    )

    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM CURRENT_USER")


def downgrade() -> None:
    op.execute("GRANT UPDATE, DELETE, TRUNCATE ON audit_log TO CURRENT_USER")

    op.execute("DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update_delete ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS audit_log_block_mutation()")

    op.drop_table("audit_chain_head")

    op.drop_column("audit_log", "row_hash")
    op.drop_column("audit_log", "prev_hash")

    op.create_foreign_key(
        "audit_log_user_id_fkey",
        "audit_log",
        "users",
        ["user_id"],
        ["id"],
        ondelete="SET NULL",
    )
