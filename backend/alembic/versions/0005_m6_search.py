"""M6: event search support (saved_searches) + keyset pagination indexes

`saved_searches` is an addition to the canonical table list, introduced by M6
to let an analyst persist a filter set.

The composite `(ts DESC, id DESC)` index is what keyset pagination rides on —
without the `id` tie-breaker, rows with an identical `ts` have no stable order
across pages. `ix_events_id` exists solely so `GET /api/events/{id}` does not
have to scan every partition, since a partitioned table's primary key (id, ts)
cannot be used to find a row when only `id` is known.

Revision ID: 0005_m6_search
Revises: 0004_m5_events
Create Date: 2026-09-21
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_m6_search"
down_revision: Union[str, None] = "0004_m5_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Created on the partitioned parent; PostgreSQL propagates both indexes to
    # every existing and future partition automatically.
    op.execute("CREATE INDEX ix_events_ts_id ON events (ts DESC, id DESC)")
    op.execute("CREATE INDEX ix_events_id ON events (id)")

    op.create_table(
        "saved_searches",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("filters", postgresql.JSONB, nullable=False),
        sa.Column("is_shared", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.UniqueConstraint("user_id", "name", name="uq_saved_search_user_name"),
    )
    op.create_index("ix_saved_searches_user_id", "saved_searches", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_saved_searches_user_id", table_name="saved_searches")
    op.drop_table("saved_searches")
    op.execute("DROP INDEX IF EXISTS ix_events_id")
    op.execute("DROP INDEX IF EXISTS ix_events_ts_id")
