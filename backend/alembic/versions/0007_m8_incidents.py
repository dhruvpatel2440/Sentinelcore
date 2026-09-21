"""M8: incidents, incident_events, incident_history

Canonical additions from CLAUDE.md's table list. Also adds the deferred FK
from M7's `incident_candidates.incident_id` now that `incidents` exists, and
a trigger making `incident_history` genuinely append-only — in an IR tool the
audit trail *is* the product, so this is enforced by the database, not
convention.

Revision ID: 0007_m8_incidents
Revises: 0006_m7_correlation
Create Date: 2026-09-21
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_m8_incidents"
down_revision: Union[str, None] = "0006_m7_correlation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    incident_status = postgresql.ENUM(
        "new", "triage", "investigating", "contained", "resolved", "false_positive",
        name="incident_status", create_type=False,
    )
    history_action = postgresql.ENUM(
        "created", "status_changed", "assigned", "severity_changed", "commented",
        "events_linked", "events_unlinked", "reopened", "closed",
        name="incident_history_action", create_type=False,
    )
    event_severity = postgresql.ENUM(
        "critical", "high", "medium", "low", "info", name="event_severity", create_type=False
    )
    for enum_type in (incident_status, history_action):
        enum_type.create(bind, checkfirst=True)

    # Human-facing sequential id ("INC-1042") — a UUID is unusable verbally.
    op.execute("CREATE SEQUENCE IF NOT EXISTS incident_number_seq START WITH 1000")

    op.create_table(
        "incidents",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column(
            "number", sa.BigInteger, nullable=False, unique=True,
            server_default=sa.text("nextval('incident_number_seq')"),
        ),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", incident_status, nullable=False, server_default="new"),
        sa.Column("severity", event_severity, nullable=False),
        sa.Column("score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("src_ip", postgresql.INET, nullable=True),
        sa.Column("dst_ip", postgresql.INET, nullable=True),
        sa.Column(
            "asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column(
            "assigned_to", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column(
            "rule_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("correlation_rules.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column(
            "candidate_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incident_candidates.id", ondelete="SET NULL"), nullable=True, unique=True,
        ),
        sa.Column("event_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("first_event_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "closed_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("resolution_note", sa.Text, nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(), onupdate=sa.func.now(),
        ),
    )
    op.create_index("ix_incidents_queue", "incidents", ["status", "severity", "opened_at"])
    op.create_index("ix_incidents_assignee", "incidents", ["assigned_to", "status"])
    op.create_index("ix_incidents_src_ip", "incidents", ["src_ip"])
    op.create_index("ix_incidents_opened_at", "incidents", ["opened_at"])

    op.create_table(
        "incident_events",
        sa.Column(
            "incident_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False,
        ),
        # No FK: events' primary key is (id, ts) because it is partitioned —
        # `id` alone cannot carry a foreign key. The IDENTITY sequence still
        # makes it a valid application-level reference.
        sa.Column("event_id", sa.BigInteger, nullable=False),
        sa.Column(
            "linked_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("incident_id", "event_id", name="pk_incident_events"),
    )

    op.create_table(
        "incident_history",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column(
            "incident_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("action", history_action, nullable=False),
        sa.Column("from_value", sa.Text, nullable=True),
        sa.Column("to_value", sa.Text, nullable=True),
        sa.Column("note", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_incident_history_incident_id", "incident_history", ["incident_id"])
    op.create_index("ix_incident_history_created_at", "incident_history", ["created_at"])

    # Append-only, enforced by the database — not by "we just don't expose
    # an update endpoint".
    op.execute(
        """
        CREATE OR REPLACE FUNCTION reject_incident_history_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'incident_history is append-only: % is not permitted', TG_OP;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_incident_history_immutable
        BEFORE UPDATE OR DELETE ON incident_history
        FOR EACH ROW EXECUTE FUNCTION reject_incident_history_mutation()
        """
    )

    # M7 mistakenly made this column unique — a merge links multiple
    # candidates onto the same incident over time, so it must be a plain
    # many-to-one reference. `incidents.candidate_id` is the correct unique
    # side (an incident traces back to at most one *originating* candidate).
    op.drop_constraint("incident_candidates_incident_id_key", "incident_candidates", type_="unique")

    # The FK M7 deferred: incident_candidates.incident_id now has somewhere
    # to point.
    op.create_foreign_key(
        "fk_incident_candidates_incident",
        "incident_candidates",
        "incidents",
        ["incident_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_incident_candidates_incident", "incident_candidates", type_="foreignkey")
    op.create_unique_constraint("incident_candidates_incident_id_key", "incident_candidates", ["incident_id"])
    op.execute("DROP TRIGGER IF EXISTS trg_incident_history_immutable ON incident_history")
    op.execute("DROP FUNCTION IF EXISTS reject_incident_history_mutation()")
    op.drop_table("incident_history")
    op.drop_table("incident_events")
    op.drop_table("incidents")
    op.execute("DROP SEQUENCE IF EXISTS incident_number_seq")

    bind = op.get_bind()
    for enum_name in ("incident_history_action", "incident_status"):
        postgresql.ENUM(name=enum_name).drop(bind, checkfirst=True)
