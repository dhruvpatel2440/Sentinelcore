"""M7: correlation_rules, incident_candidates, rule_runs

Canonical additions from M7. `incident_candidates.incident_id` has no FK yet
— the `incidents` table does not exist until M8, which adds the constraint
once it does.

Revision ID: 0006_m7_correlation
Revises: 0005_m6_search
Create Date: 2026-09-21
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_m7_correlation"
down_revision: Union[str, None] = "0005_m6_search"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    rule_type = postgresql.ENUM(
        "threshold", "sequence", "rare", "beacon", name="correlation_rule_type", create_type=False
    )
    candidate_status = postgresql.ENUM(
        "new", "promoted", "suppressed", name="candidate_status", create_type=False
    )
    event_severity = postgresql.ENUM(
        "critical", "high", "medium", "low", "info", name="event_severity", create_type=False
    )

    for enum_type in (rule_type, candidate_status):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "correlation_rules",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("rule_type", rule_type, nullable=False),
        sa.Column("match", postgresql.JSONB, nullable=False),
        sa.Column("group_by", postgresql.JSONB, nullable=False),
        sa.Column("window_seconds", sa.Integer, nullable=False),
        sa.Column("threshold", sa.Integer, nullable=False, server_default="1"),
        sa.Column("severity", event_severity, nullable=False),
        sa.Column("dedup_window_seconds", sa.Integer, nullable=False, server_default="3600"),
        sa.Column("params", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )

    op.create_table(
        "incident_candidates",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column(
            "rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("correlation_rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("group_key", sa.String(512), nullable=False),
        sa.Column("first_event_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer, nullable=False),
        sa.Column("severity", event_severity, nullable=False),
        sa.Column("score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("evidence", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("status", candidate_status, nullable=False, server_default="new"),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=True, unique=True),
        sa.Column("suppressed_reason", sa.Text, nullable=True),
        sa.Column(
            "suppressed_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("rule_id", "group_key", "first_event_ts", name="uq_candidate_rule_group_first"),
    )
    op.create_index("ix_incident_candidates_group_key", "incident_candidates", ["group_key"])
    op.create_index("ix_incident_candidates_created_at", "incident_candidates", ["created_at"])

    op.create_table(
        "rule_runs",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column(
            "rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("correlation_rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("events_scanned", sa.Integer, nullable=False, server_default="0"),
        sa.Column("candidates_created", sa.Integer, nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_rule_runs_rule_id", "rule_runs", ["rule_id"])
    op.create_index("ix_rule_runs_created_at", "rule_runs", ["created_at"])


def downgrade() -> None:
    op.drop_table("rule_runs")
    op.drop_table("incident_candidates")
    op.drop_table("correlation_rules")

    bind = op.get_bind()
    for enum_name in ("candidate_status", "correlation_rule_type"):
        postgresql.ENUM(name=enum_name).drop(bind, checkfirst=True)
