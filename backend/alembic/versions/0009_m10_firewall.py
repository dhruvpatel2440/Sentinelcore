"""M10: firewall_actions

Canonical addition from M10.

Revision ID: 0009_m10_firewall
Revises: 0008_m9_reports
Create Date: 2026-09-22
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_m10_firewall"
down_revision: Union[str, None] = "0008_m9_reports"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    direction = postgresql.ENUM("inbound", "outbound", "both", name="firewall_direction", create_type=False)
    action_status = postgresql.ENUM(
        "pending", "active", "expired", "revoked", "failed", name="firewall_action_status", create_type=False
    )
    for enum_type in (direction, action_status):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "firewall_actions",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column("target", postgresql.CIDR, nullable=False),
        sa.Column("direction", direction, nullable=False),
        sa.Column("protocol", sa.String(4), nullable=True),
        sa.Column("port", sa.Integer, nullable=True),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column(
            "incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("ttl_seconds", sa.Integer, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", action_status, nullable=False, server_default="pending"),
        sa.Column(
            "created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "revoked_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("error", sa.Text, nullable=True),
        sa.CheckConstraint("ttl_seconds BETWEEN 60 AND 86400", name="ck_firewall_actions_ttl_bounds"),
        sa.CheckConstraint("ttl_seconds > 0", name="ck_firewall_actions_ttl_positive"),
    )
    op.create_index("ix_firewall_actions_expires_at", "firewall_actions", ["expires_at"])
    op.create_index("ix_firewall_actions_status", "firewall_actions", ["status"])
    op.create_index("ix_firewall_actions_incident_id", "firewall_actions", ["incident_id"])
    op.create_index("ix_firewall_actions_target", "firewall_actions", ["target"])


def downgrade() -> None:
    op.drop_table("firewall_actions")

    bind = op.get_bind()
    for enum_name in ("firewall_action_status", "firewall_direction"):
        postgresql.ENUM(name=enum_name).drop(bind, checkfirst=True)
