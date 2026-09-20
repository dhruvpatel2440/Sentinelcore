"""M4: rule_sources, rule_overrides, sensor_events

All three are additions to the canonical table list in CLAUDE.md, introduced by
M4 for Suricata sensor and ruleset management.

Revision ID: 0003_m4_sensor
Revises: 0002_m3_assets
Create Date: 2026-09-14
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_m4_sensor"
down_revision: Union[str, None] = "0002_m3_assets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    override_action = postgresql.ENUM(
        "disabled", "enabled", "threshold", name="override_action", create_type=False
    )
    sensor_action = postgresql.ENUM(
        "start", "stop", "reload", "rules_update", "config_test",
        name="sensor_action", create_type=False,
    )
    for enum_type in (override_action, sensor_action):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "rule_sources",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"), nullable=False,
        ),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("url", sa.String(length=1024), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=32), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("rule_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "rule_overrides",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"), nullable=False,
        ),
        sa.Column("sid", sa.BigInteger(), nullable=False),
        sa.Column("action", override_action, nullable=False),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        # NOT NULL: an unexplained silenced signature is a blind spot.
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sid"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.CheckConstraint("sid > 0", name="ck_rule_overrides_sid_positive"),
    )
    op.create_index("ix_rule_overrides_sid", "rule_overrides", ["sid"])

    op.create_table(
        "sensor_events",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"), nullable=False,
        ),
        sa.Column("action", sensor_action, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_sensor_events_action", "sensor_events", ["action"])
    op.create_index("ix_sensor_events_created_at", "sensor_events", ["created_at"])

    # Emerging Threats Open is the sensible default feed.
    op.execute(
        """
        INSERT INTO rule_sources (name, url, enabled)
        VALUES (
            'Emerging Threats Open',
            'https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz',
            true
        )
        ON CONFLICT (name) DO NOTHING
        """
    )


def downgrade() -> None:
    op.drop_index("ix_sensor_events_created_at", table_name="sensor_events")
    op.drop_index("ix_sensor_events_action", table_name="sensor_events")
    op.drop_table("sensor_events")

    op.drop_index("ix_rule_overrides_sid", table_name="rule_overrides")
    op.drop_table("rule_overrides")
    op.drop_table("rule_sources")

    bind = op.get_bind()
    for enum_name in ("sensor_action", "override_action"):
        postgresql.ENUM(name=enum_name).drop(bind, checkfirst=True)
