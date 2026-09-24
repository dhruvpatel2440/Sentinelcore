"""M12: ioc, ioc_sources, ioc_matches; ioc_match/ioc_severity on events

Canonical addition from M12. `events` is range-partitioned by `ts`; adding
columns to the parent propagates to every existing and future partition.

Revision ID: 0011_m12_intel
Revises: 0010_m11_pcap
Create Date: 2026-09-22
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_m12_intel"
down_revision: Union[str, None] = "0010_m11_pcap"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    # CIDR has no default GiST operator class in core Postgres; btree_gist
    # supplies one so containment lookups on `cidr_shadow` can use GiST.
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gist")

    ioc_type = postgresql.ENUM(
        "ip", "cidr", "domain", "url", "md5", "sha1", "sha256", "email",
        name="ioc_type", create_type=False,
    )
    ioc_severity = postgresql.ENUM(
        "critical", "high", "medium", "low", "info", name="ioc_severity", create_type=False,
    )
    source_format = postgresql.ENUM(
        "csv", "json", "txt", "misp", "stix", name="ioc_source_format", create_type=False,
    )
    for enum_type in (ioc_type, ioc_severity, source_format):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "ioc_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("format", source_format, nullable=False),
        sa.Column("parser_config", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("default_confidence", sa.Integer, nullable=False, server_default="50"),
        sa.Column("default_severity", ioc_severity, nullable=False, server_default="medium"),
        sa.Column("refresh_interval_hours", sa.Integer, nullable=False, server_default="24"),
        sa.Column("ttl_days", sa.Integer, nullable=False, server_default="30"),
        sa.Column("last_fetch_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(32), nullable=True),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("indicator_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "ioc",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("indicator", sa.Text, nullable=False),
        sa.Column("ioc_type", ioc_type, nullable=False),
        sa.Column("cidr_shadow", postgresql.CIDR, nullable=True),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ioc_sources.id", ondelete="SET NULL"), nullable=True),
        sa.Column("confidence", sa.Integer, nullable=False, server_default="50"),
        sa.Column("severity", ioc_severity, nullable=False, server_default="medium"),
        sa.Column("threat_type", sa.String(64), nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("tags", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("added_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("indicator", "ioc_type", "source_id", name="uq_ioc_indicator_type_source"),
    )
    op.create_index("ix_ioc_indicator", "ioc", ["indicator"])
    op.create_index("ix_ioc_type_active", "ioc", ["ioc_type", "is_active"])
    op.create_index("ix_ioc_expires_at", "ioc", ["expires_at"])
    op.create_index("ix_ioc_cidr_shadow", "ioc", ["cidr_shadow"], postgresql_using="gist")

    op.create_table(
        "ioc_matches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("ioc_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ioc.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_id", sa.BigInteger, nullable=True),
        sa.Column("pcap_artifact_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("pcap_artifacts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("matched_value", sa.Text, nullable=False),
        sa.Column("matched_field", sa.String(32), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ioc_matches_ioc_ts", "ioc_matches", ["ioc_id", "ts"])
    op.create_index("ix_ioc_matches_event_id", "ioc_matches", ["event_id"])

    # events: partitioned parent — ALTER TABLE here propagates to every
    # partition, existing and future.
    op.add_column("events", sa.Column("ioc_match", sa.Boolean, nullable=False, server_default=sa.false()))
    op.add_column("events", sa.Column("ioc_severity", postgresql.ENUM(name="event_severity", create_type=False), nullable=True))
    op.create_index("ix_events_ioc_match_ts", "events", ["ioc_match", "ts"])


def downgrade() -> None:
    op.drop_index("ix_events_ioc_match_ts", table_name="events")
    op.drop_column("events", "ioc_severity")
    op.drop_column("events", "ioc_match")

    op.drop_table("ioc_matches")
    op.drop_table("ioc")
    op.drop_table("ioc_sources")

    bind = op.get_bind()
    for enum_name in ("ioc_source_format", "ioc_severity", "ioc_type"):
        postgresql.ENUM(name=enum_name).drop(bind, checkfirst=True)
