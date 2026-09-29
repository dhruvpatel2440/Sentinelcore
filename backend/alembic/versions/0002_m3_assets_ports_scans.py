"""M3: assets, asset_ports, scans

`assets` and `asset_ports` are canonical tables from CLAUDE.md. `scans` is an
addition introduced by M3 to track discovery-run history and status.

Revision ID: 0002_m3_assets
Revises: 0001_m1_auth
Create Date: 2026-09-14
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_m3_assets"
down_revision: Union[str, None] = "0001_m1_auth"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    protocol = postgresql.ENUM("tcp", "udp", name="port_protocol", create_type=False)
    port_state = postgresql.ENUM("open", "filtered", "closed", name="port_state", create_type=False)
    scan_status = postgresql.ENUM(
        "queued", "running", "completed", "failed", name="scan_status", create_type=False
    )
    scan_type = postgresql.ENUM("nmap", "arp", "combined", name="scan_type", create_type=False)

    for enum_type in (protocol, port_state, scan_status, scan_type):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "assets",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("ip_address", postgresql.INET(), nullable=False),
        sa.Column("mac_address", postgresql.MACADDR(), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("hostname_override", sa.String(length=255), nullable=True),
        sa.Column("vendor", sa.String(length=128), nullable=True),
        sa.Column("os_guess", sa.String(length=128), nullable=True),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("missed_scans", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ip_address"),
    )
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"])
    op.create_index("ix_assets_last_seen", "assets", ["last_seen"])
    op.create_index("ix_assets_first_seen", "assets", ["first_seen"])
    op.create_index("ix_assets_is_active", "assets", ["is_active"])

    op.create_table(
        "asset_ports",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", protocol, nullable=False),
        sa.Column("state", port_state, nullable=False),
        sa.Column("service", sa.String(length=64), nullable=True),
        sa.Column("product", sa.String(length=128), nullable=True),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
        # CASCADE here is correct: a port row is meaningless without its asset.
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_port_proto"),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_asset_ports_range"),
    )
    op.create_index("ix_asset_ports_asset_id", "asset_ports", ["asset_id"])

    op.create_table(
        "scans",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("scan_type", scan_type, nullable=False, server_default="combined"),
        sa.Column("status", scan_status, nullable=False, server_default="queued"),
        sa.Column("targets", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("ports", sa.String(length=512), nullable=True),
        sa.Column("mode", sa.String(length=32), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hosts_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("ports_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_scans_created_at", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_table("scans")

    op.drop_index("ix_asset_ports_asset_id", table_name="asset_ports")
    op.drop_table("asset_ports")

    for name in ("ix_assets_is_active", "ix_assets_first_seen", "ix_assets_last_seen", "ix_assets_ip_address"):
        op.drop_index(name, table_name="assets")
    op.drop_table("assets")

    bind = op.get_bind()
    for enum_name in ("scan_type", "scan_status", "port_state", "port_protocol"):
        postgresql.ENUM(name=enum_name).drop(bind, checkfirst=True)
