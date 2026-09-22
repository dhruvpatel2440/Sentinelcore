"""M11: pcap_files, pcap_flows, pcap_artifacts

Canonical addition from M11.

Revision ID: 0010_m11_pcap
Revises: 0009_m10_firewall
Create Date: 2026-09-22
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_m11_pcap"
down_revision: Union[str, None] = "0009_m10_firewall"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    pcap_status = postgresql.ENUM("uploaded", "parsing", "parsed", "failed", name="pcap_status", create_type=False)
    artifact_type = postgresql.ENUM(
        "dns_query", "http_request", "tls_sni", "credential", "file_transfer", "user_agent",
        name="pcap_artifact_type", create_type=False,
    )
    for enum_type in (pcap_status, artifact_type):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "pcap_files",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("stored_path", sa.Text, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column("status", pcap_status, nullable=False, server_default="uploaded"),
        sa.Column("packet_count", sa.Integer, nullable=True),
        sa.Column("first_packet_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_packet_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Float, nullable=True),
        sa.Column("link_type", sa.String(64), nullable=True),
        sa.Column("capture_interface", sa.String(64), nullable=True),
        sa.Column("flow_truncated", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("uploaded_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("parsed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_pcap_files_status", "pcap_files", ["status"])
    op.create_index("ix_pcap_files_uploaded_at", "pcap_files", ["uploaded_at"])

    op.create_table(
        "pcap_flows",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("pcap_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("pcap_files.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stream_id", sa.Integer, nullable=False),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("src_ip", postgresql.INET, nullable=False),
        sa.Column("src_port", sa.Integer, nullable=True),
        sa.Column("dst_ip", postgresql.INET, nullable=False),
        sa.Column("dst_port", sa.Integer, nullable=True),
        sa.Column("packet_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("byte_count", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("start_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("end_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("app_protocol", sa.String(32), nullable=True),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("src_asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("dst_asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_pcap_flows_pcap_bytes", "pcap_flows", ["pcap_id", "byte_count"])
    op.create_index("ix_pcap_flows_pcap_start", "pcap_flows", ["pcap_id", "start_ts"])
    op.create_index("ix_pcap_flows_src_ip", "pcap_flows", ["src_ip"])
    op.create_index("ix_pcap_flows_dst_ip", "pcap_flows", ["dst_ip"])

    op.create_table(
        "pcap_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("pcap_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("pcap_files.id", ondelete="CASCADE"), nullable=False),
        sa.Column("flow_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("pcap_flows.id", ondelete="SET NULL"), nullable=True),
        sa.Column("artifact_type", artifact_type, nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("detail", postgresql.JSONB, nullable=True),
        sa.Column("packet_number", sa.Integer, nullable=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_pcap_artifacts_pcap_type", "pcap_artifacts", ["pcap_id", "artifact_type"])


def downgrade() -> None:
    op.drop_table("pcap_artifacts")
    op.drop_table("pcap_flows")
    op.drop_table("pcap_files")

    bind = op.get_bind()
    for enum_name in ("pcap_artifact_type", "pcap_status"):
        postgresql.ENUM(name=enum_name).drop(bind, checkfirst=True)
