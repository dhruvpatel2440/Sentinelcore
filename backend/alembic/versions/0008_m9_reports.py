"""M9: reports, report_schedules

Canonical addition from M9.

Revision ID: 0008_m9_reports
Revises: 0007_m8_incidents
Create Date: 2026-09-21
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_m9_reports"
down_revision: Union[str, None] = "0007_m8_incidents"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    report_type = postgresql.ENUM(
        "incident_summary", "incident_detail", "asset_inventory", "event_statistics",
        name="report_type", create_type=False,
    )
    report_format = postgresql.ENUM("pdf", "csv", "json", name="report_format", create_type=False)
    report_status = postgresql.ENUM(
        "queued", "running", "completed", "failed", name="report_status", create_type=False
    )
    for enum_type in (report_type, report_format, report_status):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "reports",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column("report_type", report_type, nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("params", postgresql.JSONB, nullable=False),
        sa.Column("format", report_format, nullable=False),
        sa.Column("status", report_status, nullable=False, server_default="queued"),
        sa.Column(
            "requested_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("file_size", sa.Integer, nullable=True),
        sa.Column("checksum", sa.String(64), nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_reports_expires_at", "reports", ["expires_at"])
    op.create_index("ix_reports_requested_by", "reports", ["requested_by"])
    op.create_index("ix_reports_status", "reports", ["status"])

    op.create_table(
        "report_schedules",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column("report_type", report_type, nullable=False),
        sa.Column("params", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("format", report_format, nullable=False),
        sa.Column("cron", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("recipients", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column(
            "created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(), onupdate=sa.func.now(),
        ),
    )
    op.create_index("ix_report_schedules_next_run_at", "report_schedules", ["next_run_at"])


def downgrade() -> None:
    op.drop_table("report_schedules")
    op.drop_table("reports")

    bind = op.get_bind()
    for enum_name in ("report_status", "report_format", "report_type"):
        postgresql.ENUM(name=enum_name).drop(bind, checkfirst=True)
