"""U10: link reports to the schedule that produced them (E11) and let an
on-demand requester opt into "email me when ready" (E12).

Revision ID: 0014_u10_report_email_links
Revises: 0013_u10_email
Create Date: 2026-10-03
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_u10_report_email_links"
down_revision: Union[str, None] = "0013_u10_email"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "reports",
        sa.Column("schedule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("report_schedules.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column("reports", sa.Column("notify_requester", sa.Boolean, nullable=False, server_default=sa.false()))
    op.create_index("ix_reports_schedule_id", "reports", ["schedule_id"])


def downgrade() -> None:
    op.drop_index("ix_reports_schedule_id", table_name="reports")
    op.drop_column("reports", "notify_requester")
    op.drop_column("reports", "schedule_id")
