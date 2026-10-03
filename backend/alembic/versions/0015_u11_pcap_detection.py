"""U11: PCAP-sourced incidents carry a signature name and structured
evidence instead of only a correlation `rule_id` (which is NULL for them).

Revision ID: 0015_u11_pcap_detection
Revises: 0014_u10_report_email_links
Create Date: 2026-10-03
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015_u11_pcap_detection"
down_revision: Union[str, None] = "0014_u10_report_email_links"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("signature_name", sa.String(128), nullable=True))
    op.add_column("incidents", sa.Column("evidence", postgresql.JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("incidents", "evidence")
    op.drop_column("incidents", "signature_name")
