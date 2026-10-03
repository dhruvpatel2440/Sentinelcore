"""U10: email notifications — outbox, preferences, settings, suppressions,
password reset tokens, login events.

`email_outbox` is the only table the API or worker ever inserts an email
into; nothing sends to Brevo directly from a request (CLAUDE.md-style
separation of the write from the side effect). `login_events` backs E21
(new-IP / suspicious login detection) and is pruned by the existing
retention job.

Revision ID: 0013_u10_email
Revises: 0012_audit_immutable
Create Date: 2026-10-03
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_u10_email"
down_revision: Union[str, None] = "0012_audit_immutable"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_EMAIL_TYPES = [f"E{i:02d}" for i in range(1, 22)]


def upgrade() -> None:
    bind = op.get_bind()

    email_type = postgresql.ENUM(*_EMAIL_TYPES, name="email_type", create_type=False)
    email_status = postgresql.ENUM(
        "queued", "sending", "sent", "failed", "suppressed", "dry_run",
        name="email_outbox_status", create_type=False,
    )
    email_severity = postgresql.ENUM(name="event_severity", create_type=False)  # reuse M5's severity enum
    email_delivery_mode = postgresql.ENUM("instant", "digest", name="email_delivery_mode", create_type=False)
    email_digest_frequency = postgresql.ENUM("daily", "weekly", name="email_digest_frequency", create_type=False)
    suppression_reason = postgresql.ENUM(
        "hard_bounce", "blocked", "spam", "unsubscribed", "manual",
        name="email_suppression_reason", create_type=False,
    )
    for enum_type in (email_type, email_status, email_delivery_mode, email_digest_frequency, suppression_reason):
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "email_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email_type", email_type, nullable=False),
        sa.Column("recipient_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("recipient_email", sa.String(255), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("html_body", sa.Text, nullable=False),
        sa.Column("text_body", sa.Text, nullable=False),
        sa.Column("dedupe_key", sa.String(255), nullable=True),
        sa.Column("status", email_status, nullable=False, server_default="queued"),
        sa.Column("digest", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("provider_message_id", sa.String(255), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("related_type", sa.String(64), nullable=True),
        sa.Column("related_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_email_outbox_status_next_attempt", "email_outbox", ["status", "next_attempt_at"])
    op.create_index("ix_email_outbox_provider_message_id", "email_outbox", ["provider_message_id"])
    op.create_index("ix_email_outbox_created_at", "email_outbox", ["created_at"])
    op.create_index(
        "uq_email_outbox_dedupe_key",
        "email_outbox",
        ["dedupe_key"],
        unique=True,
        postgresql_where=sa.text("dedupe_key IS NOT NULL"),
    )

    op.create_table(
        "email_preferences",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("min_severity", email_severity, nullable=False, server_default="high"),
        sa.Column("delivery_mode", email_delivery_mode, nullable=False, server_default="instant"),
        sa.Column("types_disabled", postgresql.ARRAY(sa.Text), nullable=False, server_default=sa.text("'{}'::text[]")),
        sa.Column("digest_frequency", email_digest_frequency, nullable=False, server_default="daily"),
        sa.Column("digest_hour_utc", sa.Integer, nullable=False, server_default="13"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "email_settings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("types_enabled", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("global_pause", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.execute("INSERT INTO email_settings (id, types_enabled, global_pause) VALUES (1, '{}'::jsonb, false)")

    op.create_table(
        "email_suppressions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("reason", suppression_reason, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "password_reset_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),  # sha256 hex
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_ip", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"])

    op.create_table(
        "login_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("user_agent_hash", sa.String(64), nullable=True),
        sa.Column("success", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_login_events_user_created", "login_events", ["user_id", "created_at"])


def downgrade() -> None:
    op.drop_table("login_events")
    op.drop_table("password_reset_tokens")
    op.drop_table("email_suppressions")
    op.drop_table("email_settings")
    op.drop_table("email_preferences")
    op.drop_table("email_outbox")

    bind = op.get_bind()
    for enum_name in (
        "email_suppression_reason",
        "email_digest_frequency",
        "email_delivery_mode",
        "email_outbox_status",
        "email_type",
    ):
        postgresql.ENUM(name=enum_name).drop(bind, checkfirst=True)
