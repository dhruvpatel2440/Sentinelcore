"""Declarative base and the model registry Alembic autogenerate reads.

Every model module must be imported in `app.db.base_all` so that
`Base.metadata` is complete when Alembic builds a migration.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
