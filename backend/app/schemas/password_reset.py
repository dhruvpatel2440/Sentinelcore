from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.schemas.user import _check_password


class PasswordResetRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=1, max_length=512)
    new_password: str = Field(max_length=256)

    _validate_password = field_validator("new_password")(_check_password)


class PasswordResetAccepted(BaseModel):
    """Identical body regardless of whether the account exists — the whole
    point is that this response cannot be used to enumerate usernames."""

    detail: str = "If that account exists, a password reset email has been sent."
