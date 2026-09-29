from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models.user import UserRole

_MIN_PASSWORD_LENGTH = 12


def _check_password(value: str) -> str:
    if len(value) < _MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters")
    return value


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(max_length=256)
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=255)
    role: UserRole = UserRole.VIEWER

    _validate_password = field_validator("password")(_check_password)


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=255)
    role: UserRole | None = None
    is_active: bool | None = None


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)

    _validate_password = field_validator("new_password")(_check_password)


class PasswordReset(BaseModel):
    """Admin-initiated reset — no current password required."""

    new_password: str = Field(max_length=256)

    _validate_password = field_validator("new_password")(_check_password)
