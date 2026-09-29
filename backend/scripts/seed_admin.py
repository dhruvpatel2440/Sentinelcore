"""Create the bootstrap admin account. Idempotent — safe to run on every boot.

Password comes from SEED_ADMIN_PASSWORD. If it is unset, a strong random one is
generated and printed **once**; there is no default credential to forget to
change, because there is no default credential.

    python -m scripts.seed_admin
"""

from __future__ import annotations

import asyncio
import os
import secrets
import string
import sys

from sqlalchemy import select

from app.core.security import hash_password
from app.db.session import SessionLocal, engine
from app.models.user import User, UserRole

_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*-_=+"


def _generate_password(length: int = 24) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


async def seed() -> int:
    username = os.getenv("SEED_ADMIN_USERNAME", "admin")
    password = os.getenv("SEED_ADMIN_PASSWORD")
    email = os.getenv("SEED_ADMIN_EMAIL")

    generated = password is None
    if generated:
        password = _generate_password()
    elif len(password) < 12:
        print("SEED_ADMIN_PASSWORD must be at least 12 characters", file=sys.stderr)
        return 1

    try:
        async with SessionLocal() as db:
            existing = await db.scalar(select(User).where(User.username == username))
            if existing is not None:
                print(f"Admin user '{username}' already exists — nothing to do.")
                return 0

            db.add(
                User(
                    username=username,
                    email=email,
                    full_name="SentinelCore Administrator",
                    role=UserRole.ADMIN,
                    password_hash=hash_password(password),
                    is_active=True,
                )
            )
            await db.commit()
    finally:
        # Dispose inside this loop; the engine's connections belong to it.
        await engine.dispose()

    print(f"Created admin user '{username}'.")
    if generated:
        print("=" * 62)
        print(f"  GENERATED PASSWORD: {password}")
        print("  Store it now — it is not recoverable and will not be shown again.")
        print("=" * 62)
    return 0


def main() -> None:
    sys.exit(asyncio.run(seed()))


if __name__ == "__main__":
    main()
