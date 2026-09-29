#!/bin/sh
# Backend/worker container entrypoint: wait for the DB, optionally migrate, then serve.
# Runs as the unprivileged `appuser` — see Dockerfile. Never add sudo here.
#
# RUN_MIGRATIONS=false is set for the worker container: only ONE process may
# run `alembic upgrade head`, or two concurrent migrations race on the same
# schema. The API owns migrations; the worker just waits for them.
set -eu

RUN_MIGRATIONS="${RUN_MIGRATIONS:-true}"

echo "[entrypoint] waiting for database..."
python - <<'PY'
import asyncio, sys
from sqlalchemy import text
from app.db.session import engine

async def wait(attempts=30, delay=2):
    for i in range(1, attempts + 1):
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            print(f"[entrypoint] database reachable after {i} attempt(s)")
            await engine.dispose()
            return 0
        except Exception as exc:
            print(f"[entrypoint] attempt {i}/{attempts}: {type(exc).__name__}")
            await asyncio.sleep(delay)
    await engine.dispose()
    return 1

sys.exit(asyncio.run(wait()))
PY

if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo "[entrypoint] applying migrations..."
    alembic upgrade head

    echo "[entrypoint] seeding admin user (idempotent)..."
    python -m scripts.seed_admin
else
    echo "[entrypoint] RUN_MIGRATIONS=false — waiting for the API to migrate..."
    python - <<'PY'
import asyncio, sys
from sqlalchemy import text
from app.db.session import engine

async def wait_for_schema(attempts=60, delay=2):
    """Block until the API container has created the events table."""
    for i in range(1, attempts + 1):
        try:
            async with engine.connect() as conn:
                found = await conn.scalar(text("SELECT to_regclass('public.events')"))
            if found:
                print(f"[entrypoint] schema ready after {i} attempt(s)")
                await engine.dispose()
                return 0
        except Exception as exc:
            print(f"[entrypoint] schema check {i}/{attempts}: {type(exc).__name__}")
        await asyncio.sleep(delay)
    await engine.dispose()
    print("[entrypoint] timed out waiting for the schema", file=sys.stderr)
    return 1

sys.exit(asyncio.run(wait_for_schema()))
PY
fi

echo "[entrypoint] starting: $*"
exec "$@"
