"""Redis-backed login attempt throttling.

Keyed on username+IP so one attacker cannot lock every account out by
hammering a single username from anywhere (that would be a DoS), and a single
IP cannot spray the whole user list.
"""

from __future__ import annotations

import hashlib

from app.core.config import settings
from app.core.redis import get_redis

_PREFIX = "auth:login_fail:"


def _key(username: str, ip: str | None) -> str:
    # Hashed so usernames are not sitting in plaintext in Redis keyspace dumps.
    digest = hashlib.sha256(f"{username.lower()}|{ip or '-'}".encode()).hexdigest()[:32]
    return f"{_PREFIX}{digest}"


async def is_locked_out(username: str, ip: str | None) -> bool:
    try:
        raw = await get_redis().get(_key(username, ip))
    except Exception:
        # Redis down must not make the platform unloggable-into. Throttling is
        # a mitigation, not the authentication boundary itself.
        return False
    if raw is None:
        return False
    try:
        return int(raw) >= settings.login_max_attempts
    except (TypeError, ValueError):
        return False


async def record_failure(username: str, ip: str | None) -> int:
    key = _key(username, ip)
    try:
        redis = get_redis()
        async with redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, settings.login_lockout_seconds)
            count, _ = await pipe.execute()
        return int(count)
    except Exception:
        return 0


async def clear(username: str, ip: str | None) -> None:
    try:
        await get_redis().delete(_key(username, ip))
    except Exception:
        pass
