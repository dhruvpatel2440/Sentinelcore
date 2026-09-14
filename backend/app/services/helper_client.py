"""Async client for the privileged helper's Unix socket.

The backend has no raw-socket capability of its own; anything needing root goes
through here. A helper failure must never surface as a 500 with a traceback —
callers map these exceptions onto clean 502/503 responses.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from app.core.config import settings

logger = logging.getLogger("sentinelcore.helper_client")

# Generous: an nmap sweep of a /24 with service detection genuinely takes minutes.
DEFAULT_TIMEOUT = 960.0
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class HelperError(Exception):
    """Base for every helper failure."""


class HelperUnavailable(HelperError):
    """The socket is missing, unreachable, or the connection dropped."""


class HelperTimeout(HelperError):
    """The helper accepted the request but did not answer in time."""


class HelperRejected(HelperError):
    """The helper refused the request. `code` mirrors its validation codes."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


async def call(
    op: str,
    params: dict[str, Any] | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Send one op and await its response.

    One connection per request: the protocol is request/response and this
    avoids any chance of two callers interleaving on a shared stream.
    """
    request_id = request_id or str(uuid.uuid4())
    payload = json.dumps(
        {"op": op, "request_id": request_id, "params": params or {}},
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"

    socket_path = settings.helper_socket_path
    logger.info("helper call op=%s request_id=%s", op, request_id)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(socket_path), timeout=10.0
        )
    except (FileNotFoundError, ConnectionRefusedError, PermissionError) as exc:
        logger.error("helper socket unavailable at %s: %s", socket_path, exc)
        raise HelperUnavailable(f"Privileged helper is not reachable: {type(exc).__name__}") from exc
    except asyncio.TimeoutError as exc:
        raise HelperUnavailable("Timed out connecting to the privileged helper") from exc
    except OSError as exc:
        raise HelperUnavailable(f"Helper socket error: {exc}") from exc

    try:
        writer.write(payload)
        await writer.drain()

        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise HelperTimeout(f"Helper did not respond to {op!r} within {timeout:.0f}s") from exc
    except (ConnectionResetError, BrokenPipeError) as exc:
        # This is the "killed mid-scan" path — surface it as unavailable so the
        # caller can mark the work failed with a readable reason.
        raise HelperUnavailable("Helper connection dropped mid-request") from exc
    except OSError as exc:
        raise HelperUnavailable(f"Helper I/O error: {exc}") from exc
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    if not raw:
        raise HelperUnavailable("Helper closed the connection without responding")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise HelperError("Helper response exceeded the size limit")

    try:
        message = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HelperError("Helper returned a malformed response") from exc

    if not isinstance(message, dict):
        raise HelperError("Helper returned an unexpected response shape")

    if not message.get("ok"):
        error = message.get("error") or {}
        code = str(error.get("code", "helper_error"))
        msg = str(error.get("message", "The privileged helper rejected the request"))
        logger.warning("helper rejected op=%s request_id=%s code=%s", op, request_id, code)
        raise HelperRejected(code, msg)

    data = message.get("data")
    return data if isinstance(data, dict) else {}


async def ping(timeout: float = 5.0) -> bool:
    """Liveness probe used by the health endpoint."""
    try:
        await call("ping", timeout=timeout)
        return True
    except HelperError:
        return False
