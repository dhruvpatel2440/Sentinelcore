"""Newline-delimited JSON request/response framing."""

from __future__ import annotations

import json
from typing import Any


class ProtocolError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


MAX_OP_NAME = 64
MAX_REQUEST_ID = 64


def parse_request(raw: bytes) -> tuple[str, str, dict[str, Any]]:
    """Return `(op, request_id, params)` from one NDJSON line."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("bad_encoding", "Request must be UTF-8") from exc

    try:
        message = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError("bad_json", "Request is not valid JSON") from exc

    if not isinstance(message, dict):
        raise ProtocolError("bad_request", "Request must be a JSON object")

    op = message.get("op")
    if not isinstance(op, str) or not op or len(op) > MAX_OP_NAME:
        raise ProtocolError("bad_request", "Missing or invalid 'op'")

    request_id = message.get("request_id", "")
    if not isinstance(request_id, str) or len(request_id) > MAX_REQUEST_ID:
        raise ProtocolError("bad_request", "Invalid 'request_id'")

    params = message.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ProtocolError("bad_request", "'params' must be an object")

    return op, request_id, params


def ok_response(request_id: str, data: dict[str, Any]) -> bytes:
    return _encode({"ok": True, "request_id": request_id, "data": data})


def error_response(request_id: str, code: str, message: str) -> bytes:
    return _encode(
        {"ok": False, "request_id": request_id, "error": {"code": code, "message": message}}
    )


def _encode(payload: dict[str, Any]) -> bytes:
    # separators without spaces keeps large XML payloads a little smaller.
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
