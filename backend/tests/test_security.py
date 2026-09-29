"""M1 unit tests: password hashing and JWT handling. No DB required."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)


def test_hash_is_argon2id_and_not_plaintext():
    digest = hash_password("correct-horse-battery")
    assert digest.startswith("$argon2id$")
    assert "correct-horse-battery" not in digest


def test_hash_is_salted_per_call():
    a = hash_password("same-password")
    b = hash_password("same-password")
    assert a != b
    assert verify_password("same-password", a)
    assert verify_password("same-password", b)


def test_verify_rejects_wrong_password():
    digest = hash_password("right")
    assert verify_password("right", digest) is True
    assert verify_password("wrong", digest) is False


def test_verify_on_garbage_hash_returns_false_not_raises():
    assert verify_password("anything", "not-a-hash") is False


def test_access_token_roundtrip_carries_role():
    uid = uuid.uuid4()
    payload = decode_token(create_access_token(uid, "admin"), "access")
    assert payload["sub"] == str(uid)
    assert payload["role"] == "admin"
    assert payload["type"] == "access"


def test_refresh_token_carries_session_id():
    uid = uuid.uuid4()
    payload = decode_token(create_refresh_token(uid, "sess-1"), "refresh")
    assert payload["sid"] == "sess-1"


def test_refresh_token_is_rejected_as_an_access_token():
    """The core confusion attack: a 7-day credential used as a 15-min one."""
    token = create_refresh_token(uuid.uuid4(), "sess-1")
    with pytest.raises(TokenError):
        decode_token(token, "access")


def test_access_token_is_rejected_as_a_refresh_token():
    token = create_access_token(uuid.uuid4(), "viewer")
    with pytest.raises(TokenError):
        decode_token(token, "refresh")


def test_tampered_signature_is_rejected():
    token = create_access_token(uuid.uuid4(), "viewer")
    header, payload, _ = token.split(".")
    with pytest.raises(TokenError):
        decode_token(f"{header}.{payload}.deadbeef", "access")


def test_expired_token_is_rejected(monkeypatch):
    import app.core.security as sec

    token = sec._encode(str(uuid.uuid4()), "access", timedelta(seconds=-1))
    with pytest.raises(TokenError, match="expired"):
        decode_token(token, "access")


def test_tokens_are_unique_per_issue():
    uid = uuid.uuid4()
    assert create_access_token(uid, "viewer") != create_access_token(uid, "viewer")
