"""Checksums and detached-signature verification (GnuPG).

Releases publish ``SHA256SUMS`` and ``latest.json`` with detached ``.asc``
signatures made by the release key. The public key ships with the package and
is published on the website.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from .common import CommandError, find_asset, run


class SignatureError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_sha256sums(text: str) -> dict[str, str]:
    """``<hex>  <name>`` lines (sha256sum format) -> {name: hex}."""
    sums: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise SignatureError(f"malformed checksum line: {line[:80]!r}")
        sums[parts[1].lstrip("*").strip()] = parts[0].lower()
    return sums


def verify_checksum(path: Path, sums: dict[str, str], name: str | None = None) -> None:
    key = name or path.name
    expected = sums.get(key)
    if not expected:
        raise SignatureError(f"{key} is not listed in SHA256SUMS")
    actual = sha256_file(path)
    if actual != expected:
        raise SignatureError(f"checksum mismatch for {key}: expected {expected[:12]}..., got {actual[:12]}...")


def release_key_path() -> Path | None:
    return find_asset("release-key.asc")


def verify_detached(data: Path, signature: Path, pubkey: Path | None = None) -> str:
    """Verify ``signature`` over ``data`` with the release public key.

    Returns the signing key fingerprint. Raises SignatureError otherwise. The
    key is imported into a throw-away keyring, so the system keyring is never
    touched and no other trusted key can satisfy the check.
    """
    key = pubkey or release_key_path()
    if key is None or not key.exists():
        raise SignatureError("the release public key (release-key.asc) is not installed")
    with tempfile.TemporaryDirectory(prefix="sc-gnupg-") as home:
        os.chmod(home, 0o700)
        env = {"GNUPGHOME": home}
        try:
            run(["gpg", "--batch", "--no-tty", "--import", str(key)], env=env)
            res = run(
                ["gpg", "--batch", "--no-tty", "--status-fd", "1", "--verify", str(signature), str(data)],
                env=env, check=False,
            )
        except CommandError as exc:
            raise SignatureError(f"gpg is unavailable or the key is unusable: {exc.output}") from exc
    for line in res.stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG"):
            return line.split()[2]
    raise SignatureError("signature verification FAILED: do not install this file")
