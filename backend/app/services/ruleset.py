"""Rule feed fetch, extraction, composition and safe deployment.

Pipeline: fetch → extract (guarded) → apply overrides → compose → stage →
checksum → validate → write → reload. Any failure leaves the previous ruleset
live; a bad rule update must never take the sensor down.
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from app.core.config import settings
from app.services import helper_client

logger = logging.getLogger("sentinelcore.ruleset")

# A rule feed is untrusted input downloaded over the network. Cap everything.
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 5000
DOWNLOAD_TIMEOUT = 120.0

COMPOSED_FILENAME = "sentinelcore.rules"

# `sid:12345;` inside a rule line.
_SID_RE = re.compile(rb"\bsid\s*:\s*(\d+)\s*;")


class RulesetError(Exception):
    pass


@dataclass
class ExtractedRules:
    files: dict[str, bytes] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(len(v) for v in self.files.values())


async def fetch_feed(url: str) -> bytes:
    """Download a rule archive over HTTPS with a timeout and a size cap."""
    if not url.lower().startswith("https://"):
        raise RulesetError("Rule sources must use HTTPS")

    try:
        async with httpx.AsyncClient(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()

                declared = response.headers.get("content-length")
                if declared and int(declared) > MAX_DOWNLOAD_BYTES:
                    raise RulesetError(f"Feed exceeds the {MAX_DOWNLOAD_BYTES} byte limit")

                chunks = bytearray()
                async for chunk in response.aiter_bytes():
                    chunks.extend(chunk)
                    # Check as we stream: a lying Content-Length must not let a
                    # feed exhaust memory.
                    if len(chunks) > MAX_DOWNLOAD_BYTES:
                        raise RulesetError(f"Feed exceeds the {MAX_DOWNLOAD_BYTES} byte limit")
                return bytes(chunks)

    except httpx.HTTPStatusError as exc:
        raise RulesetError(f"Feed returned HTTP {exc.response.status_code}") from exc
    except httpx.RequestError as exc:
        raise RulesetError(f"Could not reach the rule feed: {type(exc).__name__}") from exc


def _is_safe_member(name: str) -> bool:
    """Zip-slip guard.

    Rejects absolute paths, traversal, drive letters and anything whose
    normalized form escapes the extraction root. Applied to *every* member —
    there is deliberately no blanket `extractall` anywhere in this module.
    """
    if not name or name.startswith("/") or name.startswith("\\"):
        return False
    if ".." in Path(name).parts:
        return False
    if re.match(r"^[a-zA-Z]:", name):  # windows drive letter
        return False
    if "\x00" in name:
        return False

    # Final containment check against a notional root.
    root = Path("/extract")
    try:
        (root / name).resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def extract_rules(archive: bytes) -> ExtractedRules:
    """Extract only `.rules` members, one at a time, with a size cap each."""
    result = ExtractedRules()

    if archive[:2] == b"PK":
        _extract_zip(archive, result)
    else:
        _extract_tar(archive, result)

    if not result.files:
        raise RulesetError("Archive contained no .rules files")

    logger.info(
        "extracted %d rule file(s), skipped %d member(s)", len(result.files), len(result.skipped)
    )
    return result


def _extract_zip(archive: bytes, result: ExtractedRules) -> None:
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        members = zf.infolist()
        if len(members) > MAX_MEMBERS:
            raise RulesetError(f"Archive has too many members ({len(members)})")

        for info in members:
            if info.is_dir():
                continue
            if not _is_safe_member(info.filename):
                result.skipped.append(f"unsafe:{info.filename}")
                logger.warning("refusing unsafe archive member: %r", info.filename)
                continue
            if not info.filename.endswith(".rules"):
                result.skipped.append(f"not-rules:{info.filename}")
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                result.skipped.append(f"too-large:{info.filename}")
                continue

            with zf.open(info) as handle:
                # read(n+1) so a zip bomb declaring a small size is still caught.
                data = handle.read(MAX_MEMBER_BYTES + 1)
            if len(data) > MAX_MEMBER_BYTES:
                result.skipped.append(f"too-large:{info.filename}")
                continue

            result.files[Path(info.filename).name] = data


def _extract_tar(archive: bytes, result: ExtractedRules) -> None:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(archive), mode="r:*")
    except tarfile.TarError as exc:
        raise RulesetError(f"Archive is not a readable zip or tar: {exc}") from exc

    with tf:
        count = 0
        for member in tf:
            count += 1
            if count > MAX_MEMBERS:
                raise RulesetError("Archive has too many members")

            # Symlinks and hardlinks can point outside the extraction root even
            # when the member name itself looks safe.
            if not member.isfile():
                result.skipped.append(f"not-a-file:{member.name}")
                continue
            if not _is_safe_member(member.name):
                result.skipped.append(f"unsafe:{member.name}")
                logger.warning("refusing unsafe archive member: %r", member.name)
                continue
            if not member.name.endswith(".rules"):
                result.skipped.append(f"not-rules:{member.name}")
                continue
            if member.size > MAX_MEMBER_BYTES:
                result.skipped.append(f"too-large:{member.name}")
                continue

            handle = tf.extractfile(member)
            if handle is None:
                continue
            data = handle.read(MAX_MEMBER_BYTES + 1)
            if len(data) > MAX_MEMBER_BYTES:
                result.skipped.append(f"too-large:{member.name}")
                continue

            result.files[Path(member.name).name] = data


@dataclass
class OverrideSpec:
    """A `rule_overrides` row, flattened for composition."""

    sid: int
    action: str  # disabled | enabled | threshold
    params: dict | None = None


def apply_overrides(rules: bytes, overrides: list[OverrideSpec]) -> tuple[bytes, dict[str, int]]:
    """Comment out disabled SIDs, re-enable disabled ones, append thresholds."""
    disabled = {o.sid for o in overrides if o.action == "disabled"}
    enabled = {o.sid for o in overrides if o.action == "enabled"}
    thresholds = [o for o in overrides if o.action == "threshold"]

    stats = {"disabled": 0, "enabled": 0, "thresholds": 0, "total": 0}
    output: list[bytes] = []

    for line in rules.splitlines():
        stripped = line.strip()
        if not stripped:
            output.append(line)
            continue

        is_commented = stripped.startswith(b"#")
        probe = stripped.lstrip(b"#").strip() if is_commented else stripped

        match = _SID_RE.search(probe)
        if match is None:
            output.append(line)
            continue

        sid = int(match.group(1))
        if not is_commented:
            stats["total"] += 1

        if sid in disabled and not is_commented:
            output.append(b"# DISABLED BY SENTINELCORE: " + line)
            stats["disabled"] += 1
        elif sid in enabled and is_commented:
            output.append(probe)
            stats["enabled"] += 1
            stats["total"] += 1
        else:
            output.append(line)

    for override in thresholds:
        params = override.params or {}
        threshold_type = str(params.get("type", "limit"))
        track = str(params.get("track", "by_src"))
        count = int(params.get("count", 1))
        seconds = int(params.get("seconds", 60))

        # Validate against fixed vocabularies — this line is written into a
        # config file consumed by Suricata, so nothing free-form goes in.
        if threshold_type not in {"limit", "threshold", "both"}:
            continue
        if track not in {"by_src", "by_dst", "by_rule", "by_both"}:
            continue
        if not (1 <= count <= 10000) or not (1 <= seconds <= 86400):
            continue

        output.append(
            f"# SentinelCore threshold for sid {override.sid}".encode()
            + b"\n"
            + f"threshold gen_id 1, sig_id {override.sid}, type {threshold_type}, "
            f"track {track}, count {count}, seconds {seconds}".encode()
        )
        stats["thresholds"] += 1

    return b"\n".join(output) + b"\n", stats


def compose(extracted: ExtractedRules, overrides: list[OverrideSpec]) -> tuple[bytes, dict[str, int]]:
    """Concatenate every extracted rule file, then apply overrides once."""
    parts: list[bytes] = [b"# Composed by SentinelCore. Do not edit by hand.\n"]
    for name in sorted(extracted.files):
        parts.append(f"\n# --- {name} ---\n".encode())
        parts.append(extracted.files[name])
        if not extracted.files[name].endswith(b"\n"):
            parts.append(b"\n")

    return apply_overrides(b"".join(parts), overrides)


def stage(content: bytes, filename: str = COMPOSED_FILENAME) -> tuple[Path, str]:
    """Write the candidate file to the shared staging volume, return its sha256.

    The helper reads from this path and verifies the checksum, so rule content
    never travels through the socket as a command argument.
    """
    staging_dir = Path(settings.suricata_staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    path = staging_dir / filename
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()

    logger.info("staged %s (%d bytes, sha256=%s…)", path, len(content), digest[:16])
    return path, digest


async def deploy(content: bytes, filename: str = COMPOSED_FILENAME) -> dict:
    """Stage → verify → validate → write → reload, with rollback inside the helper."""
    _, digest = stage(content, filename)

    write_result = await helper_client.call(
        "suricata_write_rules",
        {"filename": filename, "content_sha256": digest},
        timeout=1200.0,
    )

    reload_result: dict = {}
    try:
        reload_result = await helper_client.call("suricata_reload_rules", timeout=180.0)
    except helper_client.HelperRejected as exc:
        # Rules are on disk and validated; the sensor just is not running.
        # Not a failure of the update itself.
        if exc.code != "not_running":
            raise
        logger.info("rules written but sensor is not running; reload skipped")

    return {**write_result, "reload": reload_result, "sha256": digest}
