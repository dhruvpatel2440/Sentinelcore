"""Suricata lifecycle and ruleset operations (M4).

Extends the M3 helper rather than creating a second privilege path. Every op is
individually validated and maps to a fixed argv list.

Rule *content* never crosses this socket. The backend writes a candidate file
into the shared staging volume; this module verifies its SHA-256, validates it
with `suricata -T`, and only then moves it into the live rules directory.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from helper.config import config
from helper.executor import ExecutionError, exclusive, run
from helper.validation import ValidationError, validate_rules_filename, validate_sha256

logger = logging.getLogger("helper.ops.suricata")

STOP_GRACE_SECONDS = 15
START_SETTLE_SECONDS = 3


# --------------------------------------------------------------------------
# Process state
# --------------------------------------------------------------------------


def _read_pid() -> int | None:
    """PID of the running Suricata daemon, or None.

    A SIGKILLed Suricata leaves its pidfile behind, and PIDs recycle quickly in
    a container. `suricata_status` itself spawns `suricata -V`, which can land
    on the very PID the stale file names — so a bare `kill(pid, 0)` check will
    report a stopped sensor as running. Identity is therefore confirmed from
    /proc/<pid>/cmdline, and a stale pidfile is cleaned up when detected.
    """
    try:
        raw = config.suricata_pid_file.read_text().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return None
    try:
        pid = int(raw)
    except ValueError:
        return None

    if _pid_is_suricata_daemon(pid):
        return pid

    # Stale: remove it so the next status call is a cheap miss.
    try:
        config.suricata_pid_file.unlink(missing_ok=True)
        logger.info("removed stale suricata pidfile naming pid=%s", pid)
    except OSError:
        pass
    return None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    return True


# One-shot invocations that are NOT the capture daemon.
_ONESHOT_FLAGS = {b"-V", b"--build-info", b"-T", b"--engine-analysis"}


def _pid_is_suricata_daemon(pid: int) -> bool:
    """True only when `pid` is a live, long-running Suricata capture process."""
    if pid <= 0:
        return False
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (OSError, FileNotFoundError):
        return False

    argv = [part for part in raw.split(b"\0") if part]
    if not argv:
        return False
    if b"suricata" not in Path(argv[0].decode("utf-8", "replace")).name.lower().encode():
        return False
    # `suricata -V` and `suricata -T` are transient helpers, not the sensor.
    if _ONESHOT_FLAGS & set(argv[1:]):
        return False
    return True


def _uptime_seconds(pid: int) -> float | None:
    """Process age from /proc, so a restart is visible as a reset uptime."""
    try:
        started_ticks = int(Path(f"/proc/{pid}/stat").read_text().split(") ")[-1].split()[19])
        boot_time = None
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("btime "):
                boot_time = int(line.split()[1])
                break
        if boot_time is None:
            return None
        hertz = os.sysconf("SC_CLK_TCK")
        return time.time() - (boot_time + started_ticks / hertz)
    except (OSError, ValueError, IndexError):
        return None


def _version() -> str | None:
    if config.suricata_path is None:
        return None
    try:
        result = run([config.suricata_path, "-V"], timeout=15, exclusive=False)
    except ExecutionError:
        return None
    # "This is Suricata version 7.0.2 RELEASE"
    for token in result.stdout.split():
        if token and token[0].isdigit():
            return token
    return result.stdout.strip()[:64] or None


def _ruleset_info() -> tuple[int, str | None]:
    """(rule count, sha256 of the live ruleset) across all .rules files."""
    rules_dir = config.suricata_rules_dir
    if not rules_dir.is_dir():
        return 0, None

    digest = hashlib.sha256()
    count = 0
    for path in sorted(rules_dir.glob("*.rules")):
        try:
            content = path.read_bytes()
        except OSError:
            continue
        digest.update(content)
        for line in content.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith(b"#"):
                count += 1

    return count, digest.hexdigest() if count or any(rules_dir.glob("*.rules")) else None


def _eve_log_age_seconds() -> float | None:
    """Age of eve.json. A sensor that is up but not writing is a real failure
    mode, and a distinct one from a sensor that is down."""
    eve = Path(os.getenv("SURICATA_EVE_LOG", "/var/log/suricata/eve.json"))
    try:
        return time.time() - eve.stat().st_mtime
    except (OSError, FileNotFoundError):
        return None


def suricata_status(params: dict) -> dict:
    pid = _read_pid()
    rule_count, checksum = _ruleset_info()

    return {
        "running": pid is not None,
        "pid": pid,
        "uptime_seconds": _uptime_seconds(pid) if pid else None,
        "version": _version(),
        "rule_count": rule_count,
        "ruleset_sha256": checksum,
        "eve_log_age_seconds": _eve_log_age_seconds(),
        "binary_available": config.suricata_path is not None,
    }


def suricata_start(params: dict) -> dict:
    if config.suricata_path is None:
        raise ExecutionError("binary_missing", "suricata is not installed in the helper image")

    if _read_pid() is not None:
        return {"already_running": True, **suricata_status({})}

    argv = [
        config.suricata_path,
        "-c",
        str(config.suricata_config_path),
        "--af-packet",
        "-i",
        config.capture_interface,
        "-D",  # daemonise; the pid file is how we track it afterwards
        "--pidfile",
        str(config.suricata_pid_file),
    ]
    result = run(argv, timeout=config.default_op_timeout_seconds)

    if result.returncode != 0:
        raise ExecutionError(
            "start_failed",
            f"suricata exited {result.returncode}: {result.stderr.strip()[:500]}",
        )

    time.sleep(START_SETTLE_SECONDS)  # let it write the pid file
    return {"started": True, **suricata_status({})}


def suricata_stop(params: dict) -> dict:
    """SIGTERM, then escalate to SIGKILL after a grace period."""
    pid = _read_pid()
    if pid is None:
        return {"already_stopped": True, **suricata_status({})}

    os.kill(pid, signal.SIGTERM)
    logger.info("sent SIGTERM to suricata pid=%s", pid)

    deadline = time.time() + STOP_GRACE_SECONDS
    while time.time() < deadline:
        if not _pid_alive(pid):
            _clear_pidfile()
            return {"stopped": True, "escalated": False, **suricata_status({})}
        time.sleep(0.5)

    logger.warning("suricata pid=%s ignored SIGTERM, sending SIGKILL", pid)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    time.sleep(1)

    stopped = not _pid_is_suricata_daemon(pid)
    if stopped:
        # A SIGKILLed Suricata never gets to clean up after itself.
        _clear_pidfile()

    return {"stopped": stopped, "escalated": True, **suricata_status({})}


def _clear_pidfile() -> None:
    try:
        config.suricata_pid_file.unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("could not remove pidfile: %s", exc)


def _test_config(*, exclusive_lock: bool) -> dict:
    """`suricata -T` dry run. Never touches the live ruleset.

    `exclusive_lock=False` is for callers that already hold the execution lock
    (see `suricata_write_rules`); the semaphore is not reentrant.
    """
    if config.suricata_path is None:
        raise ExecutionError("binary_missing", "suricata is not installed in the helper image")

    argv = [config.suricata_path, "-T", "-c", str(config.suricata_config_path)]
    result = run(argv, timeout=config.suricata_test_timeout_seconds, exclusive=exclusive_lock)

    return {
        "valid": result.returncode == 0,
        "returncode": result.returncode,
        # Output is data returned to the caller; it is never re-executed.
        "output": (result.stderr or result.stdout)[-8000:],
    }


def suricata_test_config(params: dict) -> dict:
    return _test_config(exclusive_lock=True)


def suricata_reload_rules(params: dict) -> dict:
    """Reload without dropping packets — never a full restart.

    Prefers suricatasc's non-blocking reload; falls back to SIGUSR2, which
    Suricata also treats as a live ruleset reload.
    """
    pid = _read_pid()
    if pid is None:
        raise ExecutionError("not_running", "Suricata is not running; cannot reload rules")

    if config.suricatasc_path is not None and config.suricata_socket.exists():
        result = run(
            [
                config.suricatasc_path,
                "-c",
                "ruleset-reload-nonblocking",
                str(config.suricata_socket),
            ],
            timeout=120,
        )
        if result.returncode == 0:
            return {"reloaded": True, "method": "suricatasc", **_reload_summary()}
        logger.warning("suricatasc reload failed (%s), falling back to SIGUSR2", result.returncode)

    os.kill(pid, signal.SIGUSR2)
    time.sleep(2)
    return {"reloaded": True, "method": "sigusr2", **_reload_summary()}


def _reload_summary() -> dict:
    rule_count, checksum = _ruleset_info()
    return {"rule_count": rule_count, "ruleset_sha256": checksum}


def suricata_write_rules(params: dict) -> dict:
    """Promote a staged rule file into the live rules directory.

    Sequence, in order, with rollback at every failure point:
      1. validate the filename (no traversal)
      2. verify the staged file's SHA-256 matches what the caller claims
      3. back up the current live file
      4. move the staged file into place
      5. `suricata -T` to validate the resulting ruleset
      6. on failure, restore the backup — a bad update never leaves the
         sensor running a broken or empty ruleset
    """
    filename = validate_rules_filename(params.get("filename"))
    expected_sha = validate_sha256(params.get("content_sha256"))

    staged = config.suricata_staging_dir / filename
    target = config.suricata_rules_dir / filename

    # Belt and braces: confirm the resolved paths really are inside their
    # directories, in case the filename regex is ever loosened.
    _assert_contained(staged, config.suricata_staging_dir)
    _assert_contained(target, config.suricata_rules_dir)

    if not staged.is_file():
        raise ValidationError("staged_missing", f"No staged rule file named {filename}")

    actual_sha = _sha256_file(staged)
    if actual_sha != expected_sha:
        # The file changed between the backend writing it and us reading it.
        raise ValidationError(
            "checksum_mismatch",
            f"Staged file checksum {actual_sha[:16]}… does not match the expected value",
        )

    config.suricata_rules_dir.mkdir(parents=True, exist_ok=True)
    backup = target.with_suffix(".rules.bak")

    # The lock is taken BEFORE the file is moved and held through validation.
    # Acquiring it only for the `-T` call would let a concurrent operation
    # fail the validation and roll back a perfectly good ruleset.
    with exclusive():
        had_previous = target.is_file()
        if had_previous:
            shutil.copy2(target, backup)

        try:
            shutil.move(str(staged), str(target))
            os.chmod(target, 0o644)

            validation = _test_config(exclusive_lock=False)
            if not validation["valid"]:
                raise ExecutionError(
                    "validation_failed",
                    f"Ruleset rejected by suricata -T: {validation['output'][-400:]}",
                )

        except Exception:
            if had_previous:
                shutil.copy2(backup, target)
                logger.warning("restored previous ruleset for %s after failed update", filename)
            else:
                target.unlink(missing_ok=True)
            raise
        finally:
            backup.unlink(missing_ok=True)

    rule_count, checksum = _ruleset_info()
    return {
        "written": True,
        "filename": filename,
        "sha256": actual_sha,
        "rule_count": rule_count,
        "ruleset_sha256": checksum,
    }


def _assert_contained(path: Path, parent: Path) -> None:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        raise ValidationError("path_escape", "Resolved path escapes its directory") from None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
