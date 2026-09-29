"""Subprocess execution — the only place in the helper that spawns a process.

Invariants enforced here rather than trusted to callers:
  * `shell=False`, always. There is no code path that builds a shell string.
  * argv[0] is an absolute path resolved at startup.
  * every call has a hard timeout.
  * output is captured, size-capped, and never interpolated back into a command.
"""

from __future__ import annotations

import logging
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

logger = logging.getLogger("helper.executor")

# Nmap XML for a /20 with service detection can be large, but not unbounded.
MAX_OUTPUT_BYTES = 32 * 1024 * 1024


class ExecutionError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ExecResult:
    returncode: int
    stdout: str
    stderr: str
    argv: list[str]


# One privileged subprocess at a time across the whole helper. A caller that
# floods the socket queues behind this rather than forking processes on the host.
_exec_lock = threading.Semaphore(1)


class BusyError(ExecutionError):
    def __init__(self) -> None:
        super().__init__("helper_busy", "Another privileged operation is already running")


@contextmanager
def exclusive() -> Iterator[None]:
    """Hold the execution lock across several steps.

    Needed by multi-step ops like `suricata_write_rules`, where promoting a
    file and validating it must be atomic — otherwise a concurrent operation
    can make the validation fail and trigger a spurious rollback of a
    perfectly good ruleset.

    Calls to `run()` inside this block must pass `exclusive=False`; the
    semaphore is not reentrant and would deadlock.
    """
    if not _exec_lock.acquire(blocking=False):
        raise BusyError()
    try:
        yield
    finally:
        _exec_lock.release()


def run(argv: list[str], *, timeout: int, exclusive: bool = True) -> ExecResult:
    """Run `argv` with no shell. Raises ExecutionError on timeout or spawn failure."""
    if not argv or not argv[0].startswith("/"):
        # Defensive: an op handler that forgot to use a resolved absolute path
        # is a bug, and a PATH-dependent exec is a privilege-escalation vector.
        raise ExecutionError("bad_argv", "argv[0] must be an absolute path")

    acquired = False
    if exclusive:
        acquired = _exec_lock.acquire(blocking=False)
        if not acquired:
            raise BusyError()

    try:
        logger.info("exec argv=%s timeout=%ss", argv, timeout)
        completed = subprocess.run(  # noqa: S603 - argv list, shell=False by construction
            argv,
            shell=False,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("exec timed out after %ss argv=%s", timeout, argv)
        raise ExecutionError("timeout", f"Operation timed out after {timeout}s") from exc
    except FileNotFoundError as exc:
        raise ExecutionError("binary_missing", f"Executable not found: {argv[0]}") from exc
    except PermissionError as exc:
        raise ExecutionError("permission_denied", f"Cannot execute {argv[0]}") from exc
    finally:
        if acquired:
            _exec_lock.release()

    stdout = _decode(completed.stdout)
    stderr = _decode(completed.stderr)
    logger.info("exec rc=%s stdout=%dB stderr=%dB", completed.returncode, len(stdout), len(stderr))

    return ExecResult(
        returncode=completed.returncode, stdout=stdout, stderr=stderr, argv=list(argv)
    )


def _decode(raw: bytes | None) -> str:
    if not raw:
        return ""
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ExecutionError("output_too_large", "Command produced too much output")
    return raw.decode("utf-8", errors="replace")
