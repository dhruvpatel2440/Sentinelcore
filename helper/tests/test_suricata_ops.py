"""M4 helper op tests: checksum verification, path containment, rollback."""

from __future__ import annotations

import hashlib

import pytest

from helper.config import config
from helper.executor import ExecutionError
from helper.ops import OPS
from helper.ops import suricata as sops
from helper.validation import ValidationError

GOOD_RULES = b'alert tcp any any -> any 22 (msg:"test"; sid:1000001; rev:1;)\n'
OTHER_RULES = b'alert tcp any any -> any 80 (msg:"other"; sid:1000002; rev:1;)\n'


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    staging = tmp_path / "staging"
    rules = tmp_path / "rules"
    staging.mkdir()
    rules.mkdir()
    monkeypatch.setattr(config, "suricata_staging_dir", staging)
    monkeypatch.setattr(config, "suricata_rules_dir", rules)
    return staging, rules


def sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "op",
    [
        "suricata_status",
        "suricata_start",
        "suricata_stop",
        "suricata_reload_rules",
        "suricata_test_config",
        "suricata_write_rules",
    ],
)
def test_all_m4_ops_are_registered(op):
    assert op in OPS


def test_no_generic_command_op_exists():
    """There is no 'run anything' escape hatch, and there never should be."""
    forbidden = {"exec", "run", "shell", "command", "system", "eval"}
    assert forbidden.isdisjoint(OPS)


# --------------------------------------------------------------------------
# write_rules: filename and checksum
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename",
    ["../../etc/passwd", "/etc/suricata/x.rules", "sub/dir.rules", "x.rules.bak", ""],
)
def test_write_rules_rejects_bad_filenames(dirs, filename):
    with pytest.raises(ValidationError):
        sops.suricata_write_rules({"filename": filename, "content_sha256": sha(GOOD_RULES)})


def test_write_rules_rejects_bad_checksum_format(dirs):
    staging, _ = dirs
    (staging / "t.rules").write_bytes(GOOD_RULES)
    for bad in ["", "zz", "g" * 64, None, 12345]:
        with pytest.raises(ValidationError):
            sops.suricata_write_rules({"filename": "t.rules", "content_sha256": bad})


def test_write_rules_requires_the_staged_file_to_exist(dirs):
    with pytest.raises(ValidationError) as exc:
        sops.suricata_write_rules(
            {"filename": "missing.rules", "content_sha256": sha(GOOD_RULES)}
        )
    assert exc.value.code == "staged_missing"


def test_write_rules_rejects_checksum_mismatch(dirs):
    """The staged file changed between the backend writing it and us reading it."""
    staging, rules = dirs
    (staging / "t.rules").write_bytes(GOOD_RULES)

    with pytest.raises(ValidationError) as exc:
        sops.suricata_write_rules(
            {"filename": "t.rules", "content_sha256": sha(b"different content")}
        )
    assert exc.value.code == "checksum_mismatch"
    # Nothing was promoted.
    assert not (rules / "t.rules").exists()


# --------------------------------------------------------------------------
# Rollback
# --------------------------------------------------------------------------


def test_previous_ruleset_is_restored_when_validation_fails(dirs, monkeypatch):
    """The M4 definition-of-done case: a bad rule file must never go live."""
    staging, rules = dirs
    live = rules / "t.rules"
    live.write_bytes(OTHER_RULES)  # the known-good ruleset currently in place

    staging_file = staging / "t.rules"
    staging_file.write_bytes(GOOD_RULES)

    # Simulate `suricata -T` rejecting the composed ruleset.
    monkeypatch.setattr(
        sops, "_test_config", lambda **kw: {"valid": False, "output": "bad rule at line 1"}
    )

    with pytest.raises(ExecutionError) as exc:
        sops.suricata_write_rules(
            {"filename": "t.rules", "content_sha256": sha(GOOD_RULES)}
        )
    assert exc.value.code == "validation_failed"

    # The PREVIOUS ruleset is still live, byte for byte.
    assert live.read_bytes() == OTHER_RULES
    # And no backup litter is left behind.
    assert not (rules / "t.rules.bak").exists()


def test_new_file_is_removed_when_validation_fails_with_no_previous(dirs, monkeypatch):
    staging, rules = dirs
    (staging / "t.rules").write_bytes(GOOD_RULES)

    monkeypatch.setattr(sops, "_test_config", lambda **kw: {"valid": False, "output": "nope"})

    with pytest.raises(ExecutionError):
        sops.suricata_write_rules({"filename": "t.rules", "content_sha256": sha(GOOD_RULES)})

    # Nothing left behind — not an empty or broken ruleset.
    assert not (rules / "t.rules").exists()


def test_successful_write_promotes_the_staged_file(dirs, monkeypatch):
    staging, rules = dirs
    (staging / "t.rules").write_bytes(GOOD_RULES)

    monkeypatch.setattr(sops, "_test_config", lambda **kw: {"valid": True, "output": ""})

    result = sops.suricata_write_rules(
        {"filename": "t.rules", "content_sha256": sha(GOOD_RULES)}
    )

    assert result["written"] is True
    assert (rules / "t.rules").read_bytes() == GOOD_RULES
    # The staged copy is consumed, not left as a duplicate.
    assert not (staging / "t.rules").exists()
    assert result["rule_count"] >= 1


def test_reload_refuses_when_suricata_is_not_running(monkeypatch):
    monkeypatch.setattr(sops, "_read_pid", lambda: None)
    with pytest.raises(ExecutionError) as exc:
        sops.suricata_reload_rules({})
    assert exc.value.code == "not_running"


def test_status_reports_stopped_cleanly_when_not_running(monkeypatch):
    monkeypatch.setattr(sops, "_read_pid", lambda: None)
    monkeypatch.setattr(sops, "_version", lambda: "7.0.7")
    status = sops.suricata_status({})
    assert status["running"] is False
    assert status["pid"] is None


def test_write_rules_holds_the_lock_across_promote_and_validate(dirs, monkeypatch):
    """Regression: validation used to contend with the write that called it.

    `run()` acquires the execution semaphore, so if write_rules moved the file
    and *then* validated without already holding the lock, a concurrent op
    could fail the validation and roll back a good ruleset. The validation call
    must therefore be made with exclusive=False from inside the held lock.
    """
    from helper import executor

    staging, rules = dirs
    (staging / "t.rules").write_bytes(GOOD_RULES)

    seen: dict[str, object] = {}

    def fake_run(argv, *, timeout, exclusive=True):
        seen["exclusive"] = exclusive
        # The lock must already be held by write_rules at this point.
        seen["lock_free"] = executor._exec_lock.acquire(blocking=False)
        if seen["lock_free"]:
            executor._exec_lock.release()
        return executor.ExecResult(returncode=0, stdout="", stderr="", argv=list(argv))

    monkeypatch.setattr(sops, "run", fake_run)

    sops.suricata_write_rules({"filename": "t.rules", "content_sha256": sha(GOOD_RULES)})

    assert seen["exclusive"] is False, "validation must not try to re-acquire the semaphore"
    assert seen["lock_free"] is False, "write_rules must hold the lock during validation"


def test_concurrent_operation_is_refused_rather_than_corrupting(dirs, monkeypatch):
    """A second privileged op during a write is refused up front, before the
    live ruleset is touched at all."""
    from helper import executor

    staging, rules = dirs
    live = rules / "t.rules"
    live.write_bytes(OTHER_RULES)
    (staging / "t.rules").write_bytes(GOOD_RULES)

    executor._exec_lock.acquire()  # simulate another op in flight
    try:
        with pytest.raises(ExecutionError) as exc:
            sops.suricata_write_rules({"filename": "t.rules", "content_sha256": sha(GOOD_RULES)})
        assert exc.value.code == "helper_busy"
        # The live ruleset was never touched.
        assert live.read_bytes() == OTHER_RULES
        assert (staging / "t.rules").exists()
    finally:
        executor._exec_lock.release()


# --------------------------------------------------------------------------
# PID identity (regression: PID reuse made a stopped sensor look running)
# --------------------------------------------------------------------------


def test_stale_pidfile_with_reused_pid_is_not_reported_as_running(tmp_path, monkeypatch):
    """The real failure: after SIGKILL the pidfile survives, and the
    `suricata -V` subprocess that status itself spawns can land on that very
    PID. A bare kill(pid, 0) check then reports a stopped sensor as running."""
    pidfile = tmp_path / "suricata.pid"
    pidfile.write_text("4242")
    monkeypatch.setattr(config, "suricata_pid_file", pidfile)

    # PID 4242 exists, but it is a transient `suricata -V`, not the daemon.
    monkeypatch.setattr(sops, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        sops, "_pid_is_suricata_daemon", lambda pid: False
    )

    assert sops._read_pid() is None
    # The stale pidfile is cleaned up so the next check is a cheap miss.
    assert not pidfile.exists()


def test_live_daemon_pid_is_reported(tmp_path, monkeypatch):
    pidfile = tmp_path / "suricata.pid"
    pidfile.write_text("777")
    monkeypatch.setattr(config, "suricata_pid_file", pidfile)
    monkeypatch.setattr(sops, "_pid_is_suricata_daemon", lambda pid: pid == 777)

    assert sops._read_pid() == 777
    assert pidfile.exists()


def test_missing_pidfile_means_stopped(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "suricata_pid_file", tmp_path / "nope.pid")
    assert sops._read_pid() is None


def test_garbage_pidfile_means_stopped(tmp_path, monkeypatch):
    pidfile = tmp_path / "suricata.pid"
    pidfile.write_text("not-a-number")
    monkeypatch.setattr(config, "suricata_pid_file", pidfile)
    assert sops._read_pid() is None


def test_daemon_identity_rejects_oneshot_invocations(monkeypatch, tmp_path):
    """`suricata -V` and `suricata -T` must never count as the running sensor."""
    import helper.ops.suricata as m

    proc = tmp_path / "proc"
    proc.mkdir()

    def make(pid: int, argv: list[bytes]) -> None:
        d = proc / str(pid)
        d.mkdir()
        (d / "cmdline").write_bytes(b"\0".join(argv) + b"\0")

    make(1, [b"/usr/bin/suricata", b"-c", b"/etc/suricata/suricata.yaml", b"-i", b"eth0"])
    make(2, [b"/usr/bin/suricata", b"-V"])
    make(3, [b"/usr/bin/suricata", b"-T", b"-c", b"/etc/suricata/suricata.yaml"])
    make(4, [b"/usr/bin/python3", b"-m", b"helper.server"])

    monkeypatch.setattr(m, "Path", lambda p: proc / str(p).replace("/proc/", ""))

    assert m._pid_is_suricata_daemon(1) is True, "the capture daemon"
    assert m._pid_is_suricata_daemon(2) is False, "suricata -V is transient"
    assert m._pid_is_suricata_daemon(3) is False, "suricata -T is transient"
    assert m._pid_is_suricata_daemon(4) is False, "not suricata at all"
    assert m._pid_is_suricata_daemon(999) is False, "no such pid"
