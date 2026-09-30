"""U03 CI/unit guard: enforces the subprocess rule in CLAUDE.md.

  * `subprocess`, `os.system(`, `os.popen(`, `create_subprocess_*` may only
    appear under `backend/app/` inside `backend/app/pcap/parser.py`.
  * `shell=True` must never appear anywhere in the repo.

The second check needs the full repository checked out to mean anything —
inside the backend Docker image only `backend/` exists, so when this test
runs there it can only see `backend/`. In CI (`pytest backend` against a
full `git checkout`, see `.github/workflows/ci.yml`) it covers the whole
tree, including `helper/`, `privileged-helper/`, `frontend/`, `docker/`.
Either way the guard degrades to "covers what's on disk", never to "skipped".
"""

from __future__ import annotations

from pathlib import Path

import pytest

_SUBPROCESS_MARKERS = ("subprocess", "os.system(", "os.popen(", "create_subprocess_exec", "create_subprocess_shell")

_ALLOWED_SUBPROCESS_FILE = Path("app/pcap/parser.py")

# Directories that legitimately talk about the rule without breaking it, or
# that are not our code to police.
_EXCLUDE_DIR_PARTS = {
    ".git", "node_modules", "__pycache__", ".pytest_cache", "venv", ".venv",
    "updates", "Modules", "dist", "build",
}


def _repo_root() -> Path:
    """Walk up from this file looking for a `.git` directory (a full repo
    checkout, e.g. in CI). Inside the backend Docker image there is no
    `.git` — only `backend/` was copied in (see backend/Dockerfile) — so
    fall back to the backend directory itself rather than walking into the
    container's root filesystem."""
    backend_root = Path(__file__).resolve().parents[1]
    for candidate in (backend_root, *backend_root.parents):
        if (candidate / ".git").is_dir():
            return candidate
    return backend_root


def _backend_app_root() -> Path:
    return Path(__file__).resolve().parents[1] / "app"


def _iter_py_files(root: Path):
    for path in root.rglob("*.py"):
        if any(part in _EXCLUDE_DIR_PARTS for part in path.parts):
            continue
        yield path


def test_subprocess_only_used_in_pcap_parser():
    app_root = _backend_app_root()
    violations: list[str] = []
    for path in _iter_py_files(app_root):
        relative = path.relative_to(app_root.parent)
        if relative == _ALLOWED_SUBPROCESS_FILE:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for marker in _SUBPROCESS_MARKERS:
            if marker in text:
                violations.append(f"{relative}: contains {marker!r}")
    assert not violations, (
        "subprocess use found outside the one permitted file "
        f"(backend/{_ALLOWED_SUBPROCESS_FILE}): {violations}"
    )


def test_no_shell_true_anywhere_on_disk():
    root = _repo_root()
    violations: list[str] = []
    for path in _iter_py_files(root):
        # This file and the invariant-check script legitimately quote the
        # string "shell=True" while describing/testing the rule itself.
        if path.name in ("test_no_subprocess.py", "e2e_test.py"):
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if "shell=True" in text:
            violations.append(str(path.relative_to(root)))
    assert not violations, f"shell=True found in: {violations}"


def test_pcap_parser_subprocess_calls_are_hardened():
    """Belt-and-braces: the one file allowed to use subprocess must still
    follow the argv-list-only, no-shell, hardened-callsite pattern."""
    parser_path = _backend_app_root() / "pcap" / "parser.py"
    text = parser_path.read_text()
    assert "shell=True" not in text
    assert "create_subprocess_exec" in text
    assert "create_subprocess_shell" not in text
    # Every callsite must pass -n (no name resolution) and a resource guard.
    assert text.count("create_subprocess_exec") == text.count("preexec_fn=_limit_resources")
    assert '"-n"' in text or "'-n'" in text
