"""Paths, logging and the one subprocess helper every module uses.

Rules (mirrors CLAUDE.md): every external command is an argv list; there is no
shell invocation anywhere in this package; nothing user-supplied is ever
concatenated into a command string.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from . import __version__

# SENTINELCORE_PREFIX re-roots every path (used by the unit tests and for
# staging a package build). Empty in production.
PREFIX = os.environ.get("SENTINELCORE_PREFIX", "")


def _p(path: str) -> Path:
    return Path(PREFIX + path) if PREFIX else Path(path)


ETC_DIR = _p("/etc/sentinelcore")
ENV_FILE = ETC_DIR / "sentinelcore.env"
PROFILE_FILE = ETC_DIR / "install-profile.yaml"
TLS_DIR = ETC_DIR / "tls"
TLS_CERT = TLS_DIR / "sentinelcore.crt"
TLS_KEY = TLS_DIR / "sentinelcore.key"

OPT_DIR = _p("/opt/sentinelcore")
COMPOSE_FILE = OPT_DIR / "docker-compose.release.yml"
RELEASE_ENV = OPT_DIR / "release.env"
IMAGES_MANIFEST = OPT_DIR / "images.json"
NGINX_CONF = OPT_DIR / "nginx" / "nginx.release.conf"
SURICATA_CONF = OPT_DIR / "suricata" / "suricata.yaml"
STATE_DIR = _p("/var/lib/sentinelcore")
ROLLBACK_DIR = STATE_DIR / "rollback"
DEFAULT_DATA_DIR = _p("/var/lib/sentinelcore/data")
INSTALL_LOG = _p("/var/log/sentinelcore-install.log")
SYSTEMD_UNIT = _p("/etc/systemd/system/sentinelcore.service")
DESKTOP_FILE = _p("/usr/share/applications/sentinelcore.desktop")

COMPOSE_PROJECT = "sentinelcore"
GROUP_NAME = "sentinelcore"
DEFAULT_UPDATE_URL = os.environ.get(
    "SENTINELCORE_UPDATE_URL",
    "https://github.com/dhruvpatel2440/sentinelcore-releases/releases/latest/download",
)

log = logging.getLogger("sentinelcore")


def share_dir() -> Path:
    """Where packaged static assets live (compose file, nginx conf, EULA...)."""
    candidates = [
        os.environ.get("SENTINELCORE_SHARE", ""),
        str(_p("/usr/share/sentinelcore")),
        # Running from a source checkout: installer/ lives next to packaging/.
        str(Path(__file__).resolve().parents[2] / "packaging"),
    ]
    for cand in candidates:
        if cand and Path(cand).is_dir():
            return Path(cand)
    return Path(candidates[1])


def find_asset(*names: str) -> Path | None:
    """First existing asset among names, searched in the share dir and the repo."""
    roots = [share_dir(), Path(__file__).resolve().parents[2]]
    for root in roots:
        for name in names:
            cand = root / name
            if cand.exists():
                return cand
    return None


def current_version() -> str:
    path = share_dir() / "VERSION"
    try:
        text = path.read_text(encoding="utf-8").strip()
        if text:
            return text
    except OSError:
        pass
    return __version__


class CommandError(RuntimeError):
    def __init__(self, argv: Sequence[str], returncode: int, output: str):
        super().__init__(f"command failed ({returncode}): {' '.join(argv[:4])} ...")
        self.argv = list(argv)
        self.returncode = returncode
        self.output = output


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str


def run(
    argv: Sequence[str],
    *,
    check: bool = True,
    input_text: str | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    stdout=None,
    cwd: str | os.PathLike | None = None,
) -> Result:
    """Run an external command from an argv list. Never uses a shell.

    The argv is logged; callers must therefore never put a secret in argv
    (pass it via ``input_text`` or ``env`` instead).
    """
    if isinstance(argv, str) or not all(isinstance(a, str) for a in argv):
        raise TypeError("run() requires an argv list of strings")
    log.debug("exec: %s", " ".join(argv))
    full_env = None
    if env is not None:
        full_env = {**os.environ, **env}
    try:
        proc = subprocess.run(
            list(argv),
            input=input_text,
            text=True,
            stdout=stdout if stdout is not None else subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=full_env,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except FileNotFoundError as exc:
        if check:
            raise CommandError(argv, 127, f"not found: {argv[0]}") from exc
        return Result(127, "", f"not found: {argv[0]}")
    except subprocess.TimeoutExpired as exc:
        if check:
            raise CommandError(argv, 124, "timed out") from exc
        return Result(124, "", "timed out")
    out = proc.stdout if isinstance(proc.stdout, str) else ""
    res = Result(proc.returncode, out or "", proc.stderr or "")
    if check and proc.returncode != 0:
        raise CommandError(argv, proc.returncode, (res.stderr or res.stdout)[-2000:])
    return res


def setup_logging(verbose: bool = False, to_file: bool = True) -> None:
    root = logging.getLogger("sentinelcore")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    if to_file:
        try:
            INSTALL_LOG.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(INSTALL_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            handler = logging.StreamHandler(os.fdopen(fd, "a", encoding="utf-8"))
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            handler.setLevel(logging.DEBUG)
            root.addHandler(handler)
        except OSError:
            pass  # not root / read-only fs: console output still works
    if verbose:
        console = logging.StreamHandler(sys.stderr)
        console.setLevel(logging.DEBUG)
        root.addHandler(console)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def compose_argv(*args: str) -> list[str]:
    """Base docker compose argv for the installed stack."""
    return [
        "docker", "compose", "-p", COMPOSE_PROJECT,
        "--env-file", str(ENV_FILE),
        "--env-file", str(RELEASE_ENV),
        "-f", str(COMPOSE_FILE),
        *args,
    ]
