"""Turns wizard answers into the two generated files.

* ``sentinelcore.env``  -- every variable the stack needs, secrets included, 0600.
* ``install-profile.json`` -- the answers WITHOUT any secret. This is the
  reusable "customized install package".
"""

from __future__ import annotations

import json
import os
import secrets
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import miniyaml
from . import validators as v
from .common import current_version, is_root

PROFILE_SCHEMA = 1

SECRET_ENV_KEYS = frozenset(
    {"POSTGRES_PASSWORD", "SECRET_KEY", "SEED_ADMIN_PASSWORD", "BREVO_API_KEY", "BREVO_WEBHOOK_SECRET"}
)


@dataclass
class Answers:
    install_type: str = "quick"  # quick | custom
    listen_address: str = "127.0.0.1"
    http_port: int = 80
    https_port: int = 443
    data_dir: str = "/var/lib/sentinelcore/data"
    capture_interface: str = ""
    monitored_network: str = ""
    protected_ips: list[str] = field(default_factory=list)
    admin_username: str = "admin"
    admin_email: str = ""
    admin_password_mode: str = "prompt"  # prompt | generate
    suricata_rules_update: bool = True
    event_retention_days: int = 90
    host_name: str = field(default_factory=socket.gethostname)

    # Never serialised into the profile:
    admin_password: str = field(default="", repr=False)

    def validate(self) -> None:
        self.listen_address = v.validate_listen_address(self.listen_address)
        self.http_port, self.https_port = v.validate_port_pair(self.http_port, self.https_port)
        self.data_dir = v.validate_data_dir(self.data_dir)
        self.capture_interface = v.validate_interface_name(self.capture_interface)
        self.monitored_network = v.validate_cidr(self.monitored_network)
        self.protected_ips = v.validate_protected_ips(self.protected_ips)
        self.admin_username = v.validate_username(self.admin_username)
        self.admin_email = v.validate_email(self.admin_email)
        self.event_retention_days = v.validate_retention_days(self.event_retention_days)
        self.host_name = v.validate_hostname(self.host_name)
        if self.admin_password_mode not in {"prompt", "generate"}:
            raise v.ValidationError("admin password mode must be 'prompt' or 'generate'")
        if self.install_type not in {"quick", "custom"}:
            raise v.ValidationError("install type must be 'quick' or 'custom'")

    # -- derived -----------------------------------------------------------
    @property
    def connect_host(self) -> str:
        """Address this machine itself uses to reach its own dashboard."""
        return "127.0.0.1" if self.listen_address == "0.0.0.0" else self.listen_address

    @property
    def public_https_suffix(self) -> str:
        return "" if self.https_port == 443 else f":{self.https_port}"

    @property
    def dashboard_url(self) -> str:
        host = "localhost" if self.listen_address in {"127.0.0.1", "0.0.0.0"} else self.listen_address
        return f"https://{host}{self.public_https_suffix}"


def generate_password(length: int = 24) -> str:
    alphabet = (
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789" "!@#%^&*-_=+"
    )
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        try:
            return v.validate_password(pw)
        except v.ValidationError:
            continue


def parse_env(text: str) -> dict[str, str]:
    """Parse files written by render_env (KEY='value' lines)."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] == "'":
            val = val[1:-1]
        out[key.strip()] = val
    return out


def load_env(path: Path) -> dict[str, str]:
    try:
        return parse_env(path.read_text(encoding="utf-8"))
    except OSError:
        return {}


def build_env(answers: Answers, existing: dict[str, str] | None = None) -> dict[str, str]:
    """All variables for sentinelcore.env.

    On a re-run, secrets that already protect live data (database password,
    JWT key) are kept; changing them would lock the stack out of its own data.
    """
    existing = existing or {}
    admin_pw = answers.admin_password or existing.get("SEED_ADMIN_PASSWORD", "")
    env: dict[str, str] = {
        "POSTGRES_USER": existing.get("POSTGRES_USER", "sentinelcore"),
        "POSTGRES_PASSWORD": existing.get("POSTGRES_PASSWORD") or secrets.token_urlsafe(24),
        "POSTGRES_DB": existing.get("POSTGRES_DB", "sentinelcore"),
        "SECRET_KEY": existing.get("SECRET_KEY") or secrets.token_hex(32),
        "ACCESS_TOKEN_EXPIRE_MINUTES": "15",
        "REFRESH_TOKEN_EXPIRE_DAYS": "7",
        "LOGIN_MAX_ATTEMPTS": "5",
        "LOGIN_LOCKOUT_SECONDS": "300",
        "SEED_ADMIN_USERNAME": answers.admin_username,
        "CAPTURE_INTERFACE": answers.capture_interface,
        "MONITORED_NETWORK": answers.monitored_network,
        "PROTECTED_IPS": ",".join(answers.protected_ips),
        "SURICATA_EVE_LOG": "/var/log/suricata/eve.json",
        "EVENT_RETENTION_DAYS": str(answers.event_retention_days),
        "ENVIRONMENT": "production",
        "EMAIL_MODE": existing.get("EMAIL_MODE", "off"),
        "APP_BASE_URL": answers.dashboard_url,
        # Deployment settings consumed by docker-compose.release.yml:
        "LISTEN_ADDRESS": answers.listen_address,
        "HTTP_PORT": str(answers.http_port),
        "HTTPS_PORT": str(answers.https_port),
        "PUBLIC_HTTPS_SUFFIX": answers.public_https_suffix,
        "HSTS_MAX_AGE": existing.get("HSTS_MAX_AGE", "300"),
        "SENTINELCORE_DATA_DIR": answers.data_dir,
    }
    if admin_pw:
        env["SEED_ADMIN_PASSWORD"] = admin_pw
    if answers.admin_email:
        env["SEED_ADMIN_EMAIL"] = answers.admin_email
    return env


def render_env(env: dict[str, str]) -> str:
    lines = [
        "# Generated by sentinelcore-installer. Contains secrets: mode 0600, root only.",
        "# Edit with care, then run: sudo sentinelcore restart",
    ]
    for key, val in env.items():
        if "\n" in val or "\r" in val or "'" in val:
            raise v.ValidationError(f"{key} contains characters that cannot be stored safely")
        lines.append(f"{key}='{val}'")
    return "\n".join(lines) + "\n"


def write_private_file(path: Path, content: str, mode: int = 0o600) -> None:
    """Atomic write with restrictive permissions from the first byte."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(tmp, mode)
        if is_root():
            os.chown(tmp, 0, 0)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def build_profile(answers: Answers) -> dict:
    return {
        "schema": PROFILE_SCHEMA,
        "version": current_version(),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host_name": answers.host_name,
        "install_type": answers.install_type,
        "access": {
            "listen_address": answers.listen_address,
            "http_port": answers.http_port,
            "https_port": answers.https_port,
            "data_dir": answers.data_dir,
        },
        "network": {
            "capture_interface": answers.capture_interface,
            "monitored_network": answers.monitored_network,
            "protected_ips": answers.protected_ips,
        },
        "admin": {
            "username": answers.admin_username,
            "email": answers.admin_email,
            # How the password is supplied on a replay. The password is never stored.
            "password_source": answers.admin_password_mode,
        },
        "options": {
            "suricata_rules_update": answers.suricata_rules_update,
            "event_retention_days": answers.event_retention_days,
        },
    }


def dump_yaml(data: dict) -> str:
    return miniyaml.dump(data)


def parse_yaml(text: str) -> dict:
    return miniyaml.load(text)


def write_profile(path: Path, answers: Answers) -> None:
    header = "# SentinelCore install profile. Contains NO secrets; safe to copy to another machine.\n"
    write_private_file(path, header + miniyaml.dump(build_profile(answers)), mode=0o644)


def answers_from_profile(profile: dict) -> Answers:
    try:
        access, net, admin, opts = (
            profile["access"], profile["network"], profile["admin"], profile.get("options", {}),
        )
        answers = Answers(
            install_type=profile.get("install_type", "custom"),
            listen_address=access["listen_address"],
            http_port=access["http_port"],
            https_port=access["https_port"],
            data_dir=access["data_dir"],
            capture_interface=net["capture_interface"],
            monitored_network=net["monitored_network"],
            protected_ips=list(net["protected_ips"]),
            admin_username=admin["username"],
            admin_email=admin.get("email", ""),
            admin_password_mode=admin.get("password_source", "prompt"),
            suricata_rules_update=bool(opts.get("suricata_rules_update", True)),
            event_retention_days=int(opts.get("event_retention_days", 90)),
            host_name=socket.gethostname(),  # per machine, never copied across
        )
    except (KeyError, TypeError) as exc:
        raise v.ValidationError(f"install profile is incomplete or malformed: {exc}") from exc
    answers.validate()
    return answers


def load_profile(path: Path) -> Answers:
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text) if text.lstrip().startswith("{") else parse_yaml(text)
    except (OSError, json.JSONDecodeError) as exc:
        raise v.ValidationError(f"cannot read profile {path}: {exc}") from exc
    if isinstance(data, dict) and any(k.lower().endswith(("password", "secret")) for k in data):
        raise v.ValidationError("profile must not contain secrets")
    return answers_from_profile(data)


def profile_as_dict(answers: Answers) -> dict:
    d = asdict(answers)
    d.pop("admin_password", None)
    return d
