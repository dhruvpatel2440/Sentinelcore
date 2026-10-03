"""The automatic installation phase.

Idempotent by construction: every phase can run again on a half-installed or
fully installed system and converges to the same state. On failure the stack
this run started is stopped (never deleted) and config files are left in
place for debugging.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import configgen, netinfo, signing
from .common import (
    COMPOSE_FILE, DESKTOP_FILE, ENV_FILE, GROUP_NAME, IMAGES_MANIFEST, INSTALL_LOG,
    NGINX_CONF, OPT_DIR, PROFILE_FILE, RELEASE_ENV, STATE_DIR, SURICATA_CONF,
    SYSTEMD_UNIT, TLS_CERT, TLS_DIR, TLS_KEY, CommandError, compose_argv,
    current_version, find_asset, is_root, log, run,
)
from .configgen import Answers
from .ui import UI


class InstallError(RuntimeError):
    def __init__(self, phase: str, message: str, hint: str = ""):
        super().__init__(message)
        self.phase, self.hint = phase, hint


# --------------------------------------------------------------------------
# Image manifest handling
# --------------------------------------------------------------------------
def load_manifest(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        images = data["images"]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise InstallError("images", f"image manifest {path} is unreadable: {exc}") from exc
    return data if isinstance(images, dict) else {}


def assert_release_manifest(manifest: dict) -> None:
    """Refuse a manifest that is not a real published release.

    A real release pins every image by sha256 digest and has a real version.
    The checked-in packaging/images.json is a development placeholder; installing
    from it would fail later with a confusing pull error, so stop here instead.
    Set SENTINELCORE_ALLOW_UNPINNED=1 only for local development with locally built images.
    """
    if os.environ.get("SENTINELCORE_ALLOW_UNPINNED") == "1":
        return
    problems = []
    if str(manifest.get("version", "0.0.0")).startswith("0.0.0"):
        problems.append("version is 0.0.0")
    for var, spec in manifest.get("images", {}).items():
        digest = spec.get("digest") or ""
        if not (digest.startswith("sha256:") and len(digest) == 71):
            problems.append(f"{var} has no sha256 digest")
        if "OWNER" in spec.get("ref", ""):
            problems.append(f"{var} still references OWNER")
    if problems:
        raise InstallError(
            "images",
            "this package does not contain a published release (" + "; ".join(problems[:3]) + ")",
            "Download a released installer from the SentinelCore website. Preview or source-tree "
            "packages cannot install the application.",
        )


def image_refs(manifest: dict, *, use_digest: bool = True) -> dict[str, str]:
    """{ENV_VAR: reference}. With a digest the reference is pinned: name:tag@sha256:..."""
    refs: dict[str, str] = {}
    for var, spec in manifest["images"].items():
        ref, digest = spec["ref"], spec.get("digest")
        refs[var] = f"{ref}@{digest}" if (use_digest and digest) else ref
    return refs


def render_release_env(refs: dict[str, str]) -> str:
    lines = ["# Image references (tag@digest). Rewritten by install/update. Not secret."]
    lines += [f"{k}={v}" for k, v in refs.items()]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Compose / HTTP helpers shared with the CLI
# --------------------------------------------------------------------------
def compose_ps() -> list[dict]:
    """Container list for the project; copes with both JSON array and NDJSON output."""
    res = run(compose_argv("ps", "--all", "--format", "json"), check=False, timeout=60)
    text = res.stdout.strip()
    if res.returncode != 0 or not text:
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]


def unhealthy_services(rows: list[dict]) -> list[str]:
    bad = []
    for row in rows:
        state, health = row.get("State", ""), row.get("Health", "")
        if state != "running" or health not in ("", "healthy"):
            bad.append(f"{row.get('Service', row.get('Name', '?'))} ({state}{'/' + health if health else ''})")
    return bad


class Api:
    """Tiny HTTPS client for the local dashboard API, trusting only our own certificate."""

    def __init__(self, host: str, port: int, cafile: Path = TLS_CERT):
        self.host, self.port = host, port
        self.ctx = ssl.create_default_context(cafile=str(cafile)) if cafile.exists() else ssl.create_default_context()

    def request(self, method: str, path: str, body: dict | None = None, token: str | None = None,
                timeout: float = 20.0) -> tuple[int, object]:
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=timeout)
        headers = {"Accept": "application/json"}
        payload = None
        if body is not None:
            payload = json.dumps(body)
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", "replace")
        finally:
            conn.close()
        try:
            return resp.status, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return resp.status, raw

    def login(self, username: str, password: str) -> str | None:
        try:
            status, data = self.request("POST", "/api/auth/login", {"username": username, "password": password})
        except (OSError, ssl.SSLError, http.client.HTTPException):
            return None
        if status == 200 and isinstance(data, dict):
            return data.get("access_token")
        return None


def wait_for(predicate: Callable[[], bool], timeout: float, interval: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except (OSError, ssl.SSLError, http.client.HTTPException, CommandError):
            pass
        time.sleep(interval)
    return False


# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------
def san_entries(answers: Answers, interfaces) -> list[str]:
    dns = ["localhost", answers.host_name]
    ips = ["127.0.0.1"]
    for ip in [*netinfo.host_addresses(interfaces), answers.listen_address]:
        if ip not in ips and ip != "0.0.0.0":
            ips.append(ip)
    return [f"DNS:{d}" for d in dict.fromkeys(dns)] + [f"IP:{i}" for i in ips]


def generate_certificate(answers: Answers, interfaces) -> bool:
    """Create a self-signed certificate unless a current one already covers the SANs."""
    sans = san_entries(answers, interfaces)
    marker = TLS_DIR / "san.txt"
    if TLS_CERT.exists() and TLS_KEY.exists() and marker.exists() and marker.read_text().split() == sans:
        return False
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(TLS_DIR, 0o750)
    old = os.umask(0o077)  # the private key must never exist with looser bits
    try:
        run([
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes", "-days", "825",
            "-keyout", str(TLS_KEY), "-out", str(TLS_CERT),
            "-subj", f"/O=SentinelCore/CN={answers.host_name}",
            "-addext", "subjectAltName=" + ",".join(sans),
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext", "extendedKeyUsage=serverAuth",
        ])
    finally:
        os.umask(old)
    os.chmod(TLS_KEY, 0o600)
    os.chmod(TLS_CERT, 0o644)
    marker.write_text("\n".join(sans) + "\n", encoding="utf-8")
    return True


# --------------------------------------------------------------------------
# The installer
# --------------------------------------------------------------------------
@dataclass
class Outcome:
    ok: bool
    failed_phase: str = ""
    message: str = ""
    hint: str = ""
    checks: list[tuple[str, bool, str]] | None = None


class Installer:
    def __init__(self, ui: UI, answers: Answers, *, offline_bundle: Path | None = None,
                 skip_images: bool = False):
        self.ui, self.a = ui, answers
        self.offline = offline_bundle
        self.skip_images = skip_images
        self.interfaces = netinfo.list_interfaces()
        self.api = Api(answers.connect_host, answers.https_port)
        self.we_started_stack = False
        self.phases: list[tuple[str, Callable[[], str | None]]] = [
            ("Preparing directories and system group", self.phase_dirs),
            ("Writing configuration", self.phase_config),
            ("Generating the TLS certificate", self.phase_tls),
            ("Installing application files", self.phase_files),
            ("Loading container images", self.phase_images),
            ("Starting the stack", self.phase_start),
            ("Waiting for services to become healthy", self.phase_health),
            ("Applying database migrations and admin account", self.phase_migrate),
            ("Starting the Suricata sensor", self.phase_sensor),
            ("Enabling start at boot and the desktop launcher", self.phase_service),
        ]

    # -- driver ------------------------------------------------------------
    def run(self) -> Outcome:
        total = len(self.phases) + 1
        for i, (label, fn) in enumerate(self.phases, 1):
            self.ui.step(i, total, label)
            log.info("phase %d/%d: %s", i, total, label)
            try:
                detail = fn() or ""
            except InstallError as exc:
                self.ui.step_done(label, False, str(exc))
                log.error("phase failed: %s: %s", label, exc)
                return self._rollback(label, str(exc), exc.hint)
            except (CommandError, OSError) as exc:
                msg = getattr(exc, "output", "") or str(exc)
                self.ui.step_done(label, False, msg.strip().splitlines()[-1] if msg.strip() else "error")
                log.error("phase failed: %s: %s", label, msg)
                return self._rollback(label, msg.strip()[-600:], "See " + str(INSTALL_LOG))
            self.ui.step_done(label, True, detail)
        self.ui.step(total, total, "Final verification")
        checks = self.verify()
        failed = [c for c in checks if not c[1]]
        self.ui.step_done("Final verification", not failed, "; ".join(f"{n}: {d}" for n, ok, d in failed))
        if failed:
            return Outcome(False, "Final verification", "Some checks failed.",
                           "Run: sudo sentinelcore doctor", checks)
        self.scrub_seed_password()
        return Outcome(True, checks=checks)

    def _rollback(self, phase: str, message: str, hint: str) -> Outcome:
        if self.we_started_stack:
            self.ui.info("Rolling back: stopping the services this run started (data and config are kept).")
            run(compose_argv("down", "--remove-orphans"), check=False, timeout=180)
        return Outcome(False, phase, message, hint or f"Config files were left in place. Log: {INSTALL_LOG}")

    # -- phases ------------------------------------------------------------
    def phase_dirs(self) -> str:
        for d, mode in [(OPT_DIR, 0o755), (OPT_DIR / "nginx", 0o755), (OPT_DIR / "suricata", 0o755),
                        (STATE_DIR, 0o750), (Path(self.a.data_dir), 0o750),
                        (Path(self.a.data_dir) / "backups", 0o750), (ENV_FILE.parent, 0o750)]:
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, mode)
        if run(["getent", "group", GROUP_NAME], check=False).returncode != 0:
            run(["groupadd", "--system", GROUP_NAME])
        return ""

    def phase_config(self) -> str:
        write_config(self.a)
        return str(ENV_FILE)

    def phase_tls(self) -> str:
        created = generate_certificate(self.a, self.interfaces)
        return "created" if created else "kept existing"

    def phase_files(self) -> str:
        deploy_files(self.offline)
        return ""

    def phase_images(self) -> str:
        if self.skip_images:
            return "skipped"
        if self.offline:
            return self._load_offline()
        run(compose_argv("pull", "--quiet"), timeout=3600)
        manifest = load_manifest(IMAGES_MANIFEST)
        unpinned = []
        for var, spec in manifest["images"].items():
            digest = spec.get("digest")
            if not digest:
                unpinned.append(var)
                continue
            res = run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", spec["ref"]], check=False)
            if digest not in res.stdout:
                raise InstallError("images", f"digest mismatch for {spec['ref']}: expected {digest}",
                                   "Do not continue: the image does not match the signed release.")
        return "digests verified" + (f" ({len(unpinned)} unpinned)" if unpinned else "")

    def _load_offline(self) -> str:
        assert self.offline is not None
        sums_file = self.offline / "SHA256SUMS"
        sig = self.offline / "SHA256SUMS.asc"
        if not sums_file.exists() or not sig.exists():
            raise InstallError("images", "offline bundle is missing SHA256SUMS or its signature")
        try:
            signing.verify_detached(sums_file, sig)
            sums = signing.parse_sha256sums(sums_file.read_text(encoding="utf-8"))
        except signing.SignatureError as exc:
            raise InstallError("images", str(exc), "Re-download the offline bundle.") from exc
        tars = sorted((self.offline / "images").glob("*.tar"))
        if not tars:
            raise InstallError("images", "offline bundle contains no images")
        for tar in tars:
            try:
                signing.verify_checksum(tar, sums, f"images/{tar.name}")
            except signing.SignatureError as exc:
                raise InstallError("images", str(exc)) from exc
            run(["docker", "load", "-i", str(tar)], timeout=1800)
        return f"{len(tars)} image archives verified and loaded"

    def phase_start(self) -> str:
        was_running = bool(compose_ps())
        run(compose_argv("up", "-d", "--remove-orphans"), timeout=900)
        self.we_started_stack = not was_running
        return "already running, updated" if was_running else ""

    def phase_health(self) -> str:
        def healthy() -> bool:
            return not unhealthy_services(compose_ps())

        if not wait_for(healthy, timeout=420, interval=5):
            bad = ", ".join(unhealthy_services(compose_ps())) or "no containers found"
            raise InstallError("health", f"services did not become healthy: {bad}",
                               "Check: sudo sentinelcore logs <service>")
        return ""

    def phase_migrate(self) -> str:
        # The backend entrypoint already migrates and seeds on boot. Running both
        # again is idempotent and makes the outcome explicit in the log.
        run(compose_argv("exec", "-T", "backend", "alembic", "upgrade", "head"), timeout=300)
        seed = run(compose_argv("exec", "-T", "backend", "python", "-m", "scripts.seed_admin"), timeout=120)
        if "already exists" in seed.stdout:
            return "admin already existed"
        return "admin created"

    def phase_sensor(self) -> str:
        token = self._admin_token()
        if token is None:
            raise InstallError(
                "sensor", "could not sign in as the administrator",
                "If this is a re-install with a different password, reset it from the dashboard or "
                "with the original one.",
            )
        notes = []
        if self.a.suricata_rules_update:
            status, _ = self.api.request("POST", "/api/sensor/rules/update", token=token)
            notes.append("rules update started" if status == 202 else "rules update skipped")
        status, data = self.api.request("POST", "/api/sensor/start", token=token, timeout=150)
        if status not in (200, 409):
            raise InstallError("sensor", f"sensor start failed (HTTP {status}): {str(data)[:200]}",
                               "Run: sudo sentinelcore doctor")
        return ", ".join(notes)

    def _admin_token(self) -> str | None:
        pw = self.a.admin_password or configgen.load_env(ENV_FILE).get("SEED_ADMIN_PASSWORD", "")
        if not pw:
            return None
        ok: dict[str, str] = {}

        def try_login() -> bool:
            token = self.api.login(self.a.admin_username, pw)
            if token:
                ok["t"] = token
            return bool(token)

        wait_for(try_login, timeout=60, interval=3)
        return ok.get("t")

    def phase_service(self) -> str:
        unit = find_asset("systemd/sentinelcore.service", "packaging/systemd/sentinelcore.service")
        notes = []
        if unit and shutil.which("systemctl"):
            SYSTEMD_UNIT.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(unit, SYSTEMD_UNIT)
            os.chmod(SYSTEMD_UNIT, 0o644)
            run(["systemctl", "daemon-reload"], check=False)
            run(["systemctl", "enable", "sentinelcore.service"], check=False)
            notes.append("systemd service enabled")
        else:
            notes.append("systemd not found: start manually with 'sentinelcore start'")
        write_desktop_launcher(self.a.dashboard_url)
        notes.append("desktop launcher installed")
        return ", ".join(notes)

    # -- verification ------------------------------------------------------
    def verify(self) -> list[tuple[str, bool, str]]:
        checks: list[tuple[str, bool, str]] = []

        def add(name: str, ok: bool, detail: str = "") -> None:
            checks.append((name, ok, detail))

        try:
            status, _ = self.api.request("GET", "/api/health")
            add("API health", status == 200, f"HTTP {status}")
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            add("API health", False, type(exc).__name__)
        try:
            status, _ = self.api.request("GET", "/")
            add("HTTPS answers", status == 200, f"HTTP {status}")
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            add("HTTPS answers", False, type(exc).__name__)
        bad = unhealthy_services(compose_ps())
        add("Containers healthy", not bad, ", ".join(bad))
        ps = run(compose_argv("exec", "-T", "helper", "pgrep", "-a", "suricata"), check=False, timeout=30)
        add("Suricata on " + self.a.capture_interface,
            ps.returncode == 0 and self.a.capture_interface in ps.stdout,
            "" if ps.returncode == 0 else "no Suricata process")
        add("Admin login", self._admin_token() is not None, "")
        return checks

    def scrub_seed_password(self) -> None:
        """Once the admin exists and login is proven, stop keeping its password on disk."""
        env = configgen.load_env(ENV_FILE)
        if "SEED_ADMIN_PASSWORD" in env:
            del env["SEED_ADMIN_PASSWORD"]
            configgen.write_private_file(ENV_FILE, configgen.render_env(env))


def deploy_files(offline: Path | None = None) -> None:
    """Copy compose/nginx/suricata/manifest into /opt/sentinelcore and pin image refs."""
    sources = {
        COMPOSE_FILE: find_asset("docker-compose.release.yml", "packaging/docker-compose.release.yml"),
        NGINX_CONF: find_asset("nginx/nginx.release.conf", "packaging/nginx/nginx.release.conf"),
        SURICATA_CONF: find_asset("suricata/suricata.yaml", "docker/suricata/suricata.yaml"),
        IMAGES_MANIFEST: (offline / "images.json") if offline else
        find_asset("images.json", "packaging/images.json"),
    }
    for dest, src in sources.items():
        if src is None or not Path(src).exists():
            raise InstallError("files", f"package file missing for {dest.name}",
                               "Reinstall the sentinelcore package.")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        os.chmod(dest, 0o644)
    manifest = load_manifest(IMAGES_MANIFEST)
    assert_release_manifest(manifest)
    # Offline archives are verified by signed checksum and carry tags, not digests.
    refs = image_refs(manifest, use_digest=offline is None)
    RELEASE_ENV.write_text(render_release_env(refs), encoding="utf-8")
    os.chmod(RELEASE_ENV, 0o644)


# --------------------------------------------------------------------------
# Config writing (used by the install and by --generate-only)
# --------------------------------------------------------------------------
def write_config(answers: Answers) -> None:
    existing = configgen.load_env(ENV_FILE)
    env = configgen.build_env(answers, existing)
    configgen.write_private_file(ENV_FILE, configgen.render_env(env), mode=0o600)
    configgen.write_profile(PROFILE_FILE, answers)


def write_desktop_launcher(url: str) -> None:
    if any(c in url for c in "\n\r\"'`$;&|<>\\ "):
        return  # the URL is built from validated parts; refuse anything unusual
    DESKTOP_FILE.parent.mkdir(parents=True, exist_ok=True)
    DESKTOP_FILE.write_text(
        "[Desktop Entry]\nType=Application\nName=SentinelCore Dashboard\n"
        "Comment=Open the SentinelCore dashboard\n"
        f"Exec=xdg-open {url}\nIcon=security-high\nTerminal=false\nCategories=Network;Security;\n",
        encoding="utf-8",
    )
    os.chmod(DESKTOP_FILE, 0o644)


def open_browser(url: str) -> bool:
    """Open the dashboard as the invoking desktop user (best effort)."""
    user = os.environ.get("SUDO_USER")
    if not user or user == "root" or not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        return False
    env = {k: os.environ[k] for k in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
                                      "DBUS_SESSION_BUS_ADDRESS") if k in os.environ}
    res = run(["runuser", "-u", user, "--", "xdg-open", url], check=False, env=env, timeout=15)
    return res.returncode == 0


def final_screen_text(answers: Answers, shown_password: str | None) -> str:
    lines = [
        "SentinelCore is installed and running.",
        "",
        f"  Dashboard : {answers.dashboard_url}",
        f"  Admin     : {answers.admin_username}",
    ]
    if shown_password:
        lines += [f"  Password  : {shown_password}", "              (shown once - store it now)"]
    lines += [
        "",
        f"  Config    : {ENV_FILE}  (secrets, root only)",
        f"  Profile   : {PROFILE_FILE}  (no secrets, reusable)",
        f"  Install log: {INSTALL_LOG}",
        "",
        "Most useful commands:",
        "  sudo sentinelcore status    - health of every service and the sensor",
        "  sudo sentinelcore doctor    - diagnose capture and network problems",
        "  sudo sentinelcore backup    - encrypted backup of data and config",
        "",
        "Your browser will warn about the self-signed certificate. That is expected",
        "for a local install; you can replace the files in /etc/sentinelcore/tls.",
        f"Version {current_version()}",
    ]
    return "\n".join(lines)
