"""Command line entry point: ``sentinelcore <command>`` and ``sentinelcore-installer``."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import configgen, install as inst, netinfo, preflight, signing
from . import validators as v
from .common import (
    COMPOSE_FILE, DEFAULT_UPDATE_URL, DESKTOP_FILE, ENV_FILE, INSTALL_LOG, OPT_DIR,
    PROFILE_FILE, RELEASE_ENV, ROLLBACK_DIR, STATE_DIR, SYSTEMD_UNIT, TLS_CERT, TLS_DIR,
    TLS_KEY, CommandError, compose_argv, current_version, is_root, log, run, setup_logging,
)
from .ui import UI, make_ui
from .wizard import Wizard

ADMIN_PW_ENV = "SENTINELCORE_ADMIN_PASSWORD"
BACKUP_PW_ENV = "SENTINELCORE_BACKUP_PASSPHRASE"


def out(text: str = "") -> None:
    print(text, flush=True)


def need_root(what: str) -> bool:
    if is_root() or os.environ.get("SENTINELCORE_PREFIX"):
        return True
    out(f"'{what}' needs administrator rights. Run: sudo sentinelcore {what}")
    return False


def installed() -> bool:
    return ENV_FILE.exists() and COMPOSE_FILE.exists()


# --------------------------------------------------------------------------
# install
# --------------------------------------------------------------------------
def _admin_password(ui: UI, answers: configgen.Answers, non_interactive: bool) -> str:
    env_pw = os.environ.get(ADMIN_PW_ENV, "")
    if env_pw:
        return v.validate_password(env_pw, answers.admin_username)
    if answers.admin_password_mode == "generate":
        return configgen.generate_password()
    if non_interactive:
        raise v.ValidationError(
            f"admin password required: set {ADMIN_PW_ENV}, or set password_source to 'generate' in the profile"
        )
    while True:
        pw = getpass.getpass(f"Password for '{answers.admin_username}' (12+ characters): ")
        again = getpass.getpass("Confirm password: ")
        if pw != again:
            out("Passwords differ, try again.")
            continue
        try:
            return v.validate_password(pw, answers.admin_username)
        except v.ValidationError as exc:
            out(str(exc))


def _print_checks(checks: list[preflight.Check]) -> list[preflight.Check]:
    blocking = []
    for c in checks:
        mark = "ok  " if c.ok else ("FAIL" if c.severity == "error" else "warn")
        out(f"  [{mark}] {c.name}: {c.message}")
        if not c.ok and c.fix:
            out(f"         fix: {c.fix}")
        if c.blocking:
            blocking.append(c)
    return blocking


def cmd_install(args: argparse.Namespace) -> int:
    setup_logging(args.verbose)
    if not need_root("install"):
        return 2
    non_interactive = args.non_interactive
    ui = make_ui(plain=args.plain, non_interactive=non_interactive)
    out(f"SentinelCore {current_version()} installer\n")

    out("Checking this machine:")
    checks = preflight.run_all(include_docker=False)
    docker_checks = preflight.check_docker()
    blocking = _print_checks(checks)
    needs_docker = any(c.blocking for c in docker_checks)
    if needs_docker and not blocking:
        if preflight.can_install_docker():
            go = args.yes or (ui.interactive and ui.yesno(
                "Docker is required",
                "Docker Engine and Compose v2 are not available. Install them now from Docker's "
                "official apt repository (download.docker.com)?", "Install Docker", "Cancel"))
            if go:
                try:
                    preflight.install_docker()
                except (CommandError, OSError, urllib.error.URLError) as exc:
                    out(f"Docker installation failed: {getattr(exc, 'output', exc)}")
                    return 1
                docker_checks = preflight.check_docker()
        needs_docker = any(c.blocking for c in docker_checks)
    blocking += _print_checks(docker_checks) if docker_checks else []
    if blocking and not args.generate_only:
        out("\nFix the items marked FAIL, then run the installer again.")
        return 1

    # --- gather answers --------------------------------------------------
    try:
        base = configgen.load_profile(Path(args.config)) if args.config else None
    except v.ValidationError as exc:
        out(f"Cannot use profile: {exc}")
        return 2
    if non_interactive:
        if base is None:
            out("--non-interactive needs --config <install-profile.yaml>")
            return 2
        answers = base
        try:
            answers.admin_password = _admin_password(ui, answers, True)
        except v.ValidationError as exc:
            out(str(exc))
            return 2
    else:
        answers = Wizard(ui, base, accept_eula=args.accept_eula).run()
        if answers is None:
            out("Setup cancelled. Nothing was changed.")
            return 1
        if not answers.admin_password:
            answers.admin_password = _admin_password(ui, answers, False)

    # Ports chosen in the wizard must be free (an existing SentinelCore is fine).
    port_check = preflight.check_ports(answers.http_port, answers.https_port, answers.listen_address, hard=True)
    if not port_check.ok and not args.generate_only:
        out(f"{port_check.message} {port_check.fix}")
        return 1

    generated_pw = answers.admin_password if answers.admin_password_mode == "generate" else None

    if args.generate_only:
        inst.write_config(answers)
        out(f"\nConfiguration written (nothing installed):\n  {ENV_FILE}  (secrets, 0600)\n  {PROFILE_FILE}  (no secrets)")
        out("Review them, then run: sudo sentinelcore install --config " + str(PROFILE_FILE))
        return 0

    offline = Path(args.offline_bundle) if args.offline_bundle else None
    out("\nInstalling. This takes a few minutes; the log is " + str(INSTALL_LOG) + "\n")
    outcome = inst.Installer(ui, answers, offline_bundle=offline, skip_images=args.skip_images).run()
    if not outcome.ok:
        out(f"\nInstallation did not finish: {outcome.failed_phase}")
        out(outcome.message)
        if outcome.hint:
            out(outcome.hint)
        for name, ok, detail in outcome.checks or []:
            out(f"  [{'ok' if ok else 'FAIL'}] {name} {detail}")
        return 1

    out("\n" + inst.final_screen_text(answers, generated_pw))
    if ui.interactive and ui.yesno("Open the dashboard?", "Open the dashboard in your browser now?"):
        if not inst.open_browser(answers.dashboard_url):
            out("Could not open a browser from here; open the URL above yourself.")
    return 0


# --------------------------------------------------------------------------
# simple stack control
# --------------------------------------------------------------------------
def cmd_compose_passthrough(args: argparse.Namespace) -> int:
    """Hidden: used by the systemd unit. `sentinelcore _compose up -d`."""
    argv = compose_argv(*args.rest)
    os.execvp(argv[0], argv)
    return 1  # pragma: no cover


def _stack(action: list[str], label: str) -> int:
    if not need_root(label) or not installed():
        if not installed():
            out("SentinelCore is not installed. Run: sudo sentinelcore install")
        return 1
    res = run(compose_argv(*action), check=False, timeout=900)
    if res.returncode != 0:
        out(res.stderr.strip()[-800:])
        return 1
    out(f"{label}: done")
    return 0


def cmd_start(args):
    return _stack(["up", "-d", "--remove-orphans"], "start")


def cmd_stop(args):
    return _stack(["stop"], "stop")


def cmd_restart(args):
    return _stack(["restart"], "restart")


def cmd_logs(args: argparse.Namespace) -> int:
    if not installed():
        out("SentinelCore is not installed.")
        return 1
    extra = ["--tail", str(args.tail)] + (["-f"] if args.follow else [])
    argv = compose_argv("logs", *extra, *([args.service] if args.service else []))
    os.execvp(argv[0], argv)
    return 1  # pragma: no cover


def cert_days_left() -> int | None:
    if not TLS_CERT.exists():
        return None
    res = run(["openssl", "x509", "-enddate", "-noout", "-in", str(TLS_CERT)], check=False)
    m = re.search(r"notAfter=(.+)", res.stdout)
    if not m:
        return None
    try:
        end = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (end - datetime.now(timezone.utc)).days


def cmd_status(args: argparse.Namespace) -> int:
    if not installed():
        out("SentinelCore is not installed.")
        return 1
    rows = inst.compose_ps()
    out(f"SentinelCore {current_version()}\n")
    out("Services:")
    for row in sorted(rows, key=lambda r: r.get("Service", "")):
        health = row.get("Health") or "-"
        out(f"  {row.get('Service', '?'):<10} {row.get('State', '?'):<10} health: {health}")
    if not rows:
        out("  (no containers: run 'sudo sentinelcore start')")
    env = configgen.load_env(ENV_FILE)
    ps = run(compose_argv("exec", "-T", "helper", "pgrep", "-a", "suricata"), check=False, timeout=30)
    iface = env.get("CAPTURE_INTERFACE", "?")
    out(f"\nSensor: {'running on ' + iface if ps.returncode == 0 and iface in ps.stdout else 'NOT running'}")
    data_dir = Path(env.get("SENTINELCORE_DATA_DIR", "/var/lib/sentinelcore"))
    for label, path in [("Data disk", data_dir if data_dir.exists() else Path("/")), ("Docker disk", Path("/var/lib/docker"))]:
        if path.exists():
            du = shutil.disk_usage(path)
            out(f"{label}: {du.free / 1024**3:.1f} GB free of {du.total / 1024**3:.0f} GB ({path})")
    days = cert_days_left()
    if days is not None:
        out(f"TLS certificate: {days} days left" + ("  (renew soon)" if days < 30 else ""))
    bad = inst.unhealthy_services(rows)
    out("\nOverall: " + ("healthy" if rows and not bad else "needs attention: " + (", ".join(bad) or "stack not running")))
    return 0 if rows and not bad else 1


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------
def last_stats_drops(eve_tail: str) -> tuple[int, int] | None:
    """(kernel_packets, kernel_drops) from the newest Suricata stats event."""
    latest = None
    for line in eve_tail.splitlines():
        if '"event_type":"stats"' in line.replace(" ", ""):
            try:
                cap = json.loads(line)["stats"]["capture"]
                latest = (int(cap.get("kernel_packets", 0)), int(cap.get("kernel_drops", 0)))
            except (KeyError, ValueError, json.JSONDecodeError):
                continue
    return latest


def cmd_doctor(args: argparse.Namespace) -> int:
    if not installed():
        out("SentinelCore is not installed. Run: sudo sentinelcore install")
        return 1
    env = configgen.load_env(ENV_FILE)
    iface_name = env.get("CAPTURE_INTERFACE", "")
    results: list[tuple[str, str, str, str]] = []  # (level, name, detail, fix)

    def add(level, name, detail, fix=""):
        results.append((level, name, detail, fix))

    docker = run(["docker", "info", "--format", "{{.ServerVersion}}"], check=False, timeout=20)
    add("ok" if docker.returncode == 0 else "fail", "Docker daemon",
        docker.stdout.strip() or "not reachable", "sudo systemctl start docker")

    bad = inst.unhealthy_services(inst.compose_ps())
    add("ok" if not bad else "fail", "Services", "all healthy" if not bad else ", ".join(bad),
        "sudo sentinelcore logs <service>")

    interfaces = {i.name: i for i in netinfo.list_interfaces()}
    iface = interfaces.get(iface_name)
    if iface is None:
        add("fail", "Capture interface", f"{iface_name} does not exist",
            "Pick an existing interface (ip link) and edit CAPTURE_INTERFACE in /etc/sentinelcore/sentinelcore.env")
    else:
        add("ok" if iface.state in ("UP", "UNKNOWN") else "fail", "Interface state", f"{iface_name} is {iface.state}",
            f"sudo ip link set {iface_name} up")
        add("ok" if iface.promiscuous else "warn", "Promiscuous mode",
            "on" if iface.promiscuous else "off (needed to see other hosts' traffic)",
            f"sudo ip link set {iface_name} promisc on  (VirtualBox: set adapter Promiscuous Mode to 'Allow All')")
        _, mgmt = netinfo.default_route()
        if mgmt == iface_name:
            add("warn", "Interface role", "capture interface is also the management interface",
                "Capture on a mirror/second interface to see network-wide traffic")

    tail = run(compose_argv("exec", "-T", "helper", "tail", "-n", "600", "/var/log/suricata/eve.json"),
               check=False, timeout=30)
    stats = last_stats_drops(tail.stdout)
    if stats is None:
        add("warn", "Suricata drops", "no stats event found yet", "Wait a minute after starting the sensor, then re-run")
    else:
        pk, dr = stats
        ratio = (dr / pk * 100) if pk else 0.0
        add("ok" if ratio < 1 else "warn", "Suricata drops", f"{dr} of {pk} packets ({ratio:.2f}%)",
            "Reduce monitored traffic or give the machine more CPU/RAM")

    https_port = int(env.get("HTTPS_PORT", "443"))
    listen = env.get("LISTEN_ADDRESS", "127.0.0.1")
    probe = "127.0.0.1" if listen == "0.0.0.0" else listen
    try:
        with socket.create_connection((probe, https_port), timeout=3):
            add("ok", "Dashboard port", f"{probe}:{https_port} accepts connections")
    except OSError:
        add("fail", "Dashboard port", f"{probe}:{https_port} is not reachable", "sudo sentinelcore start")

    sync = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], check=False)
    if sync.returncode == 0:
        synced = sync.stdout.strip() == "yes"
        add("ok" if synced else "warn", "System clock", "synchronised" if synced else "not synchronised",
            "sudo timedatectl set-ntp true  (wrong time breaks token expiry and event ordering)")

    for path, want in [(ENV_FILE, 0o600), (TLS_KEY, 0o600)]:
        if path.exists():
            mode = path.stat().st_mode & 0o777
            add("ok" if mode == want else "fail", f"Permissions {path.name}", oct(mode),
                f"sudo chmod {oct(want)[2:]} {path}")

    days = cert_days_left()
    if days is not None:
        add("ok" if days > 30 else "warn", "TLS certificate", f"{days} days left",
            "Replace the files in /etc/sentinelcore/tls and run: sudo sentinelcore restart")

    free = shutil.disk_usage("/var/lib").free / 1024**3 if Path("/var/lib").exists() else 0
    add("ok" if free >= 5 else "warn", "Free disk", f"{free:.1f} GB", "Free space or lower EVENT_RETENTION_DAYS")

    worst = 0
    for level, name, detail, fix in results:
        out(f"  [{level:<4}] {name}: {detail}")
        if level != "ok" and fix:
            out(f"         -> {fix}")
        worst = max(worst, {"ok": 0, "warn": 1, "fail": 2}[level])
    return 1 if worst == 2 else 0


# --------------------------------------------------------------------------
# backup / restore
# --------------------------------------------------------------------------
def _passphrase(confirm: bool) -> str:
    pw = os.environ.get(BACKUP_PW_ENV, "")
    if pw:
        return pw
    if not sys.stdin.isatty():
        raise v.ValidationError(f"no passphrase: set {BACKUP_PW_ENV} or run interactively")
    pw = getpass.getpass("Backup passphrase: ")
    if confirm and getpass.getpass("Confirm passphrase: ") != pw:
        raise v.ValidationError("passphrases differ")
    if len(pw) < 8:
        raise v.ValidationError("use a passphrase of at least 8 characters")
    return pw


def _openssl_crypt(decrypt: bool, src: Path, dest: Path, passphrase: str) -> None:
    run([
        "openssl", "enc", "-d" if decrypt else "-e", "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-salt",
        "-in", str(src), "-out", str(dest), "-pass", "env:SC_BACKUP_PASS",
    ], env={"SC_BACKUP_PASS": passphrase})


def make_backup(passphrase: str, dest_dir: Path | None = None) -> Path:
    env = configgen.load_env(ENV_FILE)
    user, db = env.get("POSTGRES_USER", "sentinelcore"), env.get("POSTGRES_DB", "sentinelcore")
    data_dir = Path(env.get("SENTINELCORE_DATA_DIR", "/var/lib/sentinelcore/data"))
    dest_dir = dest_dir or data_dir / "backups"
    dest_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(dest_dir, 0o750)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    final = dest_dir / f"sentinelcore-backup-{stamp}.tar.enc"
    with tempfile.TemporaryDirectory(prefix="sc-backup-") as tmp:
        tmpd = Path(tmp)
        os.chmod(tmpd, 0o700)
        dump = tmpd / "database.sql"
        with open(dump, "wb") as fh:
            res = run(compose_argv("exec", "-T", "db", "pg_dump", "-U", user, "-d", db, "--clean", "--if-exists",
                                   "--no-owner"), stdout=fh, timeout=3600)
        if dump.stat().st_size == 0:
            raise CommandError(["pg_dump"], 1, "database dump is empty")
        tar_path = tmpd / "backup.tar"
        with tarfile.open(tar_path, "w") as tar:
            tar.add(dump, arcname="database.sql")
            for path, arc in [(ENV_FILE, "config/sentinelcore.env"), (PROFILE_FILE, "config/install-profile.yaml"),
                              (TLS_CERT, "config/tls/sentinelcore.crt"), (TLS_KEY, "config/tls/sentinelcore.key"),
                              (RELEASE_ENV, "config/release.env")]:
                if path.exists():
                    tar.add(path, arcname=arc)
            meta = tmpd / "meta.json"
            meta.write_text(json.dumps({"version": current_version(), "created": stamp}), encoding="utf-8")
            tar.add(meta, arcname="meta.json")
        _openssl_crypt(False, tar_path, final, passphrase)
    os.chmod(final, 0o600)
    return final


def cmd_backup(args: argparse.Namespace) -> int:
    if not need_root("backup") or not installed():
        return 1
    try:
        final = make_backup(_passphrase(True), Path(args.output) if args.output else None)
    except (v.ValidationError, CommandError, OSError) as exc:
        out(f"Backup failed: {getattr(exc, 'output', exc)}")
        return 1
    out(f"Backup written: {final}\nIt is encrypted with your passphrase. Keep the passphrase safe: it cannot be recovered.")
    return 0


def safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract regular files only, refusing absolute paths, '..' and links."""
    base = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not member.isfile() or not str(target).startswith(str(base) + os.sep):
            raise v.ValidationError(f"unsafe entry in backup: {member.name}")
    tar.extractall(dest)  # noqa: S202 - members validated above


def cmd_restore(args: argparse.Namespace) -> int:
    if not need_root("restore") or not installed():
        return 1
    src = Path(args.file)
    if not src.is_file():
        out(f"No such file: {src}")
        return 1
    host = socket.gethostname()
    if not args.yes:
        typed = input(f"Restoring REPLACES the current database. Type this host name ({host}) to continue: ")
        if typed.strip() != host:
            out("Cancelled.")
            return 1
    try:
        passphrase = _passphrase(False)
        with tempfile.TemporaryDirectory(prefix="sc-restore-") as tmp:
            tmpd = Path(tmp)
            os.chmod(tmpd, 0o700)
            plain = tmpd / "backup.tar"
            _openssl_crypt(True, src, plain, passphrase)
            with tarfile.open(plain) as tar:
                safe_extract(tar, tmpd / "x")
            dump = tmpd / "x" / "database.sql"
            if not dump.exists():
                raise v.ValidationError("backup has no database.sql")
            env = configgen.load_env(ENV_FILE)
            user, db = env.get("POSTGRES_USER", "sentinelcore"), env.get("POSTGRES_DB", "sentinelcore")
            run(compose_argv("stop", "backend", "worker"), timeout=300)
            with open(dump, "rb") as fh:
                proc = subprocess.run(
                    compose_argv("exec", "-T", "db", "psql", "-U", user, "-d", db, "-v", "ON_ERROR_STOP=1"),
                    stdin=fh, capture_output=True, check=False)
            if proc.returncode != 0:
                raise CommandError(["psql"], proc.returncode, proc.stderr.decode("utf-8", "replace")[-800:])
            run(compose_argv("up", "-d"), timeout=600)
    except (v.ValidationError, CommandError, OSError, tarfile.TarError) as exc:
        out(f"Restore failed: {getattr(exc, 'output', exc)}")
        run(compose_argv("up", "-d"), check=False, timeout=600)
        return 1
    out("Restore complete. Configuration files in the backup were NOT applied automatically;\n"
        "they are inside the archive if you need them (config/).")
    return 0


# --------------------------------------------------------------------------
# update
# --------------------------------------------------------------------------
_VER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")


def parse_version(text: str) -> tuple[int, int, int, int, str]:
    m = _VER_RE.match(text.strip())
    if not m:
        raise v.ValidationError(f"not a semantic version: {text!r}")
    major, minor, patch, pre = int(m[1]), int(m[2]), int(m[3]), m[4] or ""
    # A pre-release sorts below its release: 1.0.0-rc1 < 1.0.0
    return (major, minor, patch, 0 if pre else 1, pre)


def is_newer(candidate: str, current: str) -> bool:
    return parse_version(candidate) > parse_version(current)


def _fetch(url: str, dest: Path, timeout: int = 60) -> None:
    if not url.startswith("https://"):
        raise v.ValidationError("update URLs must use https")
    req = urllib.request.Request(url, headers={"User-Agent": f"sentinelcore/{current_version()}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as fh:  # noqa: S310
        shutil.copyfileobj(resp, fh)


def check_latest(base_url: str, workdir: Path) -> dict:
    """Download latest.json + signature, verify, return parsed contents."""
    meta, sig = workdir / "latest.json", workdir / "latest.json.asc"
    _fetch(f"{base_url.rstrip('/')}/latest.json", meta)
    _fetch(f"{base_url.rstrip('/')}/latest.json.asc", sig)
    signing.verify_detached(meta, sig)
    try:
        data = json.loads(meta.read_text(encoding="utf-8"))
        data["version"], data["files"]
    except (KeyError, json.JSONDecodeError) as exc:
        raise v.ValidationError(f"latest.json is malformed: {exc}") from exc
    return data


def cmd_update(args: argparse.Namespace) -> int:
    if not need_root("update") or not installed():
        return 1
    current = current_version()
    try:
        with tempfile.TemporaryDirectory(prefix="sc-update-") as tmp:
            work = Path(tmp)
            data = check_latest(args.url or DEFAULT_UPDATE_URL, work)
            latest = data["version"]
            if not is_newer(latest, current):
                out(f"SentinelCore {current} is up to date.")
                return 0
            minimum = data.get("min_compatible_version")
            if minimum and parse_version(current) < parse_version(minimum):
                out(f"Version {latest} requires at least {minimum} first. Update to {minimum} before continuing.")
                return 1
            out(f"Update available: {current} -> {latest}")
            if data.get("migration_notes"):
                out("Notes: " + str(data["migration_notes"]))
            if not args.yes and input("Back up and install the update? [y/N] ").strip().lower() != "y":
                return 1
            deb = data["files"].get("deb")
            if not deb:
                raise v.ValidationError("latest.json lists no .deb package")
            deb_path = work / "sentinelcore.deb"
            out("Backing up first ...")
            backup = make_backup(_passphrase(True))
            out(f"  backup: {backup}")
            out("Downloading the update ...")
            _fetch(deb["url"], deb_path, timeout=600)
            if signing.sha256_file(deb_path) != deb["sha256"].lower():
                raise signing.SignatureError("package checksum does not match the signed latest.json")
            return _apply_update(deb_path, data)
    except (v.ValidationError, signing.SignatureError, CommandError, OSError, urllib.error.URLError) as exc:
        out(f"Update stopped: {getattr(exc, 'output', exc)}")
        return 1


def _snapshot() -> Path:
    snap = ROLLBACK_DIR / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snap.mkdir(parents=True, exist_ok=True)
    for f in [COMPOSE_FILE, RELEASE_ENV, OPT_DIR / "images.json", OPT_DIR / "nginx" / "nginx.release.conf",
              OPT_DIR / "suricata" / "suricata.yaml"]:
        if f.exists():
            shutil.copyfile(f, snap / f.name)
    return snap


def _restore_snapshot(snap: Path) -> None:
    mapping = {"docker-compose.release.yml": COMPOSE_FILE, "release.env": RELEASE_ENV,
               "images.json": OPT_DIR / "images.json", "nginx.release.conf": OPT_DIR / "nginx" / "nginx.release.conf",
               "suricata.yaml": OPT_DIR / "suricata" / "suricata.yaml"}
    for name, dest in mapping.items():
        if (snap / name).exists():
            shutil.copyfile(snap / name, dest)


def _apply_update(deb_path: Path, data: dict) -> int:
    snap = _snapshot()
    try:
        run(["dpkg", "-i", str(deb_path)], timeout=300)
        inst.deploy_files()
        run(compose_argv("pull", "--quiet"), timeout=3600)
        run(compose_argv("up", "-d", "--remove-orphans"), timeout=900)
        if not inst.wait_for(lambda: not inst.unhealthy_services(inst.compose_ps()), timeout=420, interval=5):
            raise CommandError(["compose"], 1, "services did not become healthy after the update")
    except (CommandError, OSError, inst.InstallError) as exc:
        out(f"Update failed ({getattr(exc, 'output', exc)}). Rolling back to the previous release ...")
        _restore_snapshot(snap)
        run(compose_argv("up", "-d", "--remove-orphans"), check=False, timeout=900)
        out("Rolled back. Your data was not changed; the pre-update backup is in the data directory.")
        return 1
    out(f"Updated to {data['version']}.")
    return 0


# --------------------------------------------------------------------------
# uninstall / version
# --------------------------------------------------------------------------
def cmd_uninstall(args: argparse.Namespace) -> int:
    if not need_root("uninstall"):
        return 1
    host = socket.gethostname()
    if args.purge:
        typed = input(f"--purge DELETES the database, reports, captures and configuration.\nType this host name ({host}) to confirm: ")
        if typed.strip() != host:
            out("Cancelled. Nothing was removed.")
            return 1
    elif not args.yes and input("Stop SentinelCore and remove its services? Data is kept. [y/N] ").strip().lower() != "y":
        return 1
    env = configgen.load_env(ENV_FILE)
    if shutil.which("systemctl"):
        run(["systemctl", "disable", "--now", "sentinelcore.service"], check=False)
    if COMPOSE_FILE.exists():
        run(compose_argv("down", "--remove-orphans", *(["-v"] if args.purge else [])), check=False, timeout=300)
    for path in (SYSTEMD_UNIT, DESKTOP_FILE):
        path.unlink(missing_ok=True)
    if shutil.which("systemctl"):
        run(["systemctl", "daemon-reload"], check=False)
    if args.purge:
        data_dir = Path(env.get("SENTINELCORE_DATA_DIR", "/var/lib/sentinelcore/data"))
        for d in (OPT_DIR, ENV_FILE.parent, STATE_DIR, data_dir):
            shutil.rmtree(d, ignore_errors=True)
        out("Everything was removed. To remove the program itself: sudo apt remove sentinelcore")
    else:
        out("Services removed. Data volumes, /etc/sentinelcore and backups were kept.\n"
            "Reinstall later with: sudo sentinelcore install --config /etc/sentinelcore/install-profile.yaml")
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    out(f"sentinelcore {current_version()}")
    return 0


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinelcore", description="Install and manage SentinelCore.")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser("install", help="run the guided setup and install everything")
    i.add_argument("--config", help="install-profile.yaml to pre-fill (or replay with --non-interactive)")
    i.add_argument("--non-interactive", action="store_true", help=f"no prompts; admin password from ${ADMIN_PW_ENV}")
    i.add_argument("--generate-only", action="store_true", help="write the config files, install nothing")
    i.add_argument("--plain", action="store_true", help="plain text prompts instead of whiptail")
    i.add_argument("--accept-eula", action="store_true", help="accept the licence without showing it")
    i.add_argument("--offline-bundle", help="directory with the offline image bundle")
    i.add_argument("--skip-images", action="store_true", help="use images already present locally")
    i.add_argument("--yes", action="store_true", help="answer yes to the Docker install offer")
    i.set_defaults(fn=cmd_install)

    sub.add_parser("start", help="start the stack").set_defaults(fn=cmd_start)
    sub.add_parser("stop", help="stop the stack").set_defaults(fn=cmd_stop)
    sub.add_parser("restart", help="restart the stack").set_defaults(fn=cmd_restart)
    sub.add_parser("status", help="service health, sensor, disk, certificate").set_defaults(fn=cmd_status)

    lg = sub.add_parser("logs", help="show service logs")
    lg.add_argument("service", nargs="?")
    lg.add_argument("-f", "--follow", action="store_true")
    lg.add_argument("--tail", type=int, default=200)
    lg.set_defaults(fn=cmd_logs)

    sub.add_parser("doctor", help="diagnose capture, network and permission problems").set_defaults(fn=cmd_doctor)

    b = sub.add_parser("backup", help="encrypted backup of database and config")
    b.add_argument("--output", help="directory for the backup file")
    b.set_defaults(fn=cmd_backup)

    r = sub.add_parser("restore", help="restore a backup file")
    r.add_argument("file")
    r.add_argument("--yes", action="store_true", help="skip the host-name confirmation")
    r.set_defaults(fn=cmd_restore)

    u = sub.add_parser("update", help="check for and install a signed update")
    u.add_argument("--url", help="release channel base URL")
    u.add_argument("--yes", action="store_true")
    u.set_defaults(fn=cmd_update)

    x = sub.add_parser("uninstall", help="remove services (data is kept unless --purge)")
    x.add_argument("--purge", action="store_true", help="also delete data and configuration")
    x.add_argument("--yes", action="store_true")
    x.set_defaults(fn=cmd_uninstall)

    sub.add_parser("version", help="print the version").set_defaults(fn=cmd_version)

    c = sub.add_parser("_compose")
    c.add_argument("rest", nargs=argparse.REMAINDER)
    c.set_defaults(fn=cmd_compose_passthrough)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args))
    except KeyboardInterrupt:
        out("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
