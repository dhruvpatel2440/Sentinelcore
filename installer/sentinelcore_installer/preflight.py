"""Pre-flight checks. Each failure says what is wrong and how to fix it."""

from __future__ import annotations

import platform
import shutil
import socket
from dataclasses import dataclass
from pathlib import Path

from . import netinfo
from .common import CommandError, is_root, log, run

MIN_DISK_GB = 10
# A "4 GB" machine reports roughly 3.8 GiB in MemTotal (firmware/kernel
# reservations), so the hard floor is set just under 4 GB to avoid rejecting
# machines that really have it.
MIN_RAM_KIB = int(3.6 * 1024 * 1024)

# (id, version) pairs. "expected" = family we believe works but have not
# installed on a clean VM; see docs/supported-platforms.md for what is tested.
EXPECTED_OS = {
    "ubuntu": {"22.04", "24.04"},
    "debian": {"12"},
}


@dataclass
class Check:
    name: str
    ok: bool
    severity: str  # "error" blocks the install, "warn" does not
    message: str
    fix: str = ""

    @property
    def blocking(self) -> bool:
        return not self.ok and self.severity == "error"


def read_os_release(path: str = "/etc/os-release") -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                key, _, val = line.partition("=")
                data[key] = val.strip().strip('"')
    except OSError:
        pass
    return data


def is_wsl() -> bool:
    try:
        text = Path("/proc/version").read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return False
    return "microsoft" in text or "wsl" in text


def check_root() -> Check:
    if is_root():
        return Check("Administrator rights", True, "error", "running as root")
    return Check(
        "Administrator rights", False, "error",
        "The installer must run as root to install Docker, write /etc and start services.",
        "Re-run with: sudo sentinelcore install",
    )


def check_os(os_release: dict[str, str] | None = None) -> Check:
    if platform.system() != "Linux":
        return Check("Operating system", False, "error",
                     f"{platform.system()} is not supported. SentinelCore installs on Linux only.",
                     "Use a Linux machine or a Linux virtual machine (see docs/supported-platforms.md).")
    if is_wsl():
        return Check("Operating system", False, "error",
                     "WSL is not supported: it cannot provide a real promiscuous capture interface.",
                     "Install on a real Linux machine or a VirtualBox/VMware VM.")
    info = os_release if os_release is not None else read_os_release()
    distro, version = info.get("ID", "unknown"), info.get("VERSION_ID", "")
    label = info.get("PRETTY_NAME", f"{distro} {version}")
    if version in EXPECTED_OS.get(distro, set()):
        return Check("Operating system", True, "warn", f"{label} (see docs/supported-platforms.md for test status)")
    return Check("Operating system", False, "warn",
                 f"{label} is not on the expected list. It may work if Docker Engine and Compose v2 are installed.",
                 "Continue at your own risk, or use Ubuntu 24.04.")


def check_docker() -> list[Check]:
    checks: list[Check] = []
    if not shutil.which("docker"):
        return [Check("Docker Engine", False, "error", "Docker is not installed.",
                      "Let the installer add it from Docker's official apt repository, or install it yourself.")]
    ver = run(["docker", "version", "--format", "{{.Server.Version}}"], check=False, timeout=20)
    if ver.returncode != 0 or not ver.stdout.strip():
        checks.append(Check("Docker Engine", False, "error",
                            "Docker is installed but the daemon does not answer.",
                            "Start it with: sudo systemctl enable --now docker"))
    else:
        checks.append(Check("Docker Engine", True, "error", f"version {ver.stdout.strip()}"))
    comp = run(["docker", "compose", "version", "--short"], check=False, timeout=20)
    if comp.returncode != 0:
        checks.append(Check("Docker Compose v2", False, "error",
                            "The 'docker compose' plugin is missing (docker-compose v1 is not supported).",
                            "Install the docker-compose-plugin package."))
    else:
        checks.append(Check("Docker Compose v2", True, "error", f"version {comp.stdout.strip()}"))
    return checks


def check_disk(path: str = "/var/lib") -> Check:
    target = path if Path(path).exists() else "/"
    free_gb = shutil.disk_usage(target).free / 1024**3
    if free_gb >= MIN_DISK_GB:
        return Check("Free disk space", True, "error", f"{free_gb:.1f} GB free")
    return Check("Free disk space", False, "error",
                 f"Only {free_gb:.1f} GB free; at least {MIN_DISK_GB} GB is needed for images and data.",
                 "Free up space or add disk, then run the installer again.")


def read_mem_kib(path: str = "/proc/meminfo") -> int:
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def check_ram(mem_kib: int | None = None) -> Check:
    kib = read_mem_kib() if mem_kib is None else mem_kib
    gib = kib / 1024 / 1024
    if kib >= MIN_RAM_KIB:
        return Check("Memory", True, "error", f"{gib:.1f} GiB")
    return Check("Memory", False, "error",
                 f"{gib:.1f} GiB detected; at least 4 GB of RAM is required.",
                 "Give the machine or VM more memory.")


def port_is_free(address: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((address, port))
        except OSError:
            return False
    return True


def stack_is_running() -> bool:
    res = run(["docker", "ps", "--filter", "label=com.docker.compose.project=sentinelcore", "-q"],
              check=False, timeout=20)
    return res.returncode == 0 and bool(res.stdout.strip())


def check_ports(http: int = 80, https: int = 443, address: str = "0.0.0.0", hard: bool = False) -> Check:
    if stack_is_running():
        return Check("Ports", True, "error", "in use by an existing SentinelCore install (will be reused)")
    busy = [p for p in (http, https) if not port_is_free(address, p)]
    if not busy:
        return Check("Ports", True, "error", f"{http} and {https} are free")
    return Check("Ports", False, "error" if hard else "warn",
                 f"Port(s) {', '.join(map(str, busy))} already in use by another program.",
                 "Stop that program, or choose other ports in a Custom install.")


def check_interfaces() -> Check:
    cands = netinfo.capture_candidates(netinfo.list_interfaces())
    if cands:
        return Check("Network interfaces", True, "error", ", ".join(i.name for i in cands))
    return Check("Network interfaces", False, "error",
                 "No non-loopback network interface was found.",
                 "Attach a network adapter (for VirtualBox: a second adapter in promiscuous mode).")


def check_tools() -> list[Check]:
    out: list[Check] = []
    if not shutil.which("openssl"):
        out.append(Check("openssl", False, "error", "openssl is needed to create the TLS certificate.",
                         "sudo apt-get install -y openssl"))
    if not shutil.which("ip"):
        out.append(Check("iproute2", False, "error", "The 'ip' command is missing.",
                         "sudo apt-get install -y iproute2"))
    if not shutil.which("systemctl"):
        out.append(Check("systemd", False, "warn", "systemd was not found; the auto-start service cannot be installed.",
                         "Start the stack manually with: sudo sentinelcore start"))
    return out


def run_all(*, include_docker: bool = True) -> list[Check]:
    checks = [check_root(), check_os(), check_disk(), check_ram(), check_interfaces(), check_ports()]
    checks += check_tools()
    if include_docker:
        checks += check_docker()
    return checks


# --------------------------------------------------------------------------
# Docker Engine installation (only ever with the user's consent)
# --------------------------------------------------------------------------
def can_install_docker(info: dict[str, str] | None = None) -> bool:
    info = info or read_os_release()
    return info.get("ID") in {"ubuntu", "debian"} and shutil.which("apt-get") is not None


def install_docker(info: dict[str, str] | None = None) -> None:
    """Install Docker Engine + Compose v2 from Docker's official apt repository."""
    import urllib.request

    info = info or read_os_release()
    distro = info.get("ID", "")
    if distro not in {"ubuntu", "debian"}:
        raise CommandError(["apt"], 1, "Docker auto-install supports Ubuntu and Debian only.")
    codename = info.get("UBUNTU_CODENAME") or info.get("VERSION_CODENAME", "")
    if not codename:
        raise CommandError(["apt"], 1, "Could not determine the distribution codename.")

    log.info("installing Docker Engine from download.docker.com (%s %s)", distro, codename)
    run(["apt-get", "update"], env={"DEBIAN_FRONTEND": "noninteractive"})
    run(["apt-get", "install", "-y", "ca-certificates", "curl", "gnupg"], env={"DEBIAN_FRONTEND": "noninteractive"})
    keyring_dir = Path("/etc/apt/keyrings")
    keyring_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    key_path = keyring_dir / "docker.asc"
    url = f"https://download.docker.com/linux/{distro}/gpg"
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - fixed https URL
        key_path.write_bytes(resp.read())
    key_path.chmod(0o644)
    arch = run(["dpkg", "--print-architecture"]).stdout.strip()
    Path("/etc/apt/sources.list.d/docker.list").write_text(
        f"deb [arch={arch} signed-by={key_path}] https://download.docker.com/linux/{distro} {codename} stable\n",
        encoding="utf-8",
    )
    run(["apt-get", "update"], env={"DEBIAN_FRONTEND": "noninteractive"})
    run(
        ["apt-get", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io",
         "docker-buildx-plugin", "docker-compose-plugin"],
        env={"DEBIAN_FRONTEND": "noninteractive"},
    )
    run(["systemctl", "enable", "--now", "docker"], check=False)
