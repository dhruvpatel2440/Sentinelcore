"""Helper configuration, resolved once at startup.

Binary paths are resolved here and never recomputed, so a later PATH change
cannot redirect what the helper executes.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    pass


def _resolve_binary(name: str, explicit: str | None) -> str | None:
    """Absolute path to a required binary, or None when it is unavailable."""
    candidate = explicit or shutil.which(name)
    if not candidate:
        return None
    path = Path(candidate).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        return None
    return str(path)


def _resolve_binary_no_symlink_follow(name: str, explicit: str | None) -> str | None:
    """Like `_resolve_binary`, but keeps the discovered path as-is.

    `iptables` on modern Debian is a symlink to the `xtables-nft-multi`
    busybox-style binary, which dispatches behaviour from `argv[0]`'s
    basename. Fully resolving the symlink (as `_resolve_binary` does for
    ordinary binaries) would rewrite argv[0] to `xtables-nft-multi` and the
    multicall binary would refuse to run with no subcommand.
    """
    candidate = explicit or shutil.which(name)
    if not candidate:
        return None
    path = Path(candidate)
    if not path.is_file() or not os.access(path, os.X_OK):
        return None
    return str(path)


@dataclass
class HelperConfig:
    socket_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("HELPER_SOCKET_PATH", "/run/sentinelcore/helper.sock")
        )
    )
    socket_group: str = os.getenv("HELPER_SOCKET_GROUP", "sentinelcore")
    # 0660: owner root, group sentinelcore. No world access, ever.
    socket_mode: int = 0o660

    monitored_network: ipaddress.IPv4Network = field(
        default_factory=lambda: _parse_network(os.getenv("MONITORED_NETWORK", "192.168.10.0/24"))
    )
    capture_interface: str = os.getenv("CAPTURE_INTERFACE", "eth1")

    # Hard ceilings. Every op runs under a timeout; none can run forever.
    nmap_timeout_seconds: int = int(os.getenv("HELPER_NMAP_TIMEOUT", "900"))
    arp_timeout_seconds: int = int(os.getenv("HELPER_ARP_TIMEOUT", "120"))
    default_op_timeout_seconds: int = int(os.getenv("HELPER_OP_TIMEOUT", "60"))
    # `suricata -T` against a full ET Open ruleset (~52k rules) takes
    # minutes on modest hardware. 180s was far too tight.
    suricata_test_timeout_seconds: int = int(os.getenv("HELPER_SURICATA_TEST_TIMEOUT", "900"))

    max_request_bytes: int = 64 * 1024

    nmap_path: str | None = field(default_factory=lambda: _resolve_binary("nmap", os.getenv("NMAP_PATH")))
    suricata_path: str | None = field(
        default_factory=lambda: _resolve_binary("suricata", os.getenv("SURICATA_PATH"))
    )
    suricatasc_path: str | None = field(
        default_factory=lambda: _resolve_binary("suricatasc", os.getenv("SURICATASC_PATH"))
    )

    # M4 paths — staging is where the backend drops candidate rule files.
    suricata_rules_dir: Path = field(
        default_factory=lambda: Path(os.getenv("SURICATA_RULES_DIR", "/var/lib/suricata/rules"))
    )
    suricata_staging_dir: Path = field(
        default_factory=lambda: Path(os.getenv("SURICATA_STAGING_DIR", "/var/lib/sentinelcore/staging"))
    )
    suricata_config_path: Path = field(
        default_factory=lambda: Path(os.getenv("SURICATA_CONFIG", "/etc/suricata/suricata.yaml"))
    )
    suricata_pid_file: Path = field(
        default_factory=lambda: Path(os.getenv("SURICATA_PID_FILE", "/var/run/suricata.pid"))
    )
    suricata_socket: Path = field(
        default_factory=lambda: Path(
            os.getenv("SURICATA_COMMAND_SOCKET", "/var/run/suricata/suricata-command.socket")
        )
    )

    # M10 — firewall containment
    ip_path: str | None = field(default_factory=lambda: _resolve_binary("ip", os.getenv("IP_PATH")))
    iptables_path: str | None = field(
        default_factory=lambda: _resolve_binary_no_symlink_follow("iptables", os.getenv("IPTABLES_PATH"))
    )
    fw_chain: str = os.getenv("FIREWALL_CHAIN", "SENTINELCORE")
    fw_op_timeout_seconds: int = int(os.getenv("HELPER_FIREWALL_TIMEOUT", "15"))
    # Never trusted alone — is_protected() also checks the live routing table
    # and /etc/resolv.conf, so a stale env value cannot widen what is blockable.
    protected_ips: frozenset[str] = field(
        default_factory=lambda: frozenset(
            ip.strip() for ip in os.getenv("PROTECTED_IPS", "").split(",") if ip.strip()
        )
    )
    dns_override: frozenset[str] = field(
        default_factory=lambda: frozenset(
            ip.strip() for ip in os.getenv("DNS_SERVERS", "").split(",") if ip.strip()
        )
    )


def _parse_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ConfigError(f"MONITORED_NETWORK is not a valid network: {value!r}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ConfigError("MONITORED_NETWORK must be IPv4")
    return network


config = HelperConfig()
