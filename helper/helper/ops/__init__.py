"""Operation registry.

Dispatch is an explicit name → handler table. There is no generic "run this
command" op and there never will be: adding a capability means adding a named
handler with its own validation, which is a reviewable diff.
"""

from __future__ import annotations

from collections.abc import Callable

from helper.ops.firewall import fw_apply, fw_check_target, fw_list, fw_reconcile, fw_revoke
from helper.ops.nmap_scan import arp_sweep, nmap_scan
from helper.ops.suricata import (
    suricata_reload_rules,
    suricata_start,
    suricata_status,
    suricata_stop,
    suricata_test_config,
    suricata_write_rules,
)

Handler = Callable[[dict], dict]

OPS: dict[str, Handler] = {
    "ping": lambda params: {"pong": True},
    # M3 — discovery
    "nmap_scan": nmap_scan,
    "arp_sweep": arp_sweep,
    # M4 — sensor lifecycle and ruleset
    "suricata_status": suricata_status,
    "suricata_start": suricata_start,
    "suricata_stop": suricata_stop,
    "suricata_reload_rules": suricata_reload_rules,
    "suricata_test_config": suricata_test_config,
    "suricata_write_rules": suricata_write_rules,
    # M10 — firewall containment
    "fw_apply": fw_apply,
    "fw_revoke": fw_revoke,
    "fw_list": fw_list,
    "fw_reconcile": fw_reconcile,
    "fw_check_target": fw_check_target,
}


def register(name: str, handler: Handler) -> None:
    """Used by M4 to add sensor ops without editing this file's imports."""
    if name in OPS:
        raise ValueError(f"Operation {name!r} is already registered")
    OPS[name] = handler


__all__ = ["OPS", "Handler", "register"]
