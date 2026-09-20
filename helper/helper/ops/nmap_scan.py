"""nmap_scan and arp_sweep — the M3 discovery operations."""

from __future__ import annotations

import logging

from helper.config import config
from helper.executor import ExecutionError, run
from helper.validation import ValidationError, validate_mode, validate_ports, validate_targets

logger = logging.getLogger("helper.ops.nmap")

# Fixed flags applied to every scan, independent of the caller.
#   -oX -   XML to stdout; the backend parses XML, never human output.
#   -n      never resolve DNS; scanning must not trigger outbound lookups.
#   -T3     polite-ish timing; -T5 floods the monitored segment.
#   --open  only report open ports, keeping the XML proportionate.
_BASE_FLAGS = ("-oX", "-", "-n", "-T3")


def nmap_scan(params: dict) -> dict:
    """Port/host scan. Returns raw nmap XML for the backend to parse."""
    if config.nmap_path is None:
        raise ExecutionError("binary_missing", "nmap is not installed in the helper image")

    networks = validate_targets(params.get("targets"))
    mode_flags = validate_mode(params.get("mode", "tcp_syn"))

    argv = [config.nmap_path, *_BASE_FLAGS, *mode_flags]

    # `ping` mode is host discovery only — a port spec would be meaningless
    # and nmap would reject the combination.
    if "-sn" not in mode_flags:
        ports = validate_ports(params.get("ports", "1-1024"))
        argv += ["--open", "-p", ports.to_nmap()]

    # Targets are appended last, re-serialised from validated network objects.
    # The caller's original strings are discarded.
    argv += [str(net) for net in networks]

    result = run(argv, timeout=config.nmap_timeout_seconds)

    if result.returncode != 0:
        raise ExecutionError(
            "scan_failed",
            f"nmap exited {result.returncode}: {result.stderr.strip()[:500] or 'no error output'}",
        )

    return {
        "xml": result.stdout,
        "argv": result.argv,
        "targets": [str(n) for n in networks],
    }


def arp_sweep(params: dict) -> dict:
    """Scapy ARP sweep for MAC addresses on the local segment.

    ARP is link-local, so this only returns results for hosts on the same
    broadcast domain — which is precisely where MAC/vendor data is meaningful.
    """
    networks = validate_targets(params.get("targets"))

    try:
        # Imported lazily: scapy is heavy and only this op needs it, so an
        # import problem cannot take down the whole helper at startup.
        from scapy.all import ARP, Ether, conf, srp  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on image contents
        raise ExecutionError("binary_missing", "scapy is not available in the helper image") from exc

    conf.verb = 0
    discovered: list[dict[str, str]] = []

    for network in networks:
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        try:
            answered, _ = srp(
                request,
                timeout=min(config.arp_timeout_seconds, 30),
                iface=config.capture_interface,
                inter=0.05,
            )
        except PermissionError as exc:
            raise ExecutionError("permission_denied", "ARP sweep needs NET_RAW") from exc
        except OSError as exc:
            raise ExecutionError("arp_failed", f"ARP sweep failed: {exc}") from exc

        for _sent, received in answered:
            discovered.append({"ip_address": received.psrc, "mac_address": received.hwsrc.lower()})

    logger.info("arp_sweep found %d host(s)", len(discovered))
    return {"hosts": discovered, "targets": [str(n) for n in networks]}
