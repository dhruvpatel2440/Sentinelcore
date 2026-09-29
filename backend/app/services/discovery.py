"""Asset discovery: drive the helper, parse results, reconcile into the DB.

Reconciliation is an upsert keyed on `ip_address`, never a replace. A host that
disappears is marked inactive after a grace period rather than deleted.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import cast, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import SessionLocal
from app.models.asset import Asset, AssetPort, PortState, Protocol
from app.models.scan import Scan, ScanStatus
from app.services import audit, helper_client
from app.services.helper_client import HelperError
from app.services.nmap_parser import NmapParseError, ParsedHost, parse_nmap_xml

logger = logging.getLogger("sentinelcore.discovery")

# Consecutive misses before a host is flagged inactive. One missed scan is
# usually a host that was asleep, not a host that left.
MISSES_BEFORE_INACTIVE = 3


async def run_discovery(scan_id: uuid.UUID) -> None:
    """Background entrypoint. Owns its own session — the request's is long gone.

    Every failure path marks the scan `failed` with a readable error; a scan
    must never be left stuck in `running`.
    """
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            logger.error("scan %s vanished before it could run", scan_id)
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

        try:
            hosts = await _execute_scan(scan)
            found_hosts, found_ports = await _reconcile(db, hosts, scan)

            scan.status = ScanStatus.COMPLETED
            scan.hosts_found = found_hosts
            scan.ports_found = found_ports
            scan.finished_at = datetime.now(timezone.utc)

            await audit.record(
                db,
                action="asset.scan_completed",
                resource_type="scan",
                resource_id=str(scan.id),
                detail={"hosts_found": found_hosts, "ports_found": found_ports},
            )
            await db.commit()
            logger.info("scan %s completed: %d host(s)", scan_id, found_hosts)

        except Exception as exc:
            # Includes HelperUnavailable when the helper is killed mid-scan.
            await db.rollback()
            message = _safe_error(exc)
            logger.exception("scan %s failed", scan_id)

            scan = await db.get(Scan, scan_id)
            if scan is not None:
                scan.status = ScanStatus.FAILED
                scan.error = message
                scan.finished_at = datetime.now(timezone.utc)
                await audit.record(
                    db,
                    action="asset.scan_failed",
                    resource_type="scan",
                    resource_id=str(scan_id),
                    outcome="failure",
                    error=message,
                )
                await db.commit()


def _safe_error(exc: Exception) -> str:
    """A message safe to store and show — never a raw traceback."""
    if isinstance(exc, HelperError):
        return str(exc)[:500]
    if isinstance(exc, NmapParseError):
        return f"Could not parse scan output: {exc}"[:500]
    return f"{type(exc).__name__}: {exc}"[:500]


async def _execute_scan(scan: Scan) -> list[ParsedHost]:
    """Run the nmap op, then enrich with an ARP sweep where possible."""
    result = await helper_client.call(
        "nmap_scan",
        {
            "targets": list(scan.targets),
            "ports": scan.ports or "1-1024",
            "mode": scan.mode or "tcp_syn",
        },
    )
    hosts = parse_nmap_xml(result.get("xml", ""))

    # ARP gives MAC + vendor for on-segment hosts. Its absence is not fatal —
    # the segment may not be local, or NET_RAW may be unavailable.
    try:
        arp = await helper_client.call("arp_sweep", {"targets": list(scan.targets)}, timeout=180.0)
        by_ip = {h["ip_address"]: h.get("mac_address") for h in arp.get("hosts", [])}
        known = {h.ip_address for h in hosts}

        for host in hosts:
            if not host.mac_address and by_ip.get(host.ip_address):
                host.mac_address = by_ip[host.ip_address]

        # A host answering ARP but not nmap is still a host on the network.
        for ip, mac in by_ip.items():
            if ip not in known:
                hosts.append(ParsedHost(ip_address=ip, mac_address=mac))

    except HelperError as exc:
        logger.warning("ARP sweep unavailable, continuing without MAC data: %s", exc)

    return hosts


async def _reconcile(db: AsyncSession, hosts: list[ParsedHost], scan: Scan) -> tuple[int, int]:
    """Upsert observed hosts; age out the ones that did not answer."""
    now = datetime.now(timezone.utc)
    seen_ips = {h.ip_address for h in hosts}
    port_count = 0

    existing: dict[str, Asset] = {}
    if seen_ips:
        # Each value is cast to INET explicitly. Postgres has no implicit
        # inet = varchar comparison, and casting the parameters rather than the
        # column keeps the index on assets.ip_address usable.
        existing_result = await db.execute(
            select(Asset).where(Asset.ip_address.in_([cast(ip, INET) for ip in seen_ips]))
        )
        existing = {str(a.ip_address): a for a in existing_result.scalars().all()}

    for parsed in hosts:
        asset = existing.get(parsed.ip_address)

        if asset is None:
            asset = Asset(ip_address=parsed.ip_address, first_seen=now)
            db.add(asset)
            await db.flush()  # need asset.id for its ports

        asset.last_seen = now
        asset.is_active = True
        asset.missed_scans = 0

        # Only overwrite with information we actually have — a scan that could
        # not resolve a hostname must not erase a previously known one.
        if parsed.mac_address:
            asset.mac_address = parsed.mac_address
        if parsed.vendor:
            asset.vendor = parsed.vendor
        if parsed.hostname:
            asset.hostname = parsed.hostname
        if parsed.os_guess:
            asset.os_guess = parsed.os_guess

        port_count += await _reconcile_ports(db, asset, parsed, now)

    await _age_out_missing(db, seen_ips, now)
    return len(hosts), port_count


async def _reconcile_ports(
    db: AsyncSession, asset: Asset, parsed: ParsedHost, now: datetime
) -> int:
    if not parsed.ports:
        return 0

    result = await db.execute(select(AssetPort).where(AssetPort.asset_id == asset.id))
    existing = {(p.port, p.protocol.value): p for p in result.scalars().all()}

    for parsed_port in parsed.ports:
        key = (parsed_port.port, parsed_port.protocol)
        record = existing.get(key)

        if record is None:
            db.add(
                AssetPort(
                    asset_id=asset.id,
                    port=parsed_port.port,
                    protocol=Protocol(parsed_port.protocol),
                    state=PortState(parsed_port.state),
                    service=parsed_port.service,
                    product=parsed_port.product,
                    version=parsed_port.version,
                    first_seen=now,
                    last_seen=now,
                )
            )
        else:
            record.state = PortState(parsed_port.state)
            record.last_seen = now
            if parsed_port.service:
                record.service = parsed_port.service
            if parsed_port.product:
                record.product = parsed_port.product
            if parsed_port.version:
                record.version = parsed_port.version

    return len(parsed.ports)


async def _age_out_missing(db: AsyncSession, seen_ips: set[str], now: datetime) -> None:
    """Increment the miss counter for active assets that did not answer.

    Deliberately conservative: assets are flagged, never deleted, so the
    investigation record of what was once on this network survives.
    """
    result = await db.execute(select(Asset).where(Asset.is_active.is_(True)))
    for asset in result.scalars().all():
        if str(asset.ip_address) in seen_ips:
            continue
        asset.missed_scans += 1
        if asset.missed_scans >= MISSES_BEFORE_INACTIVE:
            asset.is_active = False
            logger.info("asset %s flagged inactive after %d misses", asset.ip_address, asset.missed_scans)
