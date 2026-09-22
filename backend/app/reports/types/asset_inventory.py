from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address as parse_ip
from ipaddress import ip_network
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.correlation.scoring import SENSITIVE_PORTS
from app.models.asset import Asset, AssetPort, PortState
from app.models.incident import Incident
from app.schemas.report import AssetInventoryParams

STALE_AFTER_DAYS = 30


async def build(params: dict[str, Any], db: AsyncSession) -> dict[str, Any]:
    p = AssetInventoryParams.model_validate(params)

    stmt = select(Asset).options(selectinload(Asset.ports))
    if p.is_active is not None:
        stmt = stmt.where(Asset.is_active.is_(p.is_active))

    assets = (await db.execute(stmt)).scalars().all()

    if p.cidr:
        network = ip_network(p.cidr, strict=False)
        assets = [a for a in assets if _ip_in(a.ip_address, network)]

    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=STALE_AFTER_DAYS)

    from_ts = p.from_ or (now - timedelta(days=365))
    to_ts = p.to or now

    rows = []
    for asset in sorted(assets, key=lambda a: str(a.ip_address)):
        incident_count = int(
            await db.scalar(
                select(func.count())
                .select_from(Incident)
                .where(
                    Incident.asset_id == asset.id,
                    Incident.deleted_at.is_(None),
                    Incident.opened_at >= from_ts,
                    Incident.opened_at <= to_ts,
                )
            )
            or 0
        )
        high_risk_ports = [
            port.port for port in asset.ports if port.state == PortState.OPEN and port.port in SENSITIVE_PORTS
        ]
        rows.append(
            {
                "ip_address": str(asset.ip_address),
                "hostname": asset.display_hostname,
                "mac_address": str(asset.mac_address) if asset.mac_address else None,
                "vendor": asset.vendor,
                "os_guess": asset.os_guess,
                "is_active": asset.is_active,
                "first_seen": asset.first_seen.isoformat(),
                "last_seen": asset.last_seen.isoformat(),
                "is_stale": asset.last_seen < stale_cutoff,
                "incident_count": incident_count,
                "high_risk_ports": high_risk_ports,
                "ports": [
                    {
                        "port": port.port, "protocol": port.protocol.value, "state": port.state.value,
                        "service": port.service, "product": port.product, "version": port.version,
                    }
                    for port in asset.ports
                ],
            }
        )

    return {
        "report_type": "asset_inventory",
        "params": {"is_active": p.is_active, "cidr": p.cidr},
        "total_assets": len(rows),
        "stale_count": sum(1 for r in rows if r["is_stale"]),
        "high_risk_count": sum(1 for r in rows if r["high_risk_ports"]),
        "table": rows,
    }


def _ip_in(ip_value, network) -> bool:
    try:
        return parse_ip(str(ip_value)) in network
    except ValueError:
        return False
