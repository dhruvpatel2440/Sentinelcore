from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.correlation import CorrelationRule
from app.models.event import Event
from app.models.incident import Incident, IncidentEvent, IncidentHistory
from app.models.user import User
from app.schemas.report import IncidentDetailParams

LINKED_EVENTS_CAP = 500


class IncidentNotFound(ValueError):
    pass


async def build(params: dict[str, Any], db: AsyncSession) -> dict[str, Any]:
    p = IncidentDetailParams.model_validate(params)

    incident = await db.scalar(select(Incident).where(Incident.id == p.incident_id))
    if incident is None:
        raise IncidentNotFound(f"incident {p.incident_id} not found")

    asset = await db.get(Asset, incident.asset_id) if incident.asset_id else None
    rule = await db.get(CorrelationRule, incident.rule_id) if incident.rule_id else None
    assignee = await db.get(User, incident.assigned_to) if incident.assigned_to else None
    closer = await db.get(User, incident.closed_by) if incident.closed_by else None

    history_rows = (
        await db.execute(
            select(IncidentHistory, User.username)
            .outerjoin(User, User.id == IncidentHistory.user_id)
            .where(IncidentHistory.incident_id == incident.id)
            .order_by(IncidentHistory.created_at.asc())
        )
    ).all()

    linked_ids = (
        await db.execute(select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id))
    ).scalars().all()
    total_linked = len(linked_ids)
    capped_ids = linked_ids[:LINKED_EVENTS_CAP]

    events = []
    if capped_ids:
        rows = (await db.execute(select(Event).where(Event.id.in_(capped_ids)).order_by(Event.ts.asc()))).scalars().all()
        events = [
            {
                "id": e.id, "ts": e.ts.isoformat(), "severity": e.severity.value, "event_type": e.event_type.value,
                "signature": e.signature, "src_ip": str(e.src_ip) if e.src_ip else None,
                "dst_ip": str(e.dst_ip) if e.dst_ip else None,
            }
            for e in rows
        ]

    return {
        "report_type": "incident_detail",
        "params": {"incident_id": str(p.incident_id)},
        "incident": {
            "number": incident.number,
            "title": incident.title,
            "description": incident.description,
            "status": incident.status.value,
            "severity": incident.severity.value,
            "score": incident.score,
            "src_ip": str(incident.src_ip) if incident.src_ip else None,
            "dst_ip": str(incident.dst_ip) if incident.dst_ip else None,
            "opened_at": incident.opened_at.isoformat(),
            "acknowledged_at": incident.acknowledged_at.isoformat() if incident.acknowledged_at else None,
            "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
            "closed_by": closer.username if closer else None,
            "resolution_note": incident.resolution_note,
            "assignee": assignee.username if assignee else None,
            "rule_name": rule.name if rule else None,
        },
        "asset": (
            {
                "ip_address": str(asset.ip_address), "hostname": asset.display_hostname,
                "os_guess": asset.os_guess, "vendor": asset.vendor,
            }
            if asset
            else None
        ),
        "history": [
            {
                "action": h.action.value, "user": u, "from_value": h.from_value, "to_value": h.to_value,
                "note": h.note, "created_at": h.created_at.isoformat(),
            }
            for h, u in history_rows
        ],
        "events": events,
        "events_total": total_linked,
        "events_truncated": total_linked > LINKED_EVENTS_CAP,
    }
