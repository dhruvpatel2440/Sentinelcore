from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.correlation import CorrelationRule
from app.models.incident import TERMINAL_STATUSES, Incident
from app.models.user import User
from app.schemas.report import IncidentSummaryParams


def _val(x: Any) -> str:
    return x.value if hasattr(x, "value") else x


async def build(params: dict[str, Any], db: AsyncSession) -> dict[str, Any]:
    p = IncidentSummaryParams.model_validate(params)

    stmt = select(Incident).where(
        Incident.deleted_at.is_(None), Incident.opened_at >= p.from_, Incident.opened_at <= p.to
    )
    if p.severity:
        stmt = stmt.where(Incident.severity.in_(p.severity))
    if p.status:
        stmt = stmt.where(Incident.status.in_(p.status))

    incidents = (await db.execute(stmt.order_by(Incident.opened_at.desc()))).scalars().all()

    totals_by_severity: dict[str, int] = {}
    totals_by_status: dict[str, int] = {}
    ack_deltas: list[float] = []
    resolve_deltas: list[float] = []
    rule_counts: dict[str, int] = {}
    asset_counts: dict[str, int] = {}
    src_ip_counts: dict[str, int] = {}
    opened_by_day: dict[str, int] = {}
    closed_by_day: dict[str, int] = {}

    for inc in incidents:
        sev, stat = _val(inc.severity), _val(inc.status)
        totals_by_severity[sev] = totals_by_severity.get(sev, 0) + 1
        totals_by_status[stat] = totals_by_status.get(stat, 0) + 1
        if inc.acknowledged_at:
            ack_deltas.append((inc.acknowledged_at - inc.opened_at).total_seconds())
        if inc.closed_at:
            resolve_deltas.append((inc.closed_at - inc.opened_at).total_seconds())
        if inc.rule_id:
            rule_counts[str(inc.rule_id)] = rule_counts.get(str(inc.rule_id), 0) + 1
        if inc.asset_id:
            asset_counts[str(inc.asset_id)] = asset_counts.get(str(inc.asset_id), 0) + 1
        if inc.src_ip:
            src_ip_counts[str(inc.src_ip)] = src_ip_counts.get(str(inc.src_ip), 0) + 1

        day = inc.opened_at.date().isoformat()
        opened_by_day[day] = opened_by_day.get(day, 0) + 1
        if inc.closed_at:
            cday = inc.closed_at.date().isoformat()
            closed_by_day[cday] = closed_by_day.get(cday, 0) + 1

    async def _names(ids: dict[str, int], model, name_attr: str, limit: int = 5) -> list[dict]:
        top = sorted(ids.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        out = []
        for id_str, count in top:
            obj = await db.get(model, id_str)
            name = getattr(obj, name_attr, None) if obj else None
            out.append({"id": id_str, "name": name or id_str, "count": count})
        return out

    top_rules = await _names(rule_counts, CorrelationRule, "name")
    top_assets = await _names(asset_counts, Asset, "display_hostname")
    top_src_ips = sorted(src_ip_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

    assignee_ids = {inc.assigned_to for inc in incidents if inc.assigned_to}
    assignees = {}
    for uid in assignee_ids:
        u = await db.get(User, uid)
        assignees[str(uid)] = u.username if u else "unknown"

    days_span = max((p.to - p.from_).days, 1)
    timeline_days = sorted(set(opened_by_day) | set(closed_by_day))

    return {
        "report_type": "incident_summary",
        "params": {"from": p.from_.isoformat(), "to": p.to.isoformat(), "severity": [s.value for s in p.severity], "status": [s.value for s in p.status]},
        "totals_by_severity": totals_by_severity,
        "totals_by_status": totals_by_status,
        "total_incidents": len(incidents),
        "mtta_seconds": sum(ack_deltas) / len(ack_deltas) if ack_deltas else None,
        "mttr_seconds": sum(resolve_deltas) / len(resolve_deltas) if resolve_deltas else None,
        "opened_vs_closed": {"days": timeline_days, "opened": opened_by_day, "closed": closed_by_day},
        "top_rules": top_rules,
        "top_assets": top_assets,
        "top_src_ips": [{"ip": ip, "count": c} for ip, c in top_src_ips],
        "days_span": days_span,
        "table": [
            {
                "number": inc.number,
                "title": inc.title,
                "severity": _val(inc.severity),
                "status": _val(inc.status),
                "opened_at": inc.opened_at.isoformat(),
                "closed_at": inc.closed_at.isoformat() if inc.closed_at else None,
                "assignee": assignees.get(str(inc.assigned_to)) if inc.assigned_to else None,
            }
            for inc in incidents
        ],
    }
