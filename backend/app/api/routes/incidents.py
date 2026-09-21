"""M8 — incident management: queue, lifecycle, linked events, history."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.db.session import get_db
from app.models.asset import Asset
from app.models.correlation import CorrelationRule
from app.models.event import Event, Severity
from app.models.incident import TERMINAL_STATUSES, HistoryAction, Incident, IncidentEvent, IncidentHistory, IncidentStatus
from app.models.user import User
from app.schemas.incident import (
    AssignRequest,
    CommentRequest,
    EventLinkRequest,
    IncidentCreate,
    IncidentDetailOut,
    IncidentHistoryOut,
    IncidentListOut,
    IncidentOut,
    IncidentUpdate,
    LinkedEventOut,
    StatsSummaryOut,
    StatusChangeRequest,
)
from app.services import audit
from app.services.incident_state import (
    IllegalTransition,
    ReopenRequiresAdmin,
    can_assign,
    is_forward_move_from_new,
    is_reopen,
    requires_resolution_note,
    validate_transition,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])

_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}


def _encode_cursor(value, id_: uuid.UUID) -> str:
    payload = json.dumps([value, str(id_)]).encode()
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _decode_cursor(cursor: str) -> tuple:
    try:
        value, id_ = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return value, uuid.UUID(id_)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail="cursor is malformed") from exc


async def _get_incident_or_404(db: AsyncSession, incident_id: uuid.UUID) -> Incident:
    incident = await db.scalar(select(Incident).where(Incident.id == incident_id, Incident.deleted_at.is_(None)))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def _check_version(incident: Incident, expected_version: int) -> None:
    if incident.version != expected_version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"version conflict: incident is at version {incident.version}, request expected {expected_version}",
        )


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------


@router.get("", response_model=IncidentListOut)
async def list_incidents(
    status_filter: list[IncidentStatus] = Query(default=[], alias="status"),
    severity: list[Severity] = Query(default=[]),
    assigned_to: str | None = Query(default=None, description='a user UUID, "me", or "unassigned"'),
    q: str | None = Query(default=None, max_length=255),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    asset_id: uuid.UUID | None = Query(default=None),
    sort: str = Query(default="opened_at", pattern="^(opened_at|severity|score)$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> IncidentListOut:
    stmt = select(Incident).where(Incident.deleted_at.is_(None))

    if status_filter:
        stmt = stmt.where(Incident.status.in_(status_filter))
    else:
        stmt = stmt.where(Incident.status.notin_(TERMINAL_STATUSES))

    if severity:
        stmt = stmt.where(Incident.severity.in_(severity))

    if assigned_to == "me":
        stmt = stmt.where(Incident.assigned_to == user.id)
    elif assigned_to == "unassigned":
        stmt = stmt.where(Incident.assigned_to.is_(None))
    elif assigned_to:
        stmt = stmt.where(Incident.assigned_to == uuid.UUID(assigned_to))

    if q:
        pattern = f"%{q}%"
        conditions = [Incident.title.ilike(pattern), cast(Incident.src_ip, String).ilike(pattern)]
        if q.strip().lstrip("INC-").isdigit():
            conditions.append(Incident.number == int(q.strip().lstrip("INC-")))
        stmt = stmt.where(or_(*conditions))

    if from_:
        stmt = stmt.where(Incident.opened_at >= from_)
    if to:
        stmt = stmt.where(Incident.opened_at <= to)
    if asset_id:
        stmt = stmt.where(Incident.asset_id == asset_id)

    sort_column = {"opened_at": Incident.opened_at, "severity": Incident.severity, "score": Incident.score}[sort]
    desc = order == "desc"

    if cursor:
        raw_value, cursor_id = _decode_cursor(cursor)
        if sort == "opened_at":
            cursor_value = datetime.fromisoformat(raw_value)
        elif sort == "severity":
            cursor_value = Severity(raw_value)
        else:
            cursor_value = raw_value
        cmp = (sort_column, Incident.id) < (cursor_value, cursor_id) if desc else (sort_column, Incident.id) > (
            cursor_value, cursor_id
        )
        stmt = stmt.where(cmp)

    order_clause = (sort_column.desc(), Incident.id.desc()) if desc else (sort_column.asc(), Incident.id.asc())
    stmt = stmt.order_by(*order_clause).limit(limit + 1)

    rows = (await db.execute(stmt)).scalars().all()
    has_more = len(rows) > limit
    rows = rows[:limit]

    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        raw_value = last.opened_at.isoformat() if sort == "opened_at" else (
            last.severity.value if sort == "severity" else last.score
        )
        next_cursor = _encode_cursor(raw_value, last.id)

    return IncidentListOut(
        items=[IncidentOut.model_validate(r, from_attributes=True) for r in rows],
        next_cursor=next_cursor,
        has_more=has_more,
    )


@router.get("/stats/summary", response_model=StatsSummaryOut)
async def stats_summary(
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> StatsSummaryOut:
    to_ts = to or datetime.now(timezone.utc)
    from_ts = from_ or (to_ts - timedelta(days=30))

    open_rows = await db.execute(
        select(Incident.severity, func.count())
        .where(Incident.deleted_at.is_(None), Incident.status.notin_(TERMINAL_STATUSES))
        .group_by(Incident.severity)
    )
    open_by_severity = {sev.value: count for sev, count in open_rows.all()}

    unassigned_count = int(
        await db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(
                Incident.deleted_at.is_(None),
                Incident.status.notin_(TERMINAL_STATUSES),
                Incident.assigned_to.is_(None),
            )
        )
        or 0
    )

    mtta = await db.scalar(
        select(func.avg(func.extract("epoch", Incident.acknowledged_at - Incident.opened_at)))
        .where(
            Incident.deleted_at.is_(None),
            Incident.acknowledged_at.is_not(None),
            Incident.opened_at >= from_ts,
            Incident.opened_at <= to_ts,
        )
    )
    mttr = await db.scalar(
        select(func.avg(func.extract("epoch", Incident.closed_at - Incident.opened_at)))
        .where(
            Incident.deleted_at.is_(None),
            Incident.closed_at.is_not(None),
            Incident.opened_at >= from_ts,
            Incident.opened_at <= to_ts,
        )
    )

    top_rules_rows = await db.execute(
        select(CorrelationRule.id, CorrelationRule.name, func.count(Incident.id).label("n"))
        .join(Incident, Incident.rule_id == CorrelationRule.id)
        .where(Incident.deleted_at.is_(None), Incident.opened_at >= from_ts, Incident.opened_at <= to_ts)
        .group_by(CorrelationRule.id, CorrelationRule.name)
        .order_by(func.count(Incident.id).desc())
        .limit(5)
    )
    top_rules = [{"rule_id": str(rid), "name": name, "count": n} for rid, name, n in top_rules_rows.all()]

    return StatsSummaryOut(
        open_by_severity=open_by_severity,
        unassigned_count=unassigned_count,
        mtta_seconds=float(mtta) if mtta is not None else None,
        mttr_seconds=float(mttr) if mttr is not None else None,
        top_rules=top_rules,
    )


# ---------------------------------------------------------------------------
# Detail and mutations
# ---------------------------------------------------------------------------


@router.get("/{incident_id}", response_model=IncidentDetailOut)
async def get_incident(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> IncidentDetailOut:
    incident = await _get_incident_or_404(db, incident_id)

    assignee = await db.get(User, incident.assigned_to) if incident.assigned_to else None
    rule = await db.get(CorrelationRule, incident.rule_id) if incident.rule_id else None
    asset = await db.get(Asset, incident.asset_id) if incident.asset_id else None

    history_rows = (
        await db.execute(
            select(IncidentHistory, User.username)
            .outerjoin(User, User.id == IncidentHistory.user_id)
            .where(IncidentHistory.incident_id == incident_id)
            .order_by(IncidentHistory.created_at.desc())
            .limit(20)
        )
    ).all()

    return IncidentDetailOut(
        **IncidentOut.model_validate(incident, from_attributes=True).model_dump(),
        assignee_username=assignee.username if assignee else None,
        rule_name=rule.name if rule else None,
        asset_hostname=asset.display_hostname if asset else None,
        recent_history=[
            IncidentHistoryOut.model_validate(h, from_attributes=True).model_copy(update={"username": u})
            for h, u in history_rows
        ],
    )


@router.post("", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
async def create_incident(
    payload: IncidentCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> IncidentOut:
    first_ts = last_ts = None
    if payload.event_ids:
        span = (
            await db.execute(select(func.min(Event.ts), func.max(Event.ts)).where(Event.id.in_(payload.event_ids)))
        ).first()
        first_ts, last_ts = span

    incident = Incident(
        title=payload.title,
        description=payload.description,
        status=IncidentStatus.NEW,
        severity=payload.severity,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        asset_id=payload.asset_id,
        event_count=len(payload.event_ids),
        first_event_ts=first_ts,
        last_event_ts=last_ts,
    )
    db.add(incident)
    await db.flush()

    for event_id in payload.event_ids:
        db.add(IncidentEvent(incident_id=incident.id, event_id=event_id, linked_by=actor.id))

    db.add(IncidentHistory(incident_id=incident.id, user_id=actor.id, action=HistoryAction.CREATED))

    await audit.record(
        db, action="incident.created", user=actor, resource_type="incident", resource_id=incident.id,
        detail={"title": incident.title}, request=request,
    )
    await db.commit()
    await db.refresh(incident)
    return IncidentOut.model_validate(incident, from_attributes=True)


@router.patch("/{incident_id}", response_model=IncidentOut)
async def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> IncidentOut:
    incident = await _get_incident_or_404(db, incident_id)
    _check_version(incident, payload.version)

    changes = payload.model_dump(exclude_unset=True, exclude={"version"})

    if "severity" in changes and changes["severity"] != incident.severity:
        db.add(
            IncidentHistory(
                incident_id=incident.id, user_id=actor.id, action=HistoryAction.SEVERITY_CHANGED,
                from_value=incident.severity.value, to_value=changes["severity"].value,
            )
        )
    if "assigned_to" in changes and changes["assigned_to"] != incident.assigned_to:
        db.add(
            IncidentHistory(
                incident_id=incident.id, user_id=actor.id, action=HistoryAction.ASSIGNED,
                from_value=str(incident.assigned_to) if incident.assigned_to else None,
                to_value=str(changes["assigned_to"]) if changes["assigned_to"] else None,
            )
        )

    for field, value in changes.items():
        setattr(incident, field, value)
    incident.version += 1

    await audit.record(
        db, action="incident.updated", user=actor, resource_type="incident", resource_id=incident.id,
        detail={k: str(v) for k, v in changes.items()}, request=request,
    )
    await db.commit()
    await db.refresh(incident)
    return IncidentOut.model_validate(incident, from_attributes=True)


@router.post("/{incident_id}/status", response_model=IncidentOut)
async def change_status(
    incident_id: uuid.UUID,
    payload: StatusChangeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> IncidentOut:
    incident = await _get_incident_or_404(db, incident_id)
    _check_version(incident, payload.version)

    current = incident.status
    target = payload.status

    try:
        validate_transition(current, target, is_admin=actor.role.value == "admin")
    except ReopenRequiresAdmin as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except IllegalTransition as exc:
        raise HTTPException(status_code=409, detail=f"illegal transition: {exc.current.value} -> {exc.target.value}") from exc

    if requires_resolution_note(target) and not (payload.note and payload.note.strip()):
        raise HTTPException(status_code=422, detail="resolution_note (note) is required to close an incident")

    if is_forward_move_from_new(current, target) and incident.acknowledged_at is None:
        incident.acknowledged_at = datetime.now(timezone.utc)

    reopening = is_reopen(current, target)
    entering_terminal = target in TERMINAL_STATUSES

    if entering_terminal:
        incident.closed_at = datetime.now(timezone.utc)
        incident.closed_by = actor.id
        incident.resolution_note = payload.note
    elif reopening:
        incident.closed_at = None
        incident.closed_by = None

    incident.status = target
    incident.version += 1

    action = HistoryAction.REOPENED if reopening else (HistoryAction.CLOSED if entering_terminal else HistoryAction.STATUS_CHANGED)
    db.add(
        IncidentHistory(
            incident_id=incident.id, user_id=actor.id, action=action,
            from_value=current.value, to_value=target.value, note=payload.note,
        )
    )

    await audit.record(
        db, action="incident.status_changed", user=actor, resource_type="incident", resource_id=incident.id,
        detail={"from": current.value, "to": target.value}, request=request,
    )
    await db.commit()
    await db.refresh(incident)
    return IncidentOut.model_validate(incident, from_attributes=True)


@router.post("/{incident_id}/assign", response_model=IncidentOut)
async def assign_incident(
    incident_id: uuid.UUID,
    payload: AssignRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> IncidentOut:
    incident = await _get_incident_or_404(db, incident_id)
    _check_version(incident, payload.version)

    if not can_assign(
        is_admin=actor.role.value == "admin",
        actor_id=actor.id,
        target_user_id=payload.user_id,
        current_assignee=incident.assigned_to,
    ):
        raise HTTPException(status_code=403, detail="Only an admin may reassign another analyst's incident")

    db.add(
        IncidentHistory(
            incident_id=incident.id, user_id=actor.id, action=HistoryAction.ASSIGNED,
            from_value=str(incident.assigned_to) if incident.assigned_to else None,
            to_value=str(payload.user_id) if payload.user_id else None,
        )
    )
    incident.assigned_to = payload.user_id
    incident.version += 1

    await audit.record(
        db, action="incident.assigned", user=actor, resource_type="incident", resource_id=incident.id,
        detail={"assigned_to": str(payload.user_id) if payload.user_id else None}, request=request,
    )
    await db.commit()
    await db.refresh(incident)
    return IncidentOut.model_validate(incident, from_attributes=True)


@router.post("/{incident_id}/comments", response_model=IncidentHistoryOut, status_code=status.HTTP_201_CREATED)
async def add_comment(
    incident_id: uuid.UUID,
    payload: CommentRequest,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> IncidentHistoryOut:
    await _get_incident_or_404(db, incident_id)
    entry = IncidentHistory(incident_id=incident_id, user_id=actor.id, action=HistoryAction.COMMENTED, note=payload.note)
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return IncidentHistoryOut.model_validate(entry, from_attributes=True).model_copy(update={"username": actor.username})


# ---------------------------------------------------------------------------
# Linked events
# ---------------------------------------------------------------------------


async def _recompute_span(db: AsyncSession, incident: Incident) -> None:
    linked_ids = (await db.execute(select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id))).scalars().all()
    incident.event_count = len(linked_ids)
    if not linked_ids:
        incident.first_event_ts = None
        incident.last_event_ts = None
        return
    span = (await db.execute(select(func.min(Event.ts), func.max(Event.ts)).where(Event.id.in_(linked_ids)))).first()
    incident.first_event_ts, incident.last_event_ts = span


@router.get("/{incident_id}/events", response_model=list[LinkedEventOut])
async def list_linked_events(
    incident_id: uuid.UUID,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[LinkedEventOut]:
    await _get_incident_or_404(db, incident_id)
    rows = (
        await db.execute(
            select(Event, IncidentEvent.linked_by, IncidentEvent.linked_at)
            .join(IncidentEvent, IncidentEvent.event_id == Event.id)
            .where(IncidentEvent.incident_id == incident_id)
            .order_by(IncidentEvent.linked_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return [
        LinkedEventOut(
            id=e.id, ts=e.ts, event_type=e.event_type.value, severity=e.severity, signature=e.signature,
            src_ip=e.src_ip, dst_ip=e.dst_ip, linked_by=linked_by, linked_at=linked_at,
        )
        for e, linked_by, linked_at in rows
    ]


@router.post("/{incident_id}/events", response_model=IncidentOut)
async def link_events(
    incident_id: uuid.UUID,
    payload: EventLinkRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> IncidentOut:
    incident = await _get_incident_or_404(db, incident_id)

    for event_id in payload.event_ids:
        exists = await db.scalar(
            select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident_id, IncidentEvent.event_id == event_id)
        )
        if not exists:
            db.add(IncidentEvent(incident_id=incident_id, event_id=event_id, linked_by=actor.id))

    await db.flush()
    await _recompute_span(db, incident)
    incident.version += 1

    db.add(
        IncidentHistory(
            incident_id=incident.id, user_id=actor.id, action=HistoryAction.EVENTS_LINKED,
            note=f"linked {len(payload.event_ids)} event(s)",
        )
    )
    await audit.record(
        db, action="incident.events_linked", user=actor, resource_type="incident", resource_id=incident.id,
        detail={"event_ids": payload.event_ids}, request=request,
    )
    await db.commit()
    await db.refresh(incident)
    return IncidentOut.model_validate(incident, from_attributes=True)


@router.delete("/{incident_id}/events/{event_id}", response_model=IncidentOut)
async def unlink_event(
    incident_id: uuid.UUID,
    event_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> IncidentOut:
    incident = await _get_incident_or_404(db, incident_id)
    link = await db.get(IncidentEvent, {"incident_id": incident_id, "event_id": event_id})
    if link is None:
        raise HTTPException(status_code=404, detail="That event is not linked to this incident")

    await db.delete(link)
    await db.flush()
    await _recompute_span(db, incident)
    incident.version += 1

    db.add(
        IncidentHistory(
            incident_id=incident.id, user_id=actor.id, action=HistoryAction.EVENTS_UNLINKED,
            note=f"unlinked event {event_id}",
        )
    )
    await audit.record(
        db, action="incident.events_unlinked", user=actor, resource_type="incident", resource_id=incident.id,
        detail={"event_id": event_id}, request=request,
    )
    await db.commit()
    await db.refresh(incident)
    return IncidentOut.model_validate(incident, from_attributes=True)


@router.get("/{incident_id}/history", response_model=list[IncidentHistoryOut])
async def get_history(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[IncidentHistoryOut]:
    await _get_incident_or_404(db, incident_id)
    rows = (
        await db.execute(
            select(IncidentHistory, User.username)
            .outerjoin(User, User.id == IncidentHistory.user_id)
            .where(IncidentHistory.incident_id == incident_id)
            .order_by(IncidentHistory.created_at.asc())
        )
    ).all()
    return [
        IncidentHistoryOut.model_validate(h, from_attributes=True).model_copy(update={"username": u})
        for h, u in rows
    ]


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_incident(
    incident_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> None:
    incident = await _get_incident_or_404(db, incident_id)
    incident.deleted_at = datetime.now(timezone.utc)
    await audit.record(
        db, action="incident.deleted", user=actor, resource_type="incident", resource_id=incident.id,
        detail={"number": incident.number}, request=request,
    )
    await db.commit()
