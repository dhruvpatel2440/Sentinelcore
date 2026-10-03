"""M7 — correlation engine: rule CRUD, dry-run testing, candidates."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.correlation.evaluators import REGISTRY
from app.correlation.scoring import score_candidate
from app.db.session import get_db
from app.models.correlation import CandidateStatus, CorrelationRule, IncidentCandidate, RuleRun
from app.models.event import Severity
from app.models.user import User
from app.schemas.correlation import (
    CandidateOut,
    CandidatePreview,
    RuleCreate,
    RuleOut,
    RuleRunOut,
    RuleTestRequest,
    RuleTestResponse,
    RuleUpdate,
    SuppressRequest,
    validate_params,
)
from app.services import audit

router = APIRouter(prefix="/correlation", tags=["correlation"])


@router.get("/rules", response_model=list[RuleOut])
async def list_rules(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[RuleOut]:
    rules = (await db.execute(select(CorrelationRule).order_by(CorrelationRule.name))).scalars().all()

    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)

    out = []
    for rule in rules:
        candidates_24h = int(
            await db.scalar(
                select(func.count())
                .select_from(IncidentCandidate)
                .where(IncidentCandidate.rule_id == rule.id, IncidentCandidate.created_at >= since_24h)
            )
            or 0
        )
        last_run = await db.scalar(
            select(RuleRun).where(RuleRun.rule_id == rule.id).order_by(RuleRun.created_at.desc()).limit(1)
        )
        last_status = "error" if (last_run and last_run.error) else ("ok" if last_run else None)
        item = RuleOut.model_validate(rule, from_attributes=True)
        item.candidates_24h = candidates_24h
        item.last_run_status = last_status
        out.append(item)
    return out


@router.post("/rules", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: RuleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> RuleOut:
    rule = CorrelationRule(
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        rule_type=payload.rule_type,
        match=payload.match.model_dump(exclude_none=True),
        group_by=payload.group_by,
        window_seconds=payload.window_seconds,
        threshold=payload.threshold,
        severity=payload.severity,
        dedup_window_seconds=payload.dedup_window_seconds,
        params=payload.params,
        created_by=actor.id,
    )
    db.add(rule)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail=f"a rule named {payload.name!r} already exists") from exc

    await audit.record(
        db,
        action="correlation.rule_created",
        user=actor,
        resource_type="correlation_rule",
        resource_id=rule.id,
        detail={"name": rule.name, "rule_type": rule.rule_type.value},
        request=request,
    )
    await db.commit()
    await db.refresh(rule)
    return RuleOut.model_validate(rule, from_attributes=True)


async def _get_rule_or_404(db: AsyncSession, rule_id: uuid.UUID) -> CorrelationRule:
    rule = await db.get(CorrelationRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    return rule


@router.patch("/rules/{rule_id}", response_model=RuleOut)
async def update_rule(
    rule_id: uuid.UUID,
    payload: RuleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> RuleOut:
    rule = await _get_rule_or_404(db, rule_id)
    changes = payload.model_dump(exclude_unset=True)

    if "match" in changes and changes["match"] is not None:
        changes["match"] = payload.match.model_dump(exclude_none=True)

    # rule_type is immutable via PATCH (it determines the params shape) — only
    # re-validate params here, against the rule's existing type.
    if "params" in changes:
        try:
            changes["params"] = validate_params(rule.rule_type, changes["params"])
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors()) from exc

    for field, value in changes.items():
        setattr(rule, field, value)

    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="a rule with that name already exists") from exc

    await audit.record(
        db,
        action="correlation.rule_updated",
        user=actor,
        resource_type="correlation_rule",
        resource_id=rule.id,
        detail=changes,
        request=request,
    )
    await db.commit()
    await db.refresh(rule)
    return RuleOut.model_validate(rule, from_attributes=True)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_rule(
    rule_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("admin")),
) -> None:
    rule = await _get_rule_or_404(db, rule_id)
    await db.delete(rule)
    await audit.record(
        db,
        action="correlation.rule_deleted",
        user=actor,
        resource_type="correlation_rule",
        resource_id=rule_id,
        detail={"name": rule.name},
        request=request,
    )
    await db.commit()


@router.post("/rules/{rule_id}/test", response_model=RuleTestResponse)
async def test_rule(
    rule_id: uuid.UUID,
    payload: RuleTestRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> RuleTestResponse:
    """Evaluate a rule against a historical window WITHOUT persisting
    anything — the dry run the UI requires before a rule can be enabled."""
    rule = await _get_rule_or_404(db, rule_id)
    evaluator = REGISTRY[rule.rule_type]

    start = time.perf_counter()
    candidates, events_scanned = await evaluator.evaluate(rule, payload.from_, payload.to, db)

    previews = []
    for c in candidates:
        score = await score_candidate(c, rule.severity, rule.threshold, db)
        previews.append(
            CandidatePreview(
                group_key=c.group_key,
                first_event_ts=c.first_event_ts,
                last_event_ts=c.last_event_ts,
                event_count=c.event_count,
                severity=rule.severity,
                score=score,
                summary=c.summary,
                evidence=c.evidence(),
            )
        )

    return RuleTestResponse(
        candidates=previews,
        events_scanned=events_scanned,
        duration_ms=int((time.perf_counter() - start) * 1000),
    )


@router.get("/rules/{rule_id}/runs", response_model=list[RuleRunOut])
async def get_rule_runs(
    rule_id: uuid.UUID,
    limit: int = Query(default=20, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[RuleRunOut]:
    await _get_rule_or_404(db, rule_id)
    runs = (
        await db.execute(
            select(RuleRun).where(RuleRun.rule_id == rule_id).order_by(RuleRun.created_at.desc()).limit(limit)
        )
    ).scalars().all()
    return [RuleRunOut.model_validate(r, from_attributes=True) for r in runs]


@router.get("/candidates", response_model=list[CandidateOut])
async def list_candidates(
    status_filter: list[CandidateStatus] = Query(default=[], alias="status"),
    rule_id: uuid.UUID | None = Query(default=None),
    severity: list[Severity] = Query(default=[]),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[CandidateOut]:
    stmt = select(IncidentCandidate, CorrelationRule.name).join(
        CorrelationRule, CorrelationRule.id == IncidentCandidate.rule_id
    )
    if status_filter:
        stmt = stmt.where(IncidentCandidate.status.in_(status_filter))
    if rule_id:
        stmt = stmt.where(IncidentCandidate.rule_id == rule_id)
    if severity:
        stmt = stmt.where(IncidentCandidate.severity.in_(severity))
    if from_:
        stmt = stmt.where(IncidentCandidate.created_at >= from_)
    if to:
        stmt = stmt.where(IncidentCandidate.created_at <= to)

    stmt = stmt.order_by(IncidentCandidate.created_at.desc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()

    out = []
    for candidate, rule_name in rows:
        item = CandidateOut.model_validate(candidate, from_attributes=True)
        item.rule_name = rule_name
        out.append(item)
    return out


@router.post("/candidates/{candidate_id}/suppress", response_model=CandidateOut)
async def suppress_candidate(
    candidate_id: uuid.UUID,
    payload: SuppressRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("analyst", "admin")),
) -> CandidateOut:
    candidate = await db.get(IncidentCandidate, candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail="Candidate not found")

    candidate.status = CandidateStatus.SUPPRESSED
    candidate.suppressed_reason = payload.reason
    candidate.suppressed_by = actor.id

    await audit.record(
        db,
        action="correlation.candidate_suppressed",
        user=actor,
        resource_type="incident_candidate",
        resource_id=candidate.id,
        detail={"reason": payload.reason},
        request=request,
    )
    await db.commit()
    await db.refresh(candidate)

    rule_name = await db.scalar(select(CorrelationRule.name).where(CorrelationRule.id == candidate.rule_id))
    item = CandidateOut.model_validate(candidate, from_attributes=True)
    item.rule_name = rule_name
    return item
