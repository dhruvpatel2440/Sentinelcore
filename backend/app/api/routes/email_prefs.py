"""U10 Part 7 — per-user notification preferences. Any authenticated role."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.session import get_db
from app.email.service import get_or_create_preferences
from app.email.types import LOCKED_TYPES
from app.models.email import EmailDeliveryMode, EmailDigestFrequency
from app.models.user import User
from app.schemas.email import EmailPreferencesOut, EmailPreferencesUpdate
from app.services import audit

router = APIRouter(prefix="/me/email-preferences", tags=["email"])

_LOCKED_VALUES = [t.value for t in LOCKED_TYPES]


def _to_out(prefs) -> EmailPreferencesOut:
    return EmailPreferencesOut(
        enabled=prefs.enabled,
        min_severity=prefs.min_severity,
        delivery_mode=prefs.delivery_mode.value,
        types_disabled=prefs.types_disabled,
        digest_frequency=prefs.digest_frequency.value,
        digest_hour_utc=prefs.digest_hour_utc,
        locked_types=_LOCKED_VALUES,
    )


@router.get("", response_model=EmailPreferencesOut)
async def get_preferences(db: AsyncSession = Depends(get_db), actor: User = Depends(get_current_user)) -> EmailPreferencesOut:
    prefs = await get_or_create_preferences(db, actor.id)
    await db.commit()
    return _to_out(prefs)


@router.put("", response_model=EmailPreferencesOut)
async def update_preferences(
    payload: EmailPreferencesUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(get_current_user),
) -> EmailPreferencesOut:
    prefs = await get_or_create_preferences(db, actor.id)
    changes = payload.model_dump(exclude_unset=True)

    if "enabled" in changes and changes["enabled"] is not None:
        prefs.enabled = changes["enabled"]
    if "min_severity" in changes and changes["min_severity"] is not None:
        prefs.min_severity = changes["min_severity"]
    if "delivery_mode" in changes and changes["delivery_mode"] is not None:
        prefs.delivery_mode = EmailDeliveryMode(changes["delivery_mode"])
    if "digest_frequency" in changes and changes["digest_frequency"] is not None:
        prefs.digest_frequency = EmailDigestFrequency(changes["digest_frequency"])
    if "digest_hour_utc" in changes and changes["digest_hour_utc"] is not None:
        prefs.digest_hour_utc = changes["digest_hour_utc"]
    if "types_disabled" in changes and changes["types_disabled"] is not None:
        # Locked types can never be opted out of, regardless of what is posted.
        prefs.types_disabled = [t for t in changes["types_disabled"] if t not in _LOCKED_VALUES]

    prefs.updated_at = datetime.now(timezone.utc)
    await audit.record(db, action="email.preferences_updated", user=actor, detail=changes, request=request)
    await db.commit()
    await db.refresh(prefs)
    return _to_out(prefs)
