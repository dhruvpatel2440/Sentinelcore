"""M8 incident status state machine — the one place a transition is legal or
not. Never re-implemented in the UI; the UI only reflects what this module
allows.

    new ──▶ triage ──▶ investigating ──▶ contained ──▶ resolved
     │         │             │                │            │
     └─────────┴─────────────┴────────────────┴──▶ false_positive
                                                        │
    resolved / false_positive ──▶ (admin only) ──▶ investigating   [reopen]
"""

from __future__ import annotations

from app.models.incident import TERMINAL_STATUSES, IncidentStatus

FORWARD_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.NEW: frozenset({IncidentStatus.TRIAGE, IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.TRIAGE: frozenset({IncidentStatus.INVESTIGATING, IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.INVESTIGATING: frozenset({IncidentStatus.CONTAINED, IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.CONTAINED: frozenset({IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.RESOLVED: frozenset(),
    IncidentStatus.FALSE_POSITIVE: frozenset(),
}

REOPEN_TARGET = IncidentStatus.INVESTIGATING


class IllegalTransition(ValueError):
    def __init__(self, current: IncidentStatus, target: IncidentStatus):
        self.current = current
        self.target = target
        super().__init__(f"cannot move from {current.value!r} to {target.value!r}")


class ReopenRequiresAdmin(ValueError):
    def __init__(self, current: IncidentStatus):
        self.current = current
        super().__init__(f"reopening from {current.value!r} requires admin")


def is_reopen(current: IncidentStatus, target: IncidentStatus) -> bool:
    return current in TERMINAL_STATUSES and target == REOPEN_TARGET


def validate_transition(current: IncidentStatus, target: IncidentStatus, *, is_admin: bool) -> None:
    """Raises IllegalTransition or ReopenRequiresAdmin; returns None if legal."""
    if current == target:
        raise IllegalTransition(current, target)

    if is_reopen(current, target):
        if not is_admin:
            raise ReopenRequiresAdmin(current)
        return

    if target not in FORWARD_TRANSITIONS.get(current, frozenset()):
        raise IllegalTransition(current, target)


def requires_resolution_note(target: IncidentStatus) -> bool:
    return target in TERMINAL_STATUSES


def is_forward_move_from_new(current: IncidentStatus, target: IncidentStatus) -> bool:
    """Any move out of `new` starts the clock on acknowledgement (MTTA)."""
    return current == IncidentStatus.NEW and target != current


def can_assign(*, is_admin: bool, actor_id, target_user_id, current_assignee) -> bool:
    """An analyst may assign to themselves or unassign their own incident.
    Anything else touching assignment — taking someone else's incident,
    reassigning it to a third party, or unassigning someone else — is
    admin-only."""
    if is_admin:
        return True
    is_self_assign = target_user_id == actor_id
    is_own_unassign = target_user_id is None and current_assignee == actor_id
    return is_self_assign or is_own_unassign
