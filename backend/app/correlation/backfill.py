"""Re-run a rule over a historical time range, walking it in window-sized
steps and persisting exactly as the live engine would. This is what makes
authoring a new rule tolerable: test it against real past data — usually
while `enabled=false` — before turning it loose on live traffic.

    python -m app.correlation.backfill <rule_id> <from_iso> <to_iso>
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from datetime import datetime, timedelta, timezone

from app.core.redis import close_redis, get_redis
from app.correlation.engine import run_rule
from app.db.session import SessionLocal, engine
from app.models.correlation import CorrelationRule, RuleRun


async def _load_rule(rule_id: uuid.UUID) -> CorrelationRule:
    async with SessionLocal() as db:
        rule = await db.get(CorrelationRule, rule_id)
        if rule is None:
            raise SystemExit(f"no correlation rule with id {rule_id}")
        return rule


async def backfill(rule_id: uuid.UUID, range_from: datetime, range_to: datetime) -> None:
    rule = await _load_rule(rule_id)
    redis = get_redis()

    step = timedelta(seconds=rule.window_seconds)
    if step.total_seconds() <= 0:
        raise SystemExit("rule window_seconds must be positive")

    cursor = range_from
    ticks = 0
    print(f"backfilling {rule.name!r} ({rule.rule_type.value}) from {range_from} to {range_to}")

    while cursor < range_to:
        window_now = min(cursor + step, range_to)
        await run_rule(rule, window_now, SessionLocal, redis)
        cursor = window_now
        ticks += 1

    async with SessionLocal() as db:
        runs = await db.execute(
            RuleRun.__table__.select()
            .where(RuleRun.rule_id == rule.id, RuleRun.created_at >= datetime.now(timezone.utc) - timedelta(minutes=5))
            .order_by(RuleRun.created_at.desc())
            .limit(ticks)
        )
        rows = runs.mappings().all()

    total_candidates = sum(r["candidates_created"] for r in rows)
    total_scanned = sum(r["events_scanned"] for r in rows)
    errors = [r["error"] for r in rows if r["error"]]

    print(f"done: {ticks} window(s), {total_scanned} event(s) scanned, {total_candidates} candidate(s) created")
    if errors:
        print(f"{len(errors)} window(s) errored, e.g.: {errors[0]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rule_id", type=uuid.UUID)
    parser.add_argument("range_from", type=datetime.fromisoformat)
    parser.add_argument("range_to", type=datetime.fromisoformat)
    args = parser.parse_args()

    async def _run() -> None:
        try:
            await backfill(args.rule_id, args.range_from, args.range_to)
        finally:
            await close_redis()
            await engine.dispose()

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
