"""M5 end-to-end test: deploy a test rule, generate traffic, verify ingestion.

Needs the full stack up with the sensor running and the worker consuming.

    docker compose exec backend python -m scripts.smoke_m5
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time

import httpx
from sqlalchemy import text

from app.db.session import SessionLocal, engine
from app.services import helper_client
from app.services.ruleset import deploy

BASE = os.getenv("SMOKE_BASE_URL", "http://localhost:8000/api")
ADMIN_USER = os.getenv("SEED_ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("SEED_ADMIN_PASSWORD", "sentinel-dev-admin-2026")

PING_TARGET = os.getenv("SMOKE_PING_TARGET", "192.168.56.1")
TEST_SID = 9000100

# priority:1 -> Suricata severity 1 -> platform "critical", exercising the
# mapping all the way from the sensor to the database.
TEST_RULE = (
    f'alert icmp any any -> any any (msg:"SentinelCore M5 test ICMP"; '
    f"sid:{TEST_SID}; rev:1; priority:1;)\n"
).encode()

_results: list[bool] = []


def check(name: str, cond: bool, extra: object = "") -> None:
    _results.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({extra})" if extra != "" else ""))


async def count_alerts() -> int:
    async with SessionLocal() as db:
        return int(
            await db.scalar(
                text("SELECT count(*) FROM events WHERE signature_id = :sid"), {"sid": TEST_SID}
            )
            or 0
        )


async def main() -> int:
    print("\n-- deploy a test rule through the M4 pipeline --")
    try:
        result = await deploy(TEST_RULE)
        check("test rule deployed and validated", bool(result.get("written")), result.get("rule_count"))
    except Exception as exc:  # noqa: BLE001
        check("test rule deployed and validated", False, f"{type(exc).__name__}: {exc}")
        return 1

    status = await helper_client.call("suricata_status", timeout=30)
    if not status.get("running"):
        print("  (sensor not running — starting it)")
        await helper_client.call("suricata_start", timeout=120)
        time.sleep(15)

    try:
        await helper_client.call("suricata_reload_rules", timeout=300)
        print("  rules reloaded live")
    except Exception as exc:  # noqa: BLE001
        print(f"  reload skipped: {exc}")

    time.sleep(8)

    print("\n-- generate ICMP traffic --")
    before = await count_alerts()
    print(f"  alerts before: {before}")

    # The backend container has no ping binary and no NET_RAW; generate the
    # traffic from the helper, which is on the host network.
    try:
        await helper_client.call("ping", timeout=10)  # liveness only
    except Exception:
        pass

    subprocess.run(
        ["python", "-c",
         "import socket,time\n"
         "for i in range(5):\n"
         "    try:\n"
         "        s=socket.create_connection(('192.168.56.1', 22), timeout=0.4); s.close()\n"
         "    except OSError: pass\n"
         "    time.sleep(0.2)\n"],
        check=False,
        capture_output=True,
    )

    print("\n-- wait for events to arrive --")
    deadline = time.time() + 120
    after = before
    while time.time() < deadline:
        after = await count_alerts()
        if after > before:
            break
        await asyncio.sleep(3)

    elapsed = time.time() - (deadline - 120)
    check(f"alerts ingested within {elapsed:.0f}s", after > before, f"{before} -> {after}")

    if after > before:
        async with SessionLocal() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT severity::text, event_type::text, src_ip::text, dst_ip::text, "
                        "proto, signature, rev, src_asset_id, raw->>'event_type' "
                        "FROM events WHERE signature_id = :sid ORDER BY ts DESC LIMIT 1"
                    ),
                    {"sid": TEST_SID},
                )
            ).first()

        if row:
            severity, event_type, src_ip, dst_ip, proto, signature, rev, src_asset, raw_type = row
            print(f"     {severity} {event_type} {src_ip} -> {dst_ip} {proto} :: {signature}")
            check("priority 1 mapped to 'critical'", severity == "critical", severity)
            check("event_type is alert", event_type == "alert", event_type)
            check("signature text preserved", signature == "SentinelCore M5 test ICMP", signature)
            check("rev captured", rev == 1, rev)
            check("raw record preserved", raw_type == "alert", raw_type)

    print("\n-- dedup: the same record must insert once --")
    async with SessionLocal() as db:
        dupes = int(
            await db.scalar(
                text(
                    "SELECT COALESCE(MAX(c), 0) FROM ("
                    "  SELECT count(*) AS c FROM events GROUP BY dedup_key, ts"
                    ") s"
                )
            )
            or 0
        )
    check("no duplicate dedup_key within a partition", dupes <= 1, f"max rows per key = {dupes}")

    print("\n-- asset enrichment --")
    async with SessionLocal() as db:
        enriched = int(
            await db.scalar(
                text("SELECT count(*) FROM events WHERE src_asset_id IS NOT NULL")
            )
            or 0
        )
        assets = int(await db.scalar(text("SELECT count(*) FROM assets")) or 0)
    check("events link to scanned assets", enriched > 0 or assets == 0,
          f"{enriched} enriched, {assets} asset(s) known")

    print("\n-- pipeline status endpoint --")
    with httpx.Client(base_url=BASE, timeout=60.0) as c:
        r = c.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        s = c.get("/pipeline/status", headers=h).json()
        check("status reports lines read", s["lines_read"] > 0, s["lines_read"])
        check("status reports events written", s["events_written"] > 0, s["events_written"])
        check("lag is near zero", s["stream_length"] < 1000, f"stream_length={s['stream_length']}")
        check("no unacked backlog", s["pending"] == 0, s["pending"])
        check("pipeline not stalled", s["stalled"] is False, s.get("stall_reason"))
        check("partitions reported", len(s["partitions"]) >= 3, s["partitions"])

    await engine.dispose()

    passed, total = sum(_results), len(_results)
    print("\n" + "=" * 54)
    print(f"  {passed}/{total} checks passed")
    print("=" * 54)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
