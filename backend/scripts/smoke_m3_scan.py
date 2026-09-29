"""M3 live scan test — runs a real discovery scan and checks reconciliation.

Needs the full stack up, including the helper with a route to MONITORED_NETWORK:

    docker compose exec backend python -m scripts.smoke_m3_scan
"""

from __future__ import annotations

import os
import sys
import time

import httpx

BASE = os.getenv("SMOKE_BASE_URL", "http://localhost:8000/api")
ADMIN_USER = os.getenv("SEED_ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("SEED_ADMIN_PASSWORD", "sentinel-dev-admin-2026")

TARGET = os.getenv("SMOKE_SCAN_TARGET", "192.168.56.0/24")
PORTS = os.getenv("SMOKE_SCAN_PORTS", "22,80,443,3389,8000-8100")

_results: list[bool] = []


def check(name: str, cond: bool, extra: object = "") -> None:
    _results.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({extra})" if extra != "" else ""))


def wait_for_scan(c: httpx.Client, headers: dict, scan_id: str, timeout: int = 600) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = c.get(f"/assets/scans/{scan_id}", headers=headers).json()
        if last["status"] in ("completed", "failed"):
            return last
        time.sleep(3)
    return last or {"status": "timeout"}


def main() -> int:
    with httpx.Client(base_url=BASE, timeout=60.0) as c:
        r = c.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
        if r.status_code != 200:
            print(f"admin login failed: {r.status_code} {r.text[:200]}")
            return 1
        admin = {"Authorization": f"Bearer {r.json()['access_token']}"}

        print(f"\n-- first scan of {TARGET} ports {PORTS} --")
        r = c.post(
            "/assets/scan",
            headers=admin,
            json={"targets": [TARGET], "ports": PORTS, "mode": "tcp_connect"},
        )
        check("POST /assets/scan -> 202", r.status_code == 202, r.status_code)
        if r.status_code != 202:
            print("   body:", r.text[:400])
            return 1
        scan_id = r.json()["id"]

        print("   waiting for the scan to finish (this takes a minute)…")
        scan = wait_for_scan(c, admin, scan_id)
        check("scan reached a terminal state", scan["status"] in ("completed", "failed"), scan["status"])
        if scan["status"] == "failed":
            print("   error:", scan.get("error"))
            return 1

        check("scan completed", scan["status"] == "completed", scan["status"])
        check("scan recorded a duration", scan.get("duration_seconds") is not None,
              f"{scan.get('duration_seconds')}s")
        hosts_found = scan["hosts_found"]
        check("scan found at least one host", hosts_found > 0, f"{hosts_found} host(s)")

        print("\n-- assets were persisted --")
        listing = c.get("/assets", headers=admin).json()
        check("assets appear in the inventory", listing["total"] > 0, f"{listing['total']} asset(s)")
        for item in listing["items"][:6]:
            print(
                f"     {item['ip_address']:<16} "
                f"mac={item['mac_address'] or '-':<18} "
                f"ports={item['open_port_count']} "
                f"host={item['hostname'] or '-'}"
            )

        first_ids = {a["id"] for a in listing["items"]}
        first_seen = {a["ip_address"]: a["first_seen"] for a in listing["items"]}

        print("\n-- second scan: must reconcile, not duplicate --")
        r = c.post(
            "/assets/scan",
            headers=admin,
            json={"targets": [TARGET], "ports": PORTS, "mode": "tcp_connect"},
        )
        check("second scan accepted", r.status_code == 202, r.status_code)
        scan2 = wait_for_scan(c, admin, r.json()["id"])
        check("second scan completed", scan2["status"] == "completed", scan2["status"])

        listing2 = c.get("/assets", headers=admin).json()
        second_ids = {a["id"] for a in listing2["items"]}

        check(
            "no duplicate assets created",
            listing2["total"] == listing["total"],
            f"{listing['total']} -> {listing2['total']}",
        )
        check("asset IDs are stable across scans", first_ids == second_ids)
        check(
            "first_seen preserved (not reset)",
            all(a["first_seen"] == first_seen.get(a["ip_address"]) for a in listing2["items"]),
        )
        check(
            "last_seen advanced",
            any(a["last_seen"] >= first_seen.get(a["ip_address"], "") for a in listing2["items"]),
        )

        print("\n-- concurrent scan is refused --")
        r1 = c.post("/assets/scan", headers=admin, json={"targets": [TARGET], "ports": "80"})
        r2 = c.post("/assets/scan", headers=admin, json={"targets": [TARGET], "ports": "80"})
        check("second concurrent scan -> 409", 409 in (r1.status_code, r2.status_code),
              f"{r1.status_code}/{r2.status_code}")
        # Let the accepted one drain so the suite leaves a clean slate.
        for resp in (r1, r2):
            if resp.status_code == 202:
                wait_for_scan(c, admin, resp.json()["id"])

    passed, total = sum(_results), len(_results)
    print("\n" + "=" * 52)
    print(f"  {passed}/{total} checks passed")
    print("=" * 52)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
