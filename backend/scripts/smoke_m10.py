"""M10 smoke test — firewall containment: guard refusals, TTL bounds, RBAC,
apply/revoke against the live helper.

    docker compose exec backend python -m scripts.smoke_m10
"""

from __future__ import annotations

import os
import sys
import time

import httpx

BASE = os.getenv("SMOKE_BASE_URL", "http://localhost:8000/api")
ADMIN_USER = os.getenv("SEED_ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("SEED_ADMIN_PASSWORD", "sentinel-dev-admin-2026")

VIEWER_USER = "smoke_fw_viewer"
VIEWER_PASS = "smoke-viewer-pass-123456"
ANALYST_USER = "smoke_fw_analyst"
ANALYST_PASS = "smoke-analyst-pass-123456"

_results: list[bool] = []


def check(name: str, cond: bool, extra: object = "") -> None:
    _results.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({extra})" if extra != "" else ""))


def main() -> int:
    with httpx.Client(base_url=BASE, timeout=60.0) as c:
        r = c.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
        if r.status_code != 200:
            print(f"admin login failed: {r.status_code} {r.text}")
            return 1
        admin = {"Authorization": f"Bearer {r.json()['access_token']}"}

        for user, pw, role in [(VIEWER_USER, VIEWER_PASS, "viewer"), (ANALYST_USER, ANALYST_PASS, "analyst")]:
            c.post("/users", headers=admin, json={"username": user, "password": pw, "role": role})
        viewer = {"Authorization": "Bearer " + c.post("/auth/login", json={"username": VIEWER_USER, "password": VIEWER_PASS}).json()["access_token"]}
        analyst = {"Authorization": "Bearer " + c.post("/auth/login", json={"username": ANALYST_USER, "password": ANALYST_PASS}).json()["access_token"]}

        print("\n-- guard refusals --")
        r = c.post("/firewall/precheck", headers=admin, json={"target": "192.168.56.102"})
        check("precheck refuses the platform's own IP", r.status_code == 200 and r.json()["allowed"] is False, r.json())

        r = c.post(
            "/firewall/actions", headers=admin,
            json={"target": "192.168.56.102/32", "direction": "inbound", "ttl_seconds": 300, "reason": "smoke: self-block attempt"},
        )
        check("blocking own IP -> 422", r.status_code == 422, r.status_code)

        r = c.post(
            "/firewall/actions", headers=admin,
            json={"target": "8.8.8.8/32", "direction": "inbound", "ttl_seconds": 300, "reason": "smoke: out-of-scope"},
        )
        check("blocking out-of-monitored-network target -> 422", r.status_code == 422, r.status_code)

        print("\n-- TTL bounds (pydantic) --")
        r = c.post(
            "/firewall/actions", headers=admin,
            json={"target": "192.168.56.77/32", "direction": "inbound", "ttl_seconds": 10, "reason": "smoke: too short"},
        )
        check("ttl_seconds=10 -> 422", r.status_code == 422, r.status_code)

        r = c.post(
            "/firewall/actions", headers=admin,
            json={"target": "192.168.56.77/32", "direction": "inbound", "ttl_seconds": 999999, "reason": "smoke: too long"},
        )
        check("ttl_seconds=999999 -> 422", r.status_code == 422, r.status_code)

        r = c.post(
            "/firewall/actions", headers=admin,
            json={"target": "192.168.56.77/32", "direction": "inbound", "ttl_seconds": -5, "reason": "smoke: negative"},
        )
        check("ttl_seconds=-5 -> 422", r.status_code == 422, r.status_code)

        print("\n-- RBAC --")
        for label, headers in [("viewer", viewer), ("analyst", analyst)]:
            r = c.post(
                "/firewall/actions", headers=headers,
                json={"target": "192.168.56.201/32", "direction": "inbound", "ttl_seconds": 300, "reason": "smoke: rbac"},
            )
            check(f"{label} POST /firewall/actions -> 403", r.status_code == 403, r.status_code)
        check("viewer GET /firewall/actions -> 200", c.get("/firewall/actions", headers=viewer).status_code == 200)

        print("\n-- apply / list / idempotent revoke / extend --")
        r = c.post(
            "/firewall/actions", headers=admin,
            json={"target": "192.168.56.201/32", "direction": "inbound", "ttl_seconds": 120, "reason": "smoke: real block"},
        )
        check("apply legit target -> 201", r.status_code == 201, r.text)
        if r.status_code != 201:
            return _finish()
        action = r.json()
        action_id = action["id"]
        check("status is active", action["status"] == "active", action["status"])
        check("remaining_seconds is populated", isinstance(action.get("remaining_seconds"), int))

        listed = c.get("/firewall/actions", headers=admin, params={"status": "active"}).json()
        check("appears in active list", any(a["id"] == action_id for a in listed))

        r = c.post(f"/firewall/actions/{action_id}/extend", headers=admin, json={"additional_seconds": 60})
        check("extend -> 200", r.status_code == 200, r.status_code)
        check("ttl grew", r.json()["ttl_seconds"] == 180, r.json()["ttl_seconds"])

        r = c.delete(f"/firewall/actions/{action_id}")
        check("revoke without auth -> 401", r.status_code == 401, r.status_code)

        r = c.delete(f"/firewall/actions/{action_id}", headers=admin)
        check("revoke -> 200", r.status_code == 200, r.status_code)
        check("status is revoked", r.json()["status"] == "revoked", r.json()["status"])

        r = c.delete(f"/firewall/actions/{action_id}", headers=admin)
        check("re-revoking an already-revoked action -> 409", r.status_code == 409, r.status_code)

        print("\n-- status / reconcile --")
        r = c.get("/firewall/status", headers=admin)
        check("GET /status -> 200", r.status_code == 200, r.text)
        check("helper reachable", r.json().get("helper_reachable") is True, r.json())

        r = c.post("/firewall/reconcile", headers=admin)
        check("POST /reconcile -> 200", r.status_code == 200, r.status_code)

    return _finish()


def _finish() -> int:
    passed, total = sum(_results), len(_results)
    print("\n" + "=" * 54)
    print(f"  {passed}/{total} checks passed")
    print("=" * 54)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
