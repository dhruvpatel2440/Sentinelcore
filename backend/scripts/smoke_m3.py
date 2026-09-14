"""M3 smoke test — privilege boundary, helper validation, and the scan API.

Run from inside the backend container with the stack up:

    docker compose exec backend python -m scripts.smoke_m3
"""

from __future__ import annotations

import asyncio
import os
import sys

import httpx

from app.services import helper_client
from app.services.helper_client import HelperRejected, HelperUnavailable

BASE = os.getenv("SMOKE_BASE_URL", "http://localhost:8000/api")
ADMIN_USER = os.getenv("SEED_ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("SEED_ADMIN_PASSWORD", "sentinel-dev-admin-2026")

VIEWER_USER = "smoke_viewer"
VIEWER_PASS = "smoke-viewer-pass-123456"

_results: list[bool] = []


def check(name: str, cond: bool, extra: object = "") -> None:
    _results.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({extra})" if extra != "" else ""))


async def helper_checks() -> None:
    print("\n-- helper reachability --")
    check("backend can open the helper socket", await helper_client.ping())

    print("\n-- helper rejects out-of-scope targets independently --")
    # These bypass the API's pydantic layer entirely and hit the helper direct,
    # which is exactly the M3 requirement: two independent validations.
    for target in ["8.8.8.8/32", "0.0.0.0/0", "10.0.0.0/8", "127.0.0.1/32"]:
        try:
            await helper_client.call(
                "nmap_scan", {"targets": [target], "ports": "80", "mode": "tcp_syn"}, timeout=30
            )
            check(f"helper rejects {target}", False, "ACCEPTED - THIS IS A BUG")
        except HelperRejected as exc:
            check(f"helper rejects {target}", True, exc.code)
        except HelperUnavailable as exc:
            check(f"helper rejects {target}", False, f"unavailable: {exc}")

    print("\n-- helper rejects injection-shaped input --")
    injections = [
        ("ports", {"targets": ["192.168.10.0/30"], "ports": "1-1024; rm -rf /", "mode": "tcp_syn"}),
        ("ports", {"targets": ["192.168.10.0/30"], "ports": "$(id)", "mode": "tcp_syn"}),
        ("mode", {"targets": ["192.168.10.0/30"], "ports": "80", "mode": "--script=vuln"}),
        ("mode", {"targets": ["192.168.10.0/30"], "ports": "80", "mode": "-sS"}),
        ("targets", {"targets": ["192.168.10.1; id"], "ports": "80", "mode": "tcp_syn"}),
        ("targets", {"targets": ["example.com"], "ports": "80", "mode": "tcp_syn"}),
    ]
    for field, params in injections:
        label = f"{field}={params[field] if field != 'targets' else params['targets'][0]!r}"
        try:
            await helper_client.call("nmap_scan", params, timeout=30)
            check(f"helper rejects {label}", False, "ACCEPTED - THIS IS A BUG")
        except HelperRejected as exc:
            check(f"helper rejects {label}", True, exc.code)

    print("\n-- helper refuses unknown operations --")
    for op in ["exec", "run_command", "shell", "suricata_start_totally_real"]:
        try:
            await helper_client.call(op, {}, timeout=10)
            check(f"unknown op {op!r} refused", False, "ACCEPTED - THIS IS A BUG")
        except HelperRejected as exc:
            check(f"unknown op {op!r} refused", exc.code == "unknown_op", exc.code)


def api_checks() -> None:
    with httpx.Client(base_url=BASE, timeout=30.0) as c:
        r = c.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
        if r.status_code != 200:
            print(f"  [FAIL] admin login ({r.status_code})")
            _results.append(False)
            return
        admin = {"Authorization": f"Bearer {r.json()['access_token']}"}

        c.post(
            "/users",
            headers=admin,
            json={"username": VIEWER_USER, "password": VIEWER_PASS, "role": "viewer"},
        )
        r = c.post("/auth/login", json={"username": VIEWER_USER, "password": VIEWER_PASS})
        viewer = {"Authorization": f"Bearer {r.json()['access_token']}"}

        print("\n-- RBAC on scan control --")
        r = c.post("/assets/scan", headers=viewer, json={"targets": ["192.168.10.0/30"]})
        check("viewer POST /assets/scan -> 403", r.status_code == 403, r.status_code)
        check("viewer GET /assets -> 200", c.get("/assets", headers=viewer).status_code == 200)

        print("\n-- API rejects out-of-scope targets (layer 1) --")
        for target in ["8.8.8.8/32", "0.0.0.0/0", "192.168.0.0/16", "127.0.0.1"]:
            r = c.post("/assets/scan", headers=admin, json={"targets": [target]})
            check(f"API rejects {target} -> 422", r.status_code == 422, r.status_code)

        print("\n-- API rejects injection-shaped input (layer 1) --")
        for label, body in [
            ("ports '1-1024; rm -rf /'", {"ports": "1-1024; rm -rf /"}),
            ("ports '$(id)'", {"ports": "$(id)"}),
            ("ports '80|nc'", {"ports": "80|nc"}),
            ("ports '0'", {"ports": "0"}),
            ("ports '1024-22' (reversed)", {"ports": "1024-22"}),
            ("mode '--script=vuln'", {"mode": "--script=vuln"}),
            ("mode '-sS'", {"mode": "-sS"}),
        ]:
            r = c.post(
                "/assets/scan", headers=admin, json={"targets": ["192.168.10.0/30"], **body}
            )
            check(f"API rejects {label} -> 422", r.status_code == 422, r.status_code)

        print("\n-- asset listing --")
        r = c.get("/assets", headers=admin)
        check("GET /assets -> 200", r.status_code == 200)
        check("response is paginated", {"items", "total", "limit", "offset"} <= set(r.json()))
        r = c.get("/assets/scans", headers=admin)
        check("GET /assets/scans -> 200", r.status_code == 200)


def main() -> int:
    asyncio.run(helper_checks())
    api_checks()

    passed, total = sum(_results), len(_results)
    print("\n" + "=" * 52)
    print(f"  {passed}/{total} checks passed")
    print("=" * 52)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
