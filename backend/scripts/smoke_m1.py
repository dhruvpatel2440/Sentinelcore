"""M1 smoke test — exercises the live auth/RBAC surface against a running API.

Unlike tests/, this needs the stack up. Run it from inside the backend
container after `docker compose up`:

    docker compose exec backend python -m scripts.smoke_m1
"""

from __future__ import annotations

import os
import sys

import httpx

BASE = os.getenv("SMOKE_BASE_URL", "http://localhost:8000/api")
ADMIN_USER = os.getenv("SEED_ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("SEED_ADMIN_PASSWORD", "sentinel-dev-admin-2026")

VIEWER_USER = "smoke_viewer"
VIEWER_PASS = "smoke-viewer-pass-123456"

_results: list[bool] = []


def check(name: str, cond: bool, extra: object = "") -> None:
    _results.append(bool(cond))
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({extra})" if extra != "" else ""))


def main() -> int:
    with httpx.Client(base_url=BASE, timeout=20.0) as c:
        print("\n-- health --")
        r = c.get("/health")
        check("GET /health -> 200 ok", r.status_code == 200 and r.json()["status"] == "ok")
        r = c.get("/health/ready")
        check("readiness: db + redis reachable", r.json()["status"] == "ok", r.json()["checks"])

        print("\n-- unauthenticated access is refused --")
        check("GET /auth/me -> 401", c.get("/auth/me").status_code == 401)
        check("GET /users -> 401", c.get("/users").status_code == 401)

        print("\n-- login failure modes --")
        r = c.post("/auth/login", json={"username": ADMIN_USER, "password": "wrong-password"})
        bad_pw_detail = r.json().get("detail")
        check("wrong password -> 401", r.status_code == 401, bad_pw_detail)
        r = c.post("/auth/login", json={"username": "nosuchuser", "password": "whatever12345"})
        check("unknown user -> 401", r.status_code == 401, r.json().get("detail"))
        check(
            "identical message for both (no user enumeration)",
            r.json().get("detail") == bad_pw_detail,
        )

        print("\n-- successful login --")
        r = c.post("/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
        check("valid credentials -> 200", r.status_code == 200, r.status_code)
        if r.status_code != 200:
            print("   body:", r.text[:400])
            return 1

        data = r.json()
        check("body carries access_token", bool(data.get("access_token")))
        check("body carries user, role=admin", data["user"]["role"] == "admin")
        check("access token expires_in = 900s", data["expires_in"] == 900, data["expires_in"])
        check("refresh token NOT in response body", "refresh_token" not in data)

        set_cookie = r.headers.get("set-cookie", "")
        check("refresh cookie is HttpOnly", "HttpOnly" in set_cookie)
        check("refresh cookie Path=/api/auth", "Path=/api/auth" in set_cookie)
        check("refresh cookie SameSite=lax", "samesite=lax" in set_cookie.lower())

        token = data["access_token"]
        auth = {"Authorization": f"Bearer {token}"}

        print("\n-- authenticated access --")
        r = c.get("/auth/me", headers=auth)
        check("GET /auth/me -> 200, correct user", r.status_code == 200 and r.json()["username"] == ADMIN_USER)
        r = c.get("/users", headers=auth)
        check("admin lists users -> 200", r.status_code == 200, f"{len(r.json())} user(s)")

        print("\n-- token type confusion --")
        cookie_token = c.cookies.get("sentinelcore_refresh")
        r = c.get("/auth/me", headers={"Authorization": f"Bearer {cookie_token}"})
        check("refresh token rejected as access token -> 401", r.status_code == 401, r.json().get("detail"))

        print("\n-- silent refresh --")
        r = c.post("/auth/refresh")
        check("refresh via cookie -> 200", r.status_code == 200, r.status_code)
        check("refresh issues a different token", r.json().get("access_token") != token)

        print("\n-- RBAC enforcement --")
        r = c.post(
            "/users",
            headers=auth,
            json={"username": VIEWER_USER, "password": VIEWER_PASS, "role": "viewer"},
        )
        check("admin creates a viewer", r.status_code in (201, 409), r.status_code)

        r = c.post("/auth/login", json={"username": VIEWER_USER, "password": VIEWER_PASS})
        check("viewer logs in -> 200", r.status_code == 200, r.status_code)
        if r.status_code != 200:
            return 1
        vauth = {"Authorization": f"Bearer {r.json()['access_token']}"}
        check("viewer role is 'viewer'", r.json()["user"]["role"] == "viewer")

        check("viewer GET /users -> 403", c.get("/users", headers=vauth).status_code == 403)
        r = c.post(
            "/users",
            headers=vauth,
            json={"username": "escalate", "password": "aaaaaaaaaaaa", "role": "admin"},
        )
        check("viewer cannot create users -> 403", r.status_code == 403, r.status_code)
        check("viewer CAN read own profile -> 200", c.get("/auth/me", headers=vauth).status_code == 200)

        print("\n-- logout revokes the session --")
        vc = httpx.Client(base_url=BASE, timeout=20.0)
        r = vc.post("/auth/login", json={"username": VIEWER_USER, "password": VIEWER_PASS})
        vtok = r.json()["access_token"]
        check("pre-logout: token works", vc.get("/auth/me", headers={"Authorization": f"Bearer {vtok}"}).status_code == 200)
        check("logout -> 204", vc.post("/auth/logout").status_code == 204)
        check(
            "post-logout: old access token rejected -> 401",
            vc.get("/auth/me", headers={"Authorization": f"Bearer {vtok}"}).status_code == 401,
        )
        check("post-logout: refresh rejected -> 401", vc.post("/auth/refresh").status_code == 401)
        vc.close()

    passed = sum(_results)
    total = len(_results)
    print("\n" + "=" * 52)
    print(f"  {passed}/{total} checks passed")
    print("=" * 52)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
