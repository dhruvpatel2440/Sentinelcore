# SentinelCore — Full-Platform Test Report

**Date:** 2026-09-22
**Branch:** `dhruv`
**Environment:** live `docker-compose` stack (backend, worker, db, redis, helper, nginx, frontend) — not mocked
**Scope:** every module M1–M12, backend API, frontend UI in a real headless Chromium browser, and the CLAUDE.md architecture invariants

## How this was actually tested

Two independent, repeatable suites were built and committed to the repo so you can re-run them yourself:

| Suite | What it does | Run it with |
|---|---|---|
| `backend/scripts/e2e_test.py` | Logs in over the real `/auth/login` endpoint as three real accounts (admin/analyst/viewer), then drives every module's HTTP API: happy paths, the full RBAC matrix, and every negative case each module's spec calls out as security-critical. | `docker compose exec backend python -m scripts.e2e_test` |
| `backend/scripts/e2e_browser.py` | Drives the real UI in headless Chromium: logs in through the actual form, visits every route, clicks real rows, fills the real intel lookup bar, and fails on any uncaught JS error or React error boundary. | `/path/to/venv/bin/python backend/scripts/e2e_browser.py` (needs `pip install playwright && playwright install chromium`) |
| `backend/scripts/e2e_fixtures.py` | One-time setup: creates `t_admin` / `t_analyst` / `t_viewer` test accounts. | `docker compose exec backend python -m scripts.e2e_fixtures` |

Screenshots of every page (logged in, as both admin and viewer) are saved to `/tmp/e2e_shots/` by the browser suite for visual verification.

**No test in either suite is a hardcoded pass.** An earlier draft of this suite had one (`record("M1", "...Argon2...", True, "see invariant section")`) — it was caught and rewritten to actually read the stored hash out of the database before this report was produced. Every assertion below reads a real HTTP response, a real database row, a real file on disk, or real rendered DOM.

## Result

```
API suite:     157 / 157 passed
Browser suite:  53 / 53  passed
TOTAL:         210 / 210 passed
```

## Bugs found and fixed

Testing this way — hitting the real stack instead of trusting that "the code looks right" — surfaced **5 real bugs**, all now fixed and re-verified:

### 1. PCAP upload and report generation were completely broken (critical)
**Symptom:** every PCAP upload and every report request failed with a 500.
**Cause:** `backend/Dockerfile` created the `appuser` (uid 1000) but never set ownership on `/var/lib/sentinelcore/pcap` and `/var/lib/sentinelcore/reports`. Docker seeds a fresh named volume from whatever is at that path in the image, so a clean deploy gets those directories `root:root 0755` — the unprivileged API/worker containers get `PermissionError: [Errno 13] Permission denied` on every write.
**Fix:** `backend/Dockerfile` now creates both directories at build time with `chown appuser:sentinelcore` and `chmod 2770` (setgid, so files stay group-writable for both the API and worker containers). Applied to the already-running volumes as well.
**Verified:** uploaded a real pcap and downloaded a real generated PDF report end-to-end.

### 2. All PDF report generation was silently failing (critical)
**Symptom:** `report generator report ... failed: 'super' object has no attribute 'transform'` for every single report.
**Cause:** `pydyf` (WeasyPrint's PDF writer) is a **transitive** dependency and was never pinned in `requirements.txt`. WeasyPrint 62.3 targets the pydyf 0.10.x API; a fresh `pip install` pulled pydyf 0.12.1, which reworked its internals and broke every render.
**Fix:** pinned `pydyf==0.10.0` explicitly in `backend/requirements.txt` with a comment explaining why, so a future clean rebuild can't silently regress this again.
**Verified:** a real `incident_summary` PDF report generated, downloaded, and its first 4 bytes checked to be the literal `%PDF` magic header.

### 3. Logging out and back in within the same second permanently locked you out (critical, user-facing)
**Symptom:** `login → logout → login again` sometimes returned "Session has been revoked" on the brand-new token, indefinitely (every subsequent login from that account also failed).
**Cause:** JWT `iat` was truncated to whole-second precision (`int(now.timestamp())`), but revocation compares it against `users.tokens_valid_from`, which has microsecond precision. A token minted in the same wall-clock second as a logout could carry an `iat` that rounds down to *before* the revocation cutoff, making a perfectly fresh token look stale forever.
**Fix:** `backend/app/core/security.py` now keeps `iat` at full float precision (RFC 7519 permits a non-integer `NumericDate`). Verified revocation of pre-logout tokens still works correctly — this wasn't a matter of just removing the check.
**Verified:** 5 rapid-fire logout→login cycles all succeed; a token minted *before* a (delayed) logout is still correctly rejected afterward.

### 4. The event-search facet cache never actually cached anything (performance)
**Symptom:** `/events/facets` recomputed five aggregation queries from scratch on every single call, even back-to-back identical calls — `cached` was always `false`.
**Cause:** when a caller omits `from`/`to` (the common case — the default 24h view), the cache key embedded `datetime.now()` at microsecond precision, so every request produced a unique key.
**Fix:** the cache key now snaps the window edges to the cache TTL (`search_facet_cache_seconds`), so requests inside the same bucket share a key. Different filters still correctly produce different keys (verified).
**Verified:** 2nd/3rd calls with the same filters now return `cached: true`; a call with a different `severity` filter still correctly misses.

### 5. The Events page could hammer the API with unbounded repeated requests (critical, performance/availability)
**Symptom:** loading `/events` with no `from`/`to` in the URL (the normal landing state) fired dozens of duplicate `GET /events` and `GET /events/facets` calls per second, unboundedly, for as long as the tab stayed open.
**Cause:** `filtersFromSearchParams()` falls back to `defaultFilters()`, which calls `new Date()`, whenever the URL has no explicit window. That function was called fresh on every render, so the `filters` object's `from`/`to` strings changed every single render. `loadFirstPage`'s effect is keyed on `JSON.stringify(filters)`, so a changing `filters` object retriggered the effect every render → new state → new render → repeat, forever.
**Fix:** `EventsPage.jsx` now writes the resolved default window into the URL once (`replace: true`) the first time it's missing, making `searchParams` the single stable source of truth. Verified request count is flat (10 requests total, from React 18 StrictMode's expected dev-only double-invoke) instead of growing without bound, and a production build (`vite build`) compiles clean.
**Verified:** watched real network traffic in a real browser for 20 seconds — steady at 10 requests, not growing.

## Unimplemented pages found and built

Two routes were still wired to the M2 placeholder scaffold despite every backend endpoint they needed already existing:

- **`/` (Overview / dashboard)** — now a real landing page: live incident/event/sensor/IOC counts, a severity breakdown chart, mean-time-to-acknowledge/resolve, recent high-severity events with IOC badges, and proactive banners when the sensor is down, a threat-intel feed is failing, or firewall rules have drifted. Every tile degrades independently if its endpoint fails or the user lacks a role for it (e.g. viewer sees no firewall tile) — one dead module can't blank the page.
- **`/admin/users`** — now a real user-management page: create users, change role, activate/deactivate, reset password, delete — all wired to the existing (and already fully RBAC-correct) `/api/users` backend. Self-protection is enforced in the UI too (you can't change your own role, deactivate, or delete yourself).

Both pass every check in the browser suite (real heading rendered, no error boundary, no JS errors) and were screenshotted as both admin and viewer.

## Full coverage detail (what "210 passed" actually checked)

**M1 Auth/RBAC** — wrong password rejected, unknown username doesn't leak existence, forged JWT rejected, every admin-only endpoint blocks viewer+analyst and allows admin, Argon2 hash format verified by reading the actual `password_hash` column, logout revocation verified both ways (does revoke old tokens, doesn't lock out new logins).

**M3 Assets** — scan launch admin-only, 5 shell-injection-shaped targets (`; rm -rf /`, `` `id` ``, `$(whoami)`, etc.) all rejected by the typed validator before reaching any subprocess, out-of-scope target rejected.

**M4 Sensor** — status/stats readable by all roles, start/stop/rule-source-creation admin-only, rule override without a required reason rejected.

**M5 Pipeline** — a synthetic Suricata EVE record pushed onto the real Redis stream is picked up by the real worker and lands in `events` with correct severity mapping and asset enrichment; an identical duplicate record collapses to one row; a malformed record doesn't crash the writer.

**M6 Search** — pagination shape, severity filtering, keyset cursor actually advances, facets aggregation and its cache (fixed above), saved-search ownership (another user can't delete yours).

**M7 Correlation** — rule CRUD is admin-only, invalid `group_by`/`window_seconds` rejected with 422, dry-run test endpoint writes nothing, candidates readable by all roles.

**M8 Incidents** — full lifecycle (new→triage→investigating→contained→resolved), optimistic-concurrency 409 on stale version, illegal backwards transitions rejected, resolution note required to close, reopening a closed incident is admin-only, comments and event-linking work, hard delete is admin-only.

**M9 Reporting** — async report request, real PDF generated and downloaded (magic-header checked), another user can't download your report, `incident_detail`+CSV combination rejected, oversized window rejected, schedules are admin-only.

**M10 Firewall** — TTL is mandatory and bounded (60s–24h), non-IP targets rejected, **the actual detected gateway IP and configured protected IPs were fed into a real block request and confirmed refused** (not simulated — read from `/proc/net/route` at test time), precheck endpoint works.

**M11 PCAP** — magic-byte validation rejects a renamed non-pcap file, a path-traversal filename (`../../../../etc/passwd`) is safely stored under a UUID with the filesystem inspected directly to confirm no escape, sha256-based dedup returns the existing record on re-upload, parse always resolves (never stuck), raw download is admin-only.

**M12 Threat Intel** — defanged indicator normalization (`hxxp://evil[.]com` → `http://evil.com`), private/RFC1918 IP refused as an IOC, CIDR containment matching, bulk add with mixed valid/invalid lines, a synthetic event to a real known-bad IP is matched live through the real Redis-backed matcher and stamped on the real event row, severity escalation confirmed to never downgrade an already-higher-severity event, sources/retro-hunt admin-only.

**Frontend** — all 12 real routes (not placeholders) served through the real nginx→Vite path, sidebar hides admin-only items from a viewer, and the route itself (not just the nav) blocks direct navigation.

**Architecture invariants (CLAUDE.md)** — API process confirmed not running as uid 0, zero occurrences of `shell=True` anywhere in the backend, `SECRET_KEY` isn't the shipped placeholder, `.env` isn't tracked by git, the privileged-helper socket exists and is the only path to root operations.

## What this report does not cover

- Load/stress testing (concurrent users, sustained high event throughput).
- Suricata's actual detection accuracy against real attack traffic (out of scope — this tests the platform around it, not the IDS engine itself).
- Cross-browser testing (only Chromium was driven; Firefox/Safari untested).
- The privileged-helper's `NET_ADMIN`/`NET_RAW` operations were exercised through the normal API path (firewall apply/precheck, sensor control) but not fuzzed directly at the Unix-socket protocol level.

## Re-running this yourself

```bash
# one-time: create test accounts
docker compose exec backend python -m scripts.e2e_fixtures

# backend + RBAC + security suite (fast, no browser needed)
docker compose exec backend python -m scripts.e2e_test

# full browser suite (needs Playwright on the host)
pip install playwright && playwright install chromium
python backend/scripts/e2e_browser.py
```

Both suites clean up every object they create and are safe to re-run repeatedly against the live stack.
