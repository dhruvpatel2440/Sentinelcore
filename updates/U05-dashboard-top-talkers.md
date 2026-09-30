# U05 — Dashboard "Top talkers" and traffic summary — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

Proposal feature 8: *"Live dashboard showing system status, incident counts, and top talkers."*
`frontend/src/pages/overview/OverviewPage.jsx` already shows incident/event/sensor/IOC counts, a severity chart, MTTA/MTTR, recent high-severity events, and status banners. "Top talkers" currently exists only inside `pcap/PcapDetail.jsx` (computed client-side from a single capture). The live dashboard has none.

## Goal

Add a "Top talkers" card (and a small "Top targets" / "Top signatures" pair) to the Overview page, driven by the `events` table for a selectable window (1h / 24h / 7d).

## Backend

- New route in `backend/app/api/routes/events.py` (or a new `stats.py`): `GET /api/stats/top-talkers?window=24h&limit=10&by=src|dest|signature`.
- Roles: viewer, analyst, admin (read-only).
- Query the `events` table (partitioned by time — always bound the query by the window so partition pruning applies). Group by `src_ip` (and `dest_ip`, `signature`) with count and max severity. Join to `assets` for hostname where known.
- Exclude the platform's own IPs and the monitored network's gateway only if the user toggles `exclude_infra=true` (default false).
- Reuse the facet-cache pattern from `services/event_search.py` (cache key snapped to the TTL — do not embed `datetime.now()` in the key; that was bug #4 in `TEST_REPORT.md`).
- Validate `window`, `limit` (max 50) and `by` with an enum/Pydantic; no string-built SQL.
- Confirm an index supports it (`(time, src_ip)` or the existing one). Add a migration only if `EXPLAIN` shows a sequential scan over the window.

## Frontend

- New `TopTalkersCard.jsx` in `pages/overview/`, using the same `Card`, `Table`, `Badge` components and the chart library already used for the severity chart (check `package.json`; the proposal names Chart.js — do not add a second chart library).
- Bar list with counts; clicking an IP navigates to `/events?src_ip=<ip>` (the filter already exists in the events page — check `events/filters.js` for the param name).
- Show an IOC badge if the IP is in threat intel (data already stamped on events by M12).
- Window selector state must live in the URL or component state **once** — do not repeat the unbounded-refetch mistake from bug #5 (no `new Date()` inside a value that feeds an effect dependency).
- Degrade independently: if the endpoint fails, only this card shows an error state.
- Auto-refresh every 30 s using a single interval that is cleaned up on unmount.

## Tests

- Backend: seeded events give expected ordering and counts; window boundary is respected; invalid params → 422; viewer allowed, unauthenticated rejected.
- Browser suite (`e2e_browser.py`): Overview renders the card, no console errors, network request count stays flat over 20 s.

## Done when

The dashboard shows live top source IPs, targets, and signatures, links through to filtered events, and `e2e_test.py` + `e2e_browser.py` still pass.
