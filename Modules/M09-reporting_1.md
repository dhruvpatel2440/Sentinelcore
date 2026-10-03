# M9 — Reporting — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore is a modular network detection and incident response platform.

- Backend: Python 3.11 / FastAPI (async), SQLAlchemy 2.0 + asyncpg, Alembic
- Frontend: React 18 + Vite + Tailwind, dark slate theme, shell from M2
- DB: PostgreSQL 16 | Redis | worker container already running M5 pipeline + M7 correlation

## What already exists

- M1: users, RBAC, `audit_log`
- M2: app shell with a `/reports` placeholder route
- M3: `assets`, `asset_ports`, scan history
- M5: `events` (partitioned by `ts`)
- M6: event query layer and facets — reuse these query builders, do not rewrite them
- M7: `correlation_rules`, `incident_candidates`
- M8: `incidents`, `incident_history`, `incident_events`, `GET /api/incidents/stats/summary`

## Objective

Produce documents someone outside the SOC will read: a weekly security summary for a manager, an incident report for a post-mortem, an asset inventory for an auditor. The hard part is not PDF generation — it is that the numbers must be reproducible and the generation must not take down the API.

## Part 1 — Report types

Four types, each a module under `backend/app/reports/types/` implementing `build(params, db) -> ReportData`:

**`incident_summary`** — params: `from`, `to`, optional severity/status filters. Contents: totals by severity and status, MTTA and MTTR, incidents opened vs closed over time, top correlation rules by volume, top affected assets and source IPs, and a table of every incident in the window with number, title, severity, status, opened, closed, assignee.

**`incident_detail`** — params: `incident_id`. A single-incident post-mortem: header facts, full description, indicators, affected asset details from M3, the complete `incident_history` timeline with authors and timestamps, linked events (capped, with the total stated), and the resolution note. This is the document that gets attached to a ticket or handed to a client.

**`asset_inventory`** — params: optional `is_active`, CIDR filter. Every asset with IP, hostname, MAC/vendor, OS guess, open ports with services and versions, first/last seen, and the incident count per asset over the window. Flag assets not seen in the last N days and assets with high-risk open ports.

**`event_statistics`** — params: `from`, `to`, optional filters mirroring M6. Event volume over time by severity, top signatures with counts and trend vs the previous period, protocol and event-type distribution, busiest sources and destinations, and sensor drop rate from M4 — a report claiming "quiet week" while the sensor dropped 40% of packets is actively misleading, so the drop rate belongs on the first page.

## Part 2 — Model and generation flow

`backend/app/models/report.py` (addition to the canonical list — note it in the migration message):

`reports` — `id` UUID, `report_type` enum, `title`, `params` JSONB, `format` enum(`pdf`/`csv`/`json`), `status` enum(`queued`/`running`/`completed`/`failed`), `requested_by` fk users, `file_path` text nullable, `file_size` int, `checksum` (sha256), `error` text, `requested_at`, `started_at`, `completed_at`, `expires_at`.

Generation is **always asynchronous**, even when it feels fast:

1. `POST /api/reports` validates params, creates a `queued` row, pushes the id to a Redis queue, returns 202 with the report id.
2. The worker picks it up, marks `running`, builds the data, renders the file to `REPORT_STORAGE_PATH` (a volume, not the image), computes the checksum, marks `completed`.
3. The client polls `GET /api/reports/{id}` and downloads when ready.

A synchronous endpoint that runs a 90-day aggregate will block a worker thread and time out behind nginx. Do not offer one.

Failures mark `failed` with the error recorded; the row is never left in `running`. Wrap the worker body accordingly and add a startup reconciliation that fails any `running` report older than the timeout.

## Part 3 — Rendering

- **PDF**: WeasyPrint rendering a Jinja2 HTML template. HTML templates are far easier to maintain than ReportLab's imperative API, and the styling can mirror the app's look. Add `weasyprint` and `jinja2` to requirements (WeasyPrint needs system libs — add them to the backend Dockerfile).
- **Charts**: render with Matplotlib to PNG at a fixed DPI and embed as base64 data URIs. No JS chart libraries — the renderer has no browser engine running scripts.
- **CSV**: stdlib `csv`, streamed for the tabular types (`incident_summary` table, `asset_inventory`, `event_statistics` top-N). Not offered for `incident_detail`, which is narrative.
- **JSON**: the raw `ReportData` — this is what makes the numbers verifiable and lets someone build their own view.

Template structure under `backend/app/reports/templates/`: a `base.html` with the cover page (title, generated-at in UTC **and** local, the exact parameters used, the requesting user, and a checksum footer), plus one template per type. Stating the parameters on the cover is what makes a report reproducible six months later.

**Escape everything.** Signatures, hostnames and resolution notes come from untrusted network data and free-text fields. Jinja2 autoescaping stays on; never mark report content `|safe`.

## Part 4 — Endpoints

Router at `/api/reports`:

- `POST /` — any authenticated role. Body `{report_type, format, params, title?}`. Validate params against a pydantic model **per report type**. Enforce a max window (`MAX_REPORT_WINDOW_DAYS`, default 365) and a per-user concurrent-generation limit (e.g. 3) to stop one user from saturating the worker.
- `GET /` — the requesting user's reports; admins see all. Paginated, filterable by type and status.
- `GET /{id}` — status and metadata.
- `GET /{id}/download` — streams the file with the correct content type and a `Content-Disposition` filename. **Authorize on every download**: only the requester or an admin. Serve via `FileResponse` from the storage path resolved and checked against the storage root — never join a user-supplied value into the path. Audit each download; who exported what matters.
- `DELETE /{id}` — requester or admin, deletes the row and the file.
- Retention: a scheduled job deletes reports past `expires_at` (default 30 days) and their files, logging what it removed.

## Part 5 — Scheduled reports

`report_schedules` — `id`, `report_type`, `params` JSONB, `format`, `cron` str, `enabled`, `recipients` JSONB (for later delivery), `created_by`, `last_run_at`, `next_run_at`.

The worker checks due schedules each minute and enqueues them with a **relative** window resolved at run time (`last_7_days`, `last_30_days`), not the absolute dates stored at creation. Store the relative intent in `params`, e.g. `{"window": "last_7_days"}`. Admin-only CRUD, audited. Delivery (email/webhook) is out of scope — generated scheduled reports simply appear in the list.

## Part 6 — Frontend

Replace the `/reports` placeholder:

- "New report" panel: type picker, then a param form that changes per type (date range with M6's presets, filters, and for `incident_detail` an incident search field), format selector, optional title.
- Reports table: title, type, format, status badge, requested by, requested at, size, and a download button enabled only when `completed`. Poll while any row is `queued`/`running`, with a progress indicator; stop polling when none are pending.
- Failed rows show the error inline with a retry action that re-submits identical params.
- Schedules tab (admin): cron builder with a plain-language preview ("every Monday at 08:00 UTC"), enable toggles, last/next run.
- A "Generate report" shortcut on the M8 incident detail page that pre-fills `incident_detail` for that incident — that is where the need actually arises.

## Definition of done

- Each of the four types generates a valid PDF with populated charts, and a seeded dataset yields numbers that match hand-calculated values.
- The same report generated twice over the same absolute window produces identical figures.
- A 365-day `event_statistics` report completes without blocking the API — requests served normally throughout.
- Requesting another user's report download returns 403; the download is recorded in `audit_log`.
- A report whose generation raises is marked `failed` with the error visible in the UI, and no row remains stuck in `running` after a worker restart.
- A signature containing `<script>` renders as literal text in the PDF and in the HTML preview.
- CSV output opens cleanly in a spreadsheet with correct headers and UTC timestamps.
- A schedule set to `last_7_days` run twice a week apart produces two reports covering different, correct windows.
- Expired reports and their files are removed by the retention job.
- Tests: per-type param validation, each `build()` against a seeded fixture DB with asserted aggregate values, path-traversal attempt on download, RBAC on download, relative-window resolution.

## Out of scope

Email or webhook delivery, custom report builders, branded/white-label templates, and executive dashboards inside the app (the M2 dashboard is separate).
