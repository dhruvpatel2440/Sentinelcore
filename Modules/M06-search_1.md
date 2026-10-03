# M6 — Event Search — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore is a modular network detection and incident response platform.

- Backend: Python 3.11 / FastAPI (async), SQLAlchemy 2.0 + asyncpg, Alembic
- Frontend: React 18 + Vite + Tailwind, dark slate theme, shell and shared components from M2
- DB: PostgreSQL 16, `events` is range-partitioned by `ts` (monthly)

## What already exists

- M1: RBAC, `audit_log`
- M2: app shell with an `/events` placeholder route, shared `Table`, `Badge`, `PageHeader`, `EmptyState`
- M3: `assets` — events carry `src_asset_id` / `dst_asset_id`
- M5: the `events` table, populated continuously. Columns: `id`, `ts`, `ingested_at`, `event_type`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto`, `signature`, `signature_id`, `rev`, `category`, `severity`, `src_asset_id`, `dst_asset_id`, `flow_id`, `dedup_key`, `raw` (JSONB). Indexed on `(ts DESC)`, `(src_ip, ts DESC)`, `(dst_ip, ts DESC)`, `(signature_id, ts DESC)`, `(severity, ts DESC)`.

## Objective

Make the event store actually usable by an analyst under time pressure: fast filtering, stable pagination over millions of rows, and a detail view that shows the full context of a single event. This is the module an analyst lives in during an investigation.

## Part 1 — Query API

Router at `/api/events`, readable by every authenticated role.

`GET /api/events` parameters:

| param | type | notes |
|---|---|---|
| `from` / `to` | ISO datetime | **required window**, default last 24h. Reject windows wider than `MAX_SEARCH_WINDOW_DAYS` (default 30) |
| `severity` | repeatable enum | OR within the field |
| `event_type` | repeatable enum | |
| `src_ip` / `dst_ip` | inet or CIDR | accept `192.168.10.0/24` and use `<<=` against the inet column |
| `ip` | inet or CIDR | matches either direction — the filter analysts actually reach for |
| `port` | int | matches src or dst |
| `proto` | str | |
| `signature_id` | repeatable bigint | |
| `q` | str | substring against `signature` and `category`, case-insensitive |
| `asset_id` | UUID | matches either side |
| `cursor` | opaque str | keyset pagination |
| `limit` | int | default 50, max 500 |
| `sort` | enum | `ts_desc` (default) or `ts_asc` |

**Keyset pagination, not OFFSET.** `OFFSET 100000` makes PostgreSQL walk 100k rows every page and, worse, silently shifts results as new events arrive. Encode the cursor as base64 of `(ts, id)` and filter `WHERE (ts, id) < (:ts, :id)` for descending order. The `(ts DESC, id DESC)` ordering must match an index.

**Always constrain `ts`** so partition pruning applies — build the filter such that the time window is non-optional at the SQL level, even if a caller omits it.

Response: `{ items: [...], next_cursor: str|null, took_ms: int }`. Do **not** return a total count — counting matched rows across partitions is the query that will fall over first. If the UI needs a sense of scale, return `has_more` and an optional capped count (`COUNT(*) ... LIMIT 10000`) behind a separate opt-in parameter.

`GET /api/events/{id}` — the full record including `raw`, plus context:

- sibling events sharing the same `flow_id` (the alert plus the http/dns/tls records for the same flow — this is where the actual story is)
- the resolved `src`/`dst` asset summaries from M3
- a count of events with the same `signature_id` in the last 24h, to answer "is this noisy or rare?" immediately

`GET /api/events/facets` — counts by severity, event_type, and the top 10 signatures / source IPs / destination IPs for the current filter set. Run it as a separate request so a slow facet query never blocks the result list. Cache per filter-hash in Redis for 30s.

## Part 2 — Saved searches

`backend/app/models/saved_search.py` (an addition to the canonical table list — note it in the migration message): `id`, `user_id` fk, `name`, `filters` JSONB, `is_shared` bool, `created_at`, `updated_at`. Unique on `(user_id, name)`.

Endpoints under `/api/events/searches`: list (own + shared), create, update, delete. A user can only modify their own; `is_shared` makes it readable by everyone. Audited on write.

## Part 3 — Frontend

Replace the `/events` placeholder.

**Filter bar** (sticky at the top):

- Time range picker with quick presets — Last 15m / 1h / 24h / 7d / Custom. The preset row matters more than the custom picker; it is what gets clicked in an incident.
- Severity multi-select as toggle chips using the M2 `Badge` colours.
- IP / CIDR input with client-side validation before the request fires.
- Free-text `q` with a 300ms debounce.
- Active filters render as removable pills, and the whole filter state is mirrored into the URL query string — an analyst has to be able to paste a link to a colleague and have them see exactly the same result set.

**Results table**:

- Columns: time (absolute on hover, relative in the cell), severity badge, signature, src → dst (with ports), proto, event type.
- Infinite scroll or an explicit "Load more" driven by `next_cursor`. Virtualize the rows — rendering 500 DOM rows per page will stutter.
- Row click opens the detail panel without navigating away from the list; keep the list scroll position.
- A "live tail" toggle that polls for events newer than the current top row every 5s and prepends them, paused automatically when the user scrolls down. Genuinely useful during an active incident; make sure it stops when the tab is hidden.

**Detail panel** (side drawer):

- Header: severity, signature, timestamp, signature id with the 24h frequency count.
- Network block: src/dst with asset names linked to M3 asset pages when resolved.
- Related events from the same `flow_id`, in a compact timeline.
- Raw JSON in a collapsible, syntax-highlighted block with a copy button.
- Pivot actions that carry the filter into a new search: "all events from this IP", "all events for this signature", "this flow".

**Facets sidebar**: top signatures / source IPs / destination IPs with counts, each clickable to add a filter. This is how an analyst finds the pattern without knowing what to search for.

**Saved searches**: a dropdown to load one, a "Save current" action, and a shared/personal indicator.

## Definition of done

- A search over a 7-day window on a table with several million events returns the first page in under 500ms.
- Paging to page 20 is as fast as page 1, and no row is skipped or repeated while new events are arriving.
- `EXPLAIN ANALYZE` on the main query shows an index scan and partition pruning — attach the plan to the PR.
- Every filter is reflected in the URL; pasting the URL in a new tab reproduces the exact result set.
- A CIDR filter of `192.168.10.0/24` matches the expected hosts; an invalid CIDR is rejected client-side with a clear message.
- Live tail prepends new events and pauses on scroll and on tab blur.
- The detail panel shows related `flow_id` events for an alert that has them.
- A saved shared search is visible to another user; a private one is not, and neither can be edited by a non-owner (verify the 403).
- Tests: cursor encode/decode round-trip, keyset boundary correctness with identical timestamps, window-cap rejection, CIDR filter SQL, saved-search ownership enforcement.

## Out of scope

Correlation rules (M7), incident creation from a search (M8), exporting results to a report (M9), IOC enrichment display (M12), and full-text search infrastructure such as Elasticsearch — PostgreSQL carries this.
