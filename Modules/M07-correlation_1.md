# M7 — Correlation Engine — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore is a modular network detection and incident response platform.

- Backend: Python 3.11 / FastAPI (async), SQLAlchemy 2.0 + asyncpg, Alembic
- Frontend: React 18 + Vite + Tailwind, dark slate theme, shell from M2
- DB: PostgreSQL 16 | Redis for windows and caching

## What already exists

- M1: RBAC (`require_role`), `audit_log`
- M2: app shell and shared components
- M3: `assets` — correlation can weight by asset criticality
- M5: the `events` table and the ingest worker (Redis Stream → batch writer). Events carry `ts`, `src_ip`, `dst_ip`, `signature_id`, `severity`, `event_type`, `flow_id`, `src_asset_id`, `dst_asset_id`.
- M6: event search and facets

## Objective

Turn a stream of individual alerts into a small number of meaningful findings. A SOC that looks at every alert looks at nothing — this module is what makes M8's incident queue survivable. It produces **incident candidates**; M8 owns the incident lifecycle.

## Design principles

- **Rules are data, not code.** Stored in a table, editable by an admin, versioned. Never a Python file the user has to redeploy to tune.
- **Idempotent and restart-safe.** Reprocessing a window must not produce duplicate candidates.
- **Cheap first, expensive second.** Filter by indexed columns before doing any grouping work.
- **Explainable.** Every candidate records exactly which rule fired and which events matched. An analyst who cannot see why something alerted will not trust it.

## Part 1 — Models

`backend/app/models/correlation.py` (additions to the canonical list — note them in the migration message).

`correlation_rules`

| column | type | notes |
|---|---|---|
| `id` | UUID pk | |
| `name` / `description` | str / text | description is required — it becomes the incident narrative |
| `enabled` | bool | default true |
| `rule_type` | enum | `threshold` \| `sequence` \| `rare` \| `beacon` |
| `match` | JSONB | event filter: severity in, event_type in, signature_id in, category regex, src/dst CIDR |
| `group_by` | JSONB | array of fields, e.g. `["src_ip"]` or `["src_ip","dst_ip"]` |
| `window_seconds` | int | sliding window |
| `threshold` | int | count that trips the rule |
| `severity` | enum | severity assigned to the candidate |
| `dedup_window_seconds` | int | suppress a repeat candidate for the same group |
| `params` | JSONB | type-specific extras (sequence steps, beacon tolerance) |
| `created_by` / `created_at` / `updated_at` | | |

`incident_candidates`

`id`, `rule_id` fk, `group_key` str (indexed), `first_event_ts`, `last_event_ts`, `event_count`, `severity`, `score` int, `summary` text, `evidence` JSONB (matched event ids, capped — store the first and last 100 plus the count, not 50,000 ids), `status` enum(`new`/`promoted`/`suppressed`), `incident_id` fk nullable (set by M8), `created_at`. Unique on `(rule_id, group_key, first_event_ts)`.

`rule_runs` — `id`, `rule_id`, `window_start`, `window_end`, `events_scanned`, `candidates_created`, `duration_ms`, `error`, `created_at`. This is what lets you debug a rule that "isn't firing".

## Part 2 — Rule types

Implement four evaluators in `backend/app/correlation/evaluators/`, each behind a common interface `evaluate(rule, window_start, window_end, db) -> list[Candidate]`.

**`threshold`** — the workhorse. Count matching events per `group_by` key in the window; fire when `count >= threshold`. Covers port scans (many distinct `dst_port` from one `src_ip`), brute force (repeated auth-failure signature to one `dst_ip`), and scanning sweeps (one `src_ip`, many distinct `dst_ip`). Support `count_distinct_field` in `params` so "50 distinct ports" is expressible, not just "50 events".

**`sequence`** — ordered stages within the window: `params.steps` is a list of match blocks that must occur in order for the same group key. This is what catches recon → exploit → callback. Implement with a per-group state machine in Redis keyed by `group_key`, with the stage TTL equal to the window.

**`rare`** — fire when a value is unusual against a learned baseline: maintain per-`signature_id` (or per-destination) counts over a trailing `params.baseline_days` and flag occurrences below a frequency floor. Keep it simple and statistical; do not reach for ML here.

**`beacon`** — detect regular callback intervals: for each `(src_ip, dst_ip)` pair, compute the inter-arrival deltas of flow events in the window and fire when the coefficient of variation is below `params.max_cv` with at least `params.min_samples` samples. Genuinely catches C2 that no signature covers.

## Part 3 — The engine

`backend/app/correlation/engine.py`, running in the M5 **worker** container (a second task, not the API process).

- Tick every `CORRELATION_INTERVAL_SECONDS` (default 30). For each enabled rule, evaluate the window `[now - window_seconds - lookback_grace, now]`.
- **Lookback grace** of ~60s covers events that arrive slightly late through the pipeline. Combined with the uniqueness constraint, re-evaluating an overlapping window is safe.
- Deduplicate with `dedup_window_seconds`: before creating a candidate, check Redis for `corr:{rule_id}:{group_key}` and skip if present; set it with the dedup TTL on creation. A port scan that runs for an hour should be one finding, not 120.
- Run rules concurrently with a bounded semaphore, each with a per-rule timeout. One pathological rule must not stall the others — record the timeout in `rule_runs` and continue.
- Score: start from the rule severity, then adjust — higher when the destination is a known asset with open sensitive ports (M3), higher for external→internal direction, higher when event count greatly exceeds the threshold. Keep the scoring function in **one** small, unit-tested module with the weights as named constants.
- Write candidates, then publish to a Redis channel that M8 subscribes to for promotion.

**Backfill**: a CLI command to re-run a rule over a historical time range, so a newly written rule can be tested against real past data before being enabled. This is the feature that makes rule authoring tolerable.

## Part 4 — Endpoints

Router at `/api/correlation`:

- `GET /rules` — any authenticated role. `POST /rules`, `PATCH /rules/{id}`, `DELETE /rules/{id}` — `require_role("admin")`, audited.
- `POST /rules/{id}/test` — admin. Body `{from, to}`. Evaluates the rule against a historical window **without persisting** and returns the candidates it would have produced, with counts. Dry-run before enable is mandatory in the UI flow.
- `GET /rules/{id}/runs` — recent `rule_runs` for debugging.
- `GET /candidates` — filterable by status, rule, severity, time. `POST /candidates/{id}/suppress` — analyst+, with a required reason, audited.
- Validate `match` and `params` JSONB against pydantic models per `rule_type` — a malformed rule must be rejected at write time, not discovered at 3am when it throws inside the engine.

## Part 5 — Frontend

New `/correlation` section (nav item visible to all, mutations admin-only):

- Rules table: name, type, enabled toggle, window, threshold, severity, candidates produced in 24h, last run status. The 24h count is how you spot a rule that is either dead or drowning you.
- Rule editor: a form driven by `rule_type` (the fields change per type), with the match block built from dropdowns — severity, event type, signature — rather than raw JSON. Offer a raw JSON escape hatch for power users.
- **Test panel** inside the editor: pick a time range, run the dry test, see matched candidates and counts before saving or enabling.
- Candidates list: severity, rule, group key, event count, time span, status, and a link into M6 search pre-filtered to the matched events.

## Definition of done

- A threshold rule ("30+ distinct destination ports from one source in 60s") fires on a simulated nmap scan against the monitored network and produces exactly one candidate, not thirty.
- Restarting the worker mid-window creates no duplicate candidates.
- A rule with a deliberately expensive match times out, is recorded in `rule_runs` with the error, and the other rules still complete that tick.
- `POST /rules/{id}/test` over a past window returns candidates and writes nothing to `incident_candidates`.
- A malformed `match` block is rejected with a 422 naming the bad field.
- An `analyst` can suppress a candidate with a reason but cannot edit rules (403); every rule change is in `audit_log`.
- Each candidate's `evidence` lets an analyst reach the underlying events in M6 in one click.
- Tests: each evaluator against fixture event sets (including a beacon with jitter and one without), dedup suppression, scoring function, JSONB schema validation per rule type, idempotency on overlapping windows.

## Out of scope

Incident lifecycle, assignment and resolution (M8), automated containment (M10), IOC-based matching (M12 feeds into `match` later), and machine-learning anomaly detection.
