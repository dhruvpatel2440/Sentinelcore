# M8 — Incident Management — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore is a modular network detection and incident response platform.

- Backend: Python 3.11 / FastAPI (async), SQLAlchemy 2.0 + asyncpg, Alembic
- Frontend: React 18 + Vite + Tailwind, dark slate theme, shell from M2
- DB: PostgreSQL 16 | Redis

## What already exists

- M1: users, RBAC (`require_role`), `audit_log` + `audit.record()`
- M2: app shell with an `/incidents` placeholder route, shared `Table`, `Badge`, `Modal`, `useToast`
- M3: `assets`
- M5: `events` (partitioned by `ts`)
- M6: event search, used for linking events into an incident
- M7: `incident_candidates` with `rule_id`, `group_key`, `evidence`, `score`, `status`, and a Redis publish on creation

## Role model — this module defines what the roles actually mean

- `viewer` — read incidents, read comments. No state changes.
- `analyst` — triage and resolve: assign, comment, change status, link/unlink events, close as resolved or false positive.
- `admin` — everything an analyst can do, plus delete, reopen closed incidents, and override assignment.

## Objective

Give analysts a queue they can work through and a record that survives scrutiny. Two tables from the canonical schema land here: `incidents` and `incident_history`. The history table is not optional bookkeeping — in an IR tool the audit trail *is* the product.

## Part 1 — Models

`backend/app/models/incident.py`

| column | type | notes |
|---|---|---|
| `id` | UUID pk | |
| `number` | bigint | human-facing sequential id (`INC-1042`), from a sequence — UUIDs are unusable verbally |
| `title` | str(255) | |
| `description` | text | seeded from the rule description |
| `status` | enum | `new` \| `triage` \| `investigating` \| `contained` \| `resolved` \| `false_positive` |
| `severity` | enum | critical / high / medium / low / info |
| `score` | int | from M7, adjustable |
| `src_ip` / `dst_ip` | inet | nullable, the primary indicators |
| `asset_id` | UUID fk assets | nullable, `ON DELETE SET NULL` |
| `assigned_to` | UUID fk users | nullable, `ON DELETE SET NULL` |
| `rule_id` | UUID fk correlation_rules | nullable — manual incidents have none |
| `candidate_id` | UUID fk incident_candidates | nullable, unique |
| `event_count` | int | denormalized, maintained on link/unlink |
| `first_event_ts` / `last_event_ts` | timestamptz | the incident's real time span |
| `opened_at` | timestamptz | default now |
| `acknowledged_at` | timestamptz | first move out of `new` — this is your MTTA |
| `closed_at` | timestamptz | nullable — MTTR |
| `closed_by` | UUID fk users | nullable |
| `resolution_note` | text | **required** to close |

Indexes: `(status, severity, opened_at DESC)` for the queue, `(assigned_to, status)`, `(src_ip)`, `(opened_at DESC)`.

`incident_events` — join table: `incident_id`, `event_id`, `linked_by` fk users nullable (null = linked automatically), `linked_at`. PK on `(incident_id, event_id)`. Events are linked, never copied; M5's retention job must skip events referenced here.

`incident_history` — `id`, `incident_id` fk cascade, `user_id` fk nullable, `action` enum(`created`/`status_changed`/`assigned`/`severity_changed`/`commented`/`events_linked`/`events_unlinked`/`reopened`/`closed`), `from_value`, `to_value`, `note` text, `created_at` indexed. **Append-only** — no update or delete endpoints, ever. Enforce it with a database trigger rejecting UPDATE and DELETE, not just by convention.

## Part 2 — Status machine

Legal transitions, enforced server-side in one place (`backend/app/services/incident_state.py`), never in the UI alone:

```
new ──▶ triage ──▶ investigating ──▶ contained ──▶ resolved
 │         │             │                │            │
 └─────────┴─────────────┴────────────────┴──▶ false_positive
                                                    │
resolved / false_positive ──▶ (admin only) ──▶ investigating   [reopen]
```

- Any forward move from `new` sets `acknowledged_at` if unset.
- `resolved` and `false_positive` require a non-empty `resolution_note` — reject with 422 otherwise. Six months later, "closed" with no reason is worthless.
- `closed_at` / `closed_by` set on entering a terminal state, cleared on reopen (and the reopen is recorded in history).
- An illegal transition returns 409 naming both states. Every transition writes `incident_history` **and** `audit_log` in the same transaction as the incident update — if the history insert fails, the status change rolls back.

## Part 3 — Promotion from candidates

`backend/app/services/promotion.py`, running in the M5/M7 worker:

- Subscribe to M7's Redis channel; on a new candidate, decide promote or hold.
- **Auto-promote** when `candidate.score >= AUTO_PROMOTE_SCORE` (setting, default corresponds to high/critical). Lower-scoring candidates stay in the candidates list for manual promotion.
- **Merge before creating.** If an open (non-terminal) incident already exists with the same `rule_id` and overlapping indicator (`src_ip`) within `INCIDENT_MERGE_WINDOW_MINUTES` (default 60), link the new events to that incident, extend `last_event_ts`, bump `event_count`, and record `events_linked` in history. Creating a fresh incident per candidate recreates exactly the alert fatigue M7 exists to prevent.
- On creation, set the candidate's `status = promoted` and `incident_id`, and write the `created` history entry with `user_id` null.
- Title generation from the rule: `"{rule.name} from {src_ip}"` — deterministic, no cleverness.

## Part 4 — Endpoints

Router at `/api/incidents`:

- `GET /` — all roles. Filters: `status` (repeatable, default excludes terminal states), `severity`, `assigned_to` (incl. `me` and `unassigned`), `q` (title/number/ip), `from`/`to`, `asset_id`. Keyset pagination like M6. Sort by opened_at, severity, or score.
- `GET /{id}` — incident with assignee, rule, asset, counts, and the last N history entries.
- `POST /` — `require_role("analyst","admin")`. Manual incident creation with optional event ids to link.
- `PATCH /{id}` — analyst+. Title, description, severity, score, assignee. Each changed field writes its own history row.
- `POST /{id}/status` — analyst+, `{status, note}`, runs through the state machine. Reopen from terminal is admin-only.
- `POST /{id}/assign` — analyst+, `{user_id|null}`. An analyst may assign to themselves or unassign; reassigning another analyst's incident is admin-only.
- `POST /{id}/comments` — analyst+, writes a `commented` history row. Comments live in history, not a separate table — one chronological narrative.
- `GET /{id}/events` — paginated linked events (joins to M5/M6 projection).
- `POST /{id}/events` / `DELETE /{id}/events/{event_id}` — analyst+, link/unlink, maintains `event_count` and the ts span, history-recorded.
- `GET /{id}/history` — full trail, chronological.
- `DELETE /{id}` — admin only, soft delete (`deleted_at`), audited. Hard deletion of an IR record is not offered.
- `GET /stats/summary` — open by severity, unassigned count, mean time to acknowledge and to resolve over a window, top rules by incident volume. M2's dashboard and M9's reports both consume this.

Concurrency: accept an `If-Match` / `version` on `PATCH` and status changes and return 409 on mismatch, so two analysts working the same incident do not silently overwrite each other.

## Part 5 — Frontend

Replace the `/incidents` placeholder.

**Queue view** — the default landing page for an analyst:

- Saved-filter tabs: *My open*, *Unassigned*, *All open*, *Critical*, *Recently closed*.
- Table: number, severity badge, title, status pill, assignee avatar/initials, age (colour-shifted as it grows), event count, last activity.
- Bulk actions on selected rows: assign, change status, close with a shared note. Bulk close still requires the note.
- Auto-refresh every 30s with a subtle "N new" indicator rather than a jarring reload that moves rows under the cursor.

**Detail view** (`/incidents/:number`):

- Header: number, title (inline editable), severity and status controls, assignee picker, age and time-to-acknowledge.
- Left column: description, indicators (src/dst with pivots into M6 and M3), linked asset card.
- Center: **linked events** table with the same columns as M6, an "Add events" action opening an M6-style search modal scoped to the incident's time window, and per-row unlink.
- Right column: **activity timeline** from `incident_history` — every status change, assignment, comment and link, with author and relative time. A comment box at the bottom, posting into the same timeline.
- Close flow: a modal that requires the resolution note and offers `resolved` or `false_positive`, with the note pre-populated by a short template.
- Keyboard shortcuts in the queue: `j`/`k` to move, `Enter` to open, `a` to assign to me. Analysts working a queue all day will use them.

## Definition of done

- A high-score candidate from M7 becomes an incident automatically with its events linked and `created` in history.
- A second candidate for the same rule and source IP within the merge window links into the existing incident instead of creating a second one.
- Closing without a resolution note returns 422; closing with one sets `closed_at`, `closed_by`, and writes history.
- An illegal transition (`new` → `resolved` directly, if not permitted by the machine) returns 409 naming both states.
- A `viewer` gets 403 on every mutation; an `analyst` cannot reassign another analyst's incident; an `admin` can, and can reopen a closed incident.
- `UPDATE` or `DELETE` against `incident_history` is rejected by the database trigger.
- Two concurrent `PATCH`es with a stale version produce a 409, not a lost update.
- MTTA/MTTR in `/stats/summary` match hand-calculated values for a seeded dataset.
- Unlinking an event decrements `event_count` and recalculates the ts span correctly.
- Tests: state machine transition matrix, merge window logic, note-required guard, RBAC matrix across all mutations, history append-only trigger, optimistic-concurrency conflict.

## Out of scope

Report generation (M9), firewall containment actions triggered from an incident (M10 — it will add a button here), PCAP attachment (M11), IOC enrichment (M12), email/Slack notifications, and SLA timers.
