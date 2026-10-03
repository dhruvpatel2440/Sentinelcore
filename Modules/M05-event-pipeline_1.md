# M5 — Event Pipeline — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore is a modular network detection and incident response platform.

- Backend: Python 3.11 / FastAPI (async), SQLAlchemy 2.0 + asyncpg, Alembic
- DB: PostgreSQL 16 | Cache + queues: Redis
- Deploy: Docker Compose

## What already exists

- M1: Alembic, Redis service, `audit_log`, RBAC
- M3: `assets` / `asset_ports` tables — events get enriched against these
- M4: Suricata writing EVE JSON to `SURICATA_EVE_LOG` (`/var/log/suricata/eve.json`), on a volume mounted **read-only** into the backend. Event types enabled: `alert`, `flow`, `dns`, `http`, `tls`, `stats`.

## Objective

Get Suricata's EVE output into PostgreSQL reliably, continuously, and without losing or duplicating events. This is the data backbone for M6 (search), M7 (correlation), M8 (incidents) and M12 (intel enrichment) — every one of them is only as good as this pipeline.

## Architecture

Three stages, deliberately decoupled:

```
eve.json ──▶ tailer ──▶ Redis Stream ──▶ batch writer ──▶ PostgreSQL events
            (reader)      (buffer)         (consumer)
```

The buffer exists so a database hiccup or a slow write does not stall the reader and cause Suricata's log to grow unbounded. Run the pipeline as a **separate `worker` container** from the API — add it to `docker-compose.yml` sharing the backend image with a different command. The API process must never tail a file in a background thread; a restart of the API would then lose the reader position.

## Part 1 — The tailer

`backend/app/pipeline/tailer.py`

- Open `eve.json`, seek to the last persisted offset, read line-delimited JSON forever.
- **Survive log rotation**: track the file's `(st_dev, st_ino)`. When the inode at the path changes, drain the remaining lines from the old handle, then reopen and reset the offset to 0. Rotation happening mid-read is the single most common cause of silent event loss — handle it explicitly.
- **Persist the read position** in Redis (`pipeline:eve:offset` with the inode) after each batch, so a worker restart resumes rather than replaying the whole file or skipping ahead.
- Truncation without rotation (`st_size` < current offset) resets the offset to 0.
- A malformed line is counted and skipped, never fatal. Suricata can emit a partial line if it is killed mid-write.
- Push raw records to a Redis Stream (`XADD` on `stream:events`) with a `MAXLEN ~` cap so an unavailable consumer cannot exhaust memory.

## Part 2 — Normalization

`backend/app/pipeline/normalize.py`

Map an EVE record to the `events` schema. Handle each enabled `event_type`; ignore `stats` (M4 consumes those separately).

- Timestamps: EVE emits ISO 8601 with an offset. Parse to timezone-aware UTC. Never store naive timestamps.
- Suricata severity is 1 (highest) to 4. Map it to the platform's scale and **document the mapping in one place** — `1→critical, 2→high, 3→medium, 4→low` — because M2's `Badge` colours, M7's scoring and M9's reports all depend on it agreeing.
- Preserve the entire original record in a `raw` JSONB column. During an investigation the field you did not model is always the one you need.
- Compute a `dedup_key`: a SHA-256 over `(timestamp_truncated_to_second, signature_id, src_ip, src_port, dst_ip, dst_port, proto)`. Suricata can emit the same alert twice across a reload.

## Part 3 — Model

`backend/app/models/event.py`

| column | type | notes |
|---|---|---|
| `id` | bigint pk identity | |
| `ts` | timestamptz | event time from EVE, **not** insert time |
| `ingested_at` | timestamptz | default now() |
| `event_type` | enum | alert / flow / dns / http / tls |
| `src_ip` / `dst_ip` | inet | indexed |
| `src_port` / `dst_port` | int | nullable |
| `proto` | str(8) | |
| `signature` | text | nullable (non-alert types) |
| `signature_id` | bigint | nullable, indexed |
| `rev` | int | signature revision |
| `category` | str(128) | |
| `severity` | enum | critical / high / medium / low / info |
| `src_asset_id` / `dst_asset_id` | UUID fk assets | nullable, `ON DELETE SET NULL` |
| `flow_id` | bigint | Suricata's flow id, indexed — ties alert to flow to http/dns |
| `dedup_key` | bytea | unique |
| `raw` | JSONB | full original record |

Indexes: `(ts DESC)` primary read path; `(src_ip, ts DESC)`; `(dst_ip, ts DESC)`; `(signature_id, ts DESC)`; `(severity, ts DESC)`; GIN on `raw` only if M6 needs it — measure first, it is expensive to maintain.

**Partitioning**: declare `events` as range-partitioned by `ts` (monthly) from the start. Retrofitting partitioning onto a table with 50M rows is a migration you do not want to write later. Include a small job that pre-creates the next month's partition.

## Part 4 — The writer

`backend/app/pipeline/writer.py`

- Redis consumer group (`XREADGROUP`) so the work is acknowledged, and an unacked batch is redelivered after a crash — at-least-once delivery, with `dedup_key` providing idempotency.
- Batch: up to 500 records or 2 seconds, whichever first. Insert with `INSERT ... ON CONFLICT (dedup_key) DO NOTHING`.
- `XACK` only **after** the transaction commits. Acking first turns a rollback into silent data loss.
- Enrichment in the same pass: resolve `src_ip` / `dst_ip` to `asset_id` using a Redis-cached IP→asset map, refreshed on a TTL and invalidated when M3 completes a scan.
- Metrics to Redis for the health endpoint: lines read, events written, duplicates skipped, parse errors, current lag (stream length), last write timestamp.

## Part 5 — Retention

`backend/app/pipeline/retention.py` — a scheduled job (APScheduler in the worker, or a loop with a sleep):

- Drop whole partitions older than `EVENT_RETENTION_DAYS` (new setting, default 90). Dropping a partition is instant; `DELETE FROM events WHERE ts < …` on a large table will lock and bloat.
- Never delete an event referenced by an open incident — check before dropping and log a warning instead, so M8's evidence trail survives.

## Part 6 — Observability endpoint

Router at `/api/pipeline`, `require_role("admin")` for control, viewer-readable status:

- `GET /status` — reader position, stream length (lag), events/sec over the last minute, parse-error count, last event timestamp, per-stage last-heartbeat.
- The most useful signal is **lag** plus **time since last event**. Surface both; the M2 shell can show a warning when the pipeline is stalled.

## Definition of done

- With Suricata generating alerts (`curl` a known-bad-signature test, or replay traffic), events appear in `events` within a couple of seconds.
- Rotating `eve.json` mid-stream loses no events and creates no duplicates.
- Killing the worker mid-batch and restarting it resumes from the persisted offset — verify the count is exactly right, not approximately.
- Stopping PostgreSQL for 30 seconds does not crash the tailer; the stream buffers and drains on recovery.
- A replayed duplicate alert inserts once thanks to `dedup_key`.
- Events from a scanned host carry a populated `src_asset_id`.
- `GET /api/pipeline/status` reports non-zero throughput and near-zero lag under normal load.
- Tests: rotation and truncation handling with a fake file, normalizer against recorded EVE fixtures for each event type, dedup key stability, writer idempotency on redelivery, severity mapping.

## Out of scope

Querying and filtering the events (M6), correlation rules (M7), incident creation (M8), IOC matching (M12), and any UI beyond the pipeline status widget.
