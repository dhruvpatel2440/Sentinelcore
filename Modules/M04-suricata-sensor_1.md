# M4 — Suricata Sensor — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore is a modular network detection and incident response platform.

- Backend: Python 3.11 / FastAPI (async), SQLAlchemy 2.0 + asyncpg, Alembic
- Frontend: React 18 + Vite + Tailwind, dark slate theme, shell from M2
- Sensor: Suricata IDS
- Env already defined in `.env.example`: `CAPTURE_INTERFACE=eth1`, `MONITORED_NETWORK=192.168.10.0/24`, `SURICATA_EVE_LOG=/var/log/suricata/eve.json`

## What already exists

- M1: RBAC (`require_role`), `audit_log`, Alembic, Redis
- M2: app shell with an admin-only `/sensor` placeholder route
- M3: the **privileged helper** at `helper/` — Unix socket at `/run/sentinelcore/helper.sock`, newline-delimited JSON, named-op dispatch with per-op validation, `subprocess.run` with argument lists and hard timeouts. Extend it here; do not build a second privilege path.

## Non-negotiable rules

- FastAPI runs unprivileged and never as root. Suricata control is a root operation → helper only.
- Never `shell=True`, never string-concatenated commands, argument lists only.
- Sensor control is `admin` only. Every control action is audited.
- No user-supplied input reaches a shell string. Rule content is data, never interpolated into a command.

## Objective

Stand up Suricata as a managed service inside the stack, give the backend safe control over its lifecycle and ruleset, and expose sensor health. This module **produces** `eve.json`; M5 consumes it. Do not parse alerts here.

## Part 1 — The Suricata service

Add a `suricata` service to `docker-compose.yml`:

- Image: `jasonish/suricata:latest-amd64` (or build from the official image), pinned to a specific tag — no floating `latest` in a security tool.
- Capabilities: `cap_add: [NET_ADMIN, NET_RAW, SYS_NICE]`. Do **not** use `privileged: true`.
- Networking: to see real traffic it needs `network_mode: host` on Linux, or an interface mapped into the container. Document the tradeoff in the service comments — with `network_mode: host` it cannot join `sentinelcore-network`, so log sharing happens over the volume, not the network.
- Volumes:
  - `suricata_logs:/var/log/suricata` — also mounted **read-only** into `backend` so M5 can tail `eve.json`
  - `suricata_rules:/var/lib/suricata/rules`
  - `./docker/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro`
- `restart: unless-stopped`

`docker/suricata/suricata.yaml`:

- `HOME_NET` set from `MONITORED_NETWORK`, `EXTERNAL_NET: "!$HOME_NET"`
- `af-packet` on `CAPTURE_INTERFACE`, cluster type `cluster_flow`
- EVE JSON output enabled with `alert`, `flow`, `dns`, `http`, `tls`, `stats` event types — M5 and M12 need more than alerts
- Log rotation configured so `eve.json` cannot fill the disk; M5's tailer must survive rotation, so document the rotation mechanism chosen here
- Sane `max-pending-packets` and a `stats` interval of 30s

## Part 2 — Helper ops

Add to `helper/` — each a **named, individually validated** handler, consistent with the M3 pattern:

| op | params | behaviour |
|---|---|---|
| `suricata_status` | none | process running?, pid, uptime, version, current ruleset checksum |
| `suricata_start` | none | start the service, return status |
| `suricata_stop` | none | graceful stop (SIGTERM, then escalate after a timeout) |
| `suricata_reload_rules` | none | `suricatasc -c ruleset-reload-nonblocking` or SIGUSR2 — reload without dropping packets, never a full restart |
| `suricata_test_config` | none | `suricata -T` config/ruleset validation, return pass/fail + output |
| `suricata_write_rules` | `{filename, content_sha256}` | move an already-staged rule file into place after checksum verification |

Rule content is **never** passed through the socket as a shell argument. The backend writes the candidate rule file to a shared staging volume and the helper verifies the SHA-256, validates it with `suricata -T`, and only then moves it into the rules directory. A failed validation leaves the live ruleset untouched.

Filenames are validated against `^[a-zA-Z0-9_-]+\.rules$` — no path separators, no traversal, no absolute paths.

## Part 3 — Models

`backend/app/models/sensor.py` (additions to the canonical table list — note them in the migration message):

- `rule_sources` — `id`, `name`, `url`, `enabled`, `last_updated_at`, `last_status`, `rule_count`
- `rule_overrides` — `id`, `sid` bigint, `action` enum(disabled/enabled/threshold), `params` JSONB, `reason` text, `created_by` fk users, `created_at`. Unique on `sid`.
- `sensor_events` — `id`, `action` enum(start/stop/reload/rules_update/config_test), `status`, `detail` JSONB, `user_id` fk, `created_at`. Sensor-specific operational history; `audit_log` still records the action too.

## Part 4 — Rule management service

`backend/app/services/ruleset.py`

- Fetch enabled `rule_sources` over HTTPS with a timeout and a size cap. Emerging Threats Open is the sensible default source.
- Verify the archive, extract **only** `.rules` members, reject any member whose normalized path escapes the extraction directory (zip-slip guard). Never extract with a blanket `extractall`.
- Apply `rule_overrides`: comment out disabled SIDs, apply thresholds.
- Compose the final rule file into the staging volume, compute the SHA-256, call `suricata_test_config`, then `suricata_write_rules` + `suricata_reload_rules`.
- **Rollback on failure**: keep the previous ruleset; if validation or reload fails, restore it and surface the error. A bad rule update must never leave the sensor down.
- Record the outcome in `sensor_events` and `audit_log`.

## Part 5 — Endpoints

Router at `/api/sensor`, every mutating route `require_role("admin")`:

- `GET /status` — viewer-readable. Running state, uptime, version, rule count, ruleset checksum, last reload time, and freshness of `eve.json` (mtime age — if it is older than the stats interval, the sensor is up but not seeing traffic, which is a distinct and important failure).
- `GET /stats` — packet/drop counters parsed from the EVE `stats` events. Surface **drop rate** prominently; a sensor dropping packets is silently missing attacks.
- `POST /start`, `POST /stop`, `POST /reload` — audited, return the new status.
- `GET /rules/sources`, `POST /rules/sources`, `PATCH /rules/sources/{id}` — manage feeds.
- `POST /rules/update` — 202 + background task running the full fetch → compose → validate → reload pipeline.
- `GET /rules/overrides`, `POST /rules/overrides`, `DELETE /rules/overrides/{sid}` — tune noisy signatures.
- `POST /config/test` — dry-run validation.

## Part 6 — Frontend

Replace the `/sensor` placeholder (admin-only route from M2):

- Status card: running/stopped indicator, uptime, version, rule count, last reload, `eve.json` freshness with an explicit warning state when stale.
- Throughput card: packets seen, drops, drop percentage over time (a small sparkline is enough).
- Control row: Start / Stop / Reload rules, each with a confirm modal — stopping the sensor blinds the platform and the UI should say so plainly.
- Rule sources table with enable toggles and an "Update now" action that shows live progress and the resulting rule count.
- Rule overrides table: add by SID with a required reason field, list with the author and date. Reason is required because six months later nobody remembers why a signature was silenced.

## Definition of done

- `docker compose up` brings Suricata up; it writes to `eve.json` and the backend can read that file read-only.
- `GET /api/sensor/status` reports running, a version, and a non-zero rule count.
- A rule update pulls a live feed, validates, reloads without a restart, and the rule count changes; a deliberately corrupted rule file fails validation and the **previous ruleset stays live**.
- Disabling a SID via an override removes it from the composed ruleset after the next update.
- A `viewer` and an `analyst` both get 403 on start/stop/reload; every control action lands in `audit_log` and `sensor_events`.
- Stopping the sensor is reflected in the UI within one status poll, with the stale-`eve.json` warning appearing afterwards.
- Tests: rules filename validator (traversal attempts), zip-slip guard on archive extraction, override application to a sample rule file, rollback path when `suricata -T` fails.

## Out of scope

Parsing alerts into the `events` table (M5), correlation (M7), custom rule authoring UI, multi-sensor fleets, and PCAP replay through Suricata (M11).
