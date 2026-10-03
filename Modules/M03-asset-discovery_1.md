# M3 — Asset Discovery (+ Privileged Helper) — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore is a modular network detection and incident response platform.

- Backend: Python 3.11 / FastAPI (async), SQLAlchemy 2.0 + asyncpg, Alembic
- Frontend: React 18 + Vite + Tailwind, dark slate theme, shell and shared components from M2
- Discovery tooling: Nmap + Scapy
- Monitored scope comes from env: `MONITORED_NETWORK` (e.g. `192.168.10.0/24`), `PROTECTED_IPS`

## What already exists

- M1: users, RBAC dependencies (`require_role`), `audit_log` + `audit.record()`, Alembic, Redis
- M2: app shell, `/assets` placeholder route, shared `Table`, `Badge`, `PageHeader`, `Modal`, `useToast`

## Non-negotiable rules — this module is where they start to bite

- **The FastAPI backend runs unprivileged and never as root.**
- **All root operations go through the privileged helper over a Unix socket.** Nmap SYN scanning and ARP work need raw sockets; the API must not have them.
- **Never `shell=True`. Never build a shell command by string concatenation.** Argument lists only.
- **Every IP, CIDR and port is validated with strict typed checks** before it goes anywhere near the helper.
- No user-supplied input ever reaches a shell string.
- Every write action is audited.

## Part 1 — The privileged helper

This is the security spine of the whole platform. M4 and M10 will extend it. Build it carefully and generically enough to grow, strictly enough that it cannot be abused.

`helper/` at the repo root — a standalone Python process, its own Dockerfile, no FastAPI, no SQLAlchemy, minimal dependencies.

**Transport.** Unix domain socket at `/run/sentinelcore/helper.sock`. Owned `root:sentinelcore`, mode `0660`. The backend container joins the `sentinelcore` group and mounts the socket directory. No TCP listener, ever.

**Protocol.** Newline-delimited JSON, one request → one response.

```json
{"op": "nmap_scan", "request_id": "<uuid>", "params": {"targets": ["192.168.10.0/24"], "ports": "1-1024", "mode": "tcp_syn"}}
{"ok": true, "request_id": "<uuid>", "data": {...}}
{"ok": false, "request_id": "<uuid>", "error": {"code": "invalid_target", "message": "..."}}
```

**Dispatch.** A dict of `op` → handler. An unknown `op` is rejected outright. There is no generic "run this command" op and there never will be — adding a capability means adding a named, validated handler.

**Validation inside the helper, not only in the caller.** The helper re-validates everything as if the backend were hostile, because the threat model is a compromised API container:

- Targets parse as `ipaddress.ip_network` / `ip_address`. Reject anything outside `MONITORED_NETWORK`. Reject loopback, link-local, and multicast.
- Port specs match a strict grammar (`\d+(-\d+)?(,\d+(-\d+)?)*`), each port 1–65535, ranges ordered, capped at a sane count.
- `mode` is an enum mapped to a fixed flag list — the caller never supplies nmap flags.

**Execution.** `subprocess.run([...], shell=False, timeout=..., capture_output=True)` with an absolute binary path resolved once at startup. Hard timeout on every op. Concurrency limit (one scan at a time) so a caller cannot fork-bomb the host. Structured logging of every request with its `request_id`, the resolved argv, and the outcome.

`backend/app/services/helper_client.py` — async client: connect, send, await response, typed exceptions (`HelperUnavailable`, `HelperRejected`, `HelperTimeout`). Never let a helper failure return a 500 with a raw traceback; map to a clean 502/503 with a safe message.

Add the helper to `docker-compose.yml`: `cap_add: [NET_ADMIN, NET_RAW]` (not `privileged: true`), a shared volume for the socket directory, `restart: unless-stopped`.

## Part 2 — Models

`backend/app/models/asset.py`

| column | type | notes |
|---|---|---|
| `id` | UUID pk | |
| `ip_address` | inet | unique, indexed |
| `mac_address` | macaddr | nullable — only known from ARP on-segment |
| `hostname` | str(255) | nullable |
| `vendor` | str(128) | nullable, OUI lookup from MAC |
| `os_guess` | str(128) | nullable |
| `first_seen` / `last_seen` | timestamptz | indexed |
| `is_active` | bool | false once it stops appearing in scans |
| `notes` | text | nullable, analyst-editable |

`backend/app/models/asset_port.py` — `id`, `asset_id` fk (cascade delete), `port` int, `protocol` enum(tcp/udp), `state` enum(open/filtered/closed), `service` str, `product` str, `version` str, `first_seen`, `last_seen`. Unique on `(asset_id, port, protocol)`.

`backend/app/models/scan.py` — `id`, `scan_type`, `targets` JSONB, `status` enum(queued/running/completed/failed), `started_at`, `finished_at`, `hosts_found`, `error`, `requested_by` fk users. (This table extends the canonical list in `CLAUDE.md`; note the addition in the migration message.)

## Part 3 — Discovery service

`backend/app/services/discovery.py`

- `run_discovery(scan_id)` — background task: mark running, call the helper, parse, reconcile, mark completed. Wrap everything so a crash marks the scan `failed` with the error recorded rather than leaving it stuck in `running`.
- Parse nmap XML output with `xml.etree` — **not** regex over human-readable output. Ask the helper for `-oX -`.
- Scapy ARP sweep as a second helper op (`arp_sweep`) for MAC + vendor on the local segment.
- **Reconciliation, not replacement**: upsert on `ip_address`. Update `last_seen` and changed fields; insert new assets; mark assets missing from the last N scans as `is_active = false` rather than deleting them. History matters in an IR tool.
- Emit audit entries for scan start and completion.

## Part 4 — Endpoints

Router at `/api/assets`:

- `POST /scan` — `require_role("admin")`. Body: optional `targets` (defaults to `MONITORED_NETWORK`), `ports`, `mode`. Validates with pydantic `IPvAnyNetwork` types, creates the `scan` row, dispatches the background task, returns 202 with the scan id. Refuse a new scan while one is `running` (409).
- `GET /` — paginated, filterable by `is_active`, `q` (ip/hostname substring), `has_open_port`. Sortable by `last_seen`, `ip_address`.
- `GET /{id}` — asset with its ports.
- `PATCH /{id}` — `require_role("analyst", "admin")`, notes and hostname override only. Audited.
- `GET /scans` and `GET /scans/{id}` — scan history and status for polling.

## Part 5 — Frontend

Replace the `/assets` placeholder:

- Asset table: IP, hostname, MAC/vendor, open-port count, last seen (relative), active badge. Filter bar + search. Uses the shared `Table`.
- Detail drawer/page: identity block, ports table (port, proto, service, product, version, state, last seen), notes editor for analyst+.
- "Run scan" button, admin-only, opens a modal with target/port/mode inputs prefilled from `MONITORED_NETWORK`. After dispatch, poll `GET /scans/{id}` and show a progress state; toast on completion and refresh the table.
- Scan history panel with status badges and durations.

## Definition of done

- The backend container has no `NET_RAW`/`NET_ADMIN` capability, runs as a non-root user, and asset discovery still works end to end.
- A scan request with `targets: ["8.8.8.8/32"]` (outside `MONITORED_NETWORK`) is rejected by the API **and independently by the helper** when the client check is bypassed.
- A port spec of `1-1024; rm -rf /` is rejected by the grammar, not executed, not logged as a shell string.
- Killing the helper mid-scan marks the scan `failed` with a readable error, and the API stays up.
- Re-running a scan updates `last_seen` and port state instead of duplicating assets; a host that disappears is flagged inactive, not deleted.
- A `viewer` gets 403 on `POST /scan`; every scan appears in `audit_log` with the requesting user.
- Tests: target/port validator unit tests (including injection-shaped inputs), nmap XML parser against a recorded fixture, upsert reconciliation, RBAC on the scan endpoint.

## Out of scope

Credentialed scanning, agent-based inventory, vulnerability scanning or CVE matching, network topology mapping.
