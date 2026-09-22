# M10 — Firewall Containment — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore is a modular network detection and incident response platform.

- Backend: Python 3.11 / FastAPI (async), SQLAlchemy 2.0 + asyncpg, Alembic
- Frontend: React 18 + Vite + Tailwind, dark slate theme, shell from M2
- Enforcement: iptables on the host, reached only through the privileged helper
- Env: `MONITORED_NETWORK=192.168.10.0/24`, `PROTECTED_IPS=192.168.10.1,192.168.10.2`

## What already exists

- M1: users, RBAC (`require_role`), `audit_log` + `audit.record()`
- M2: app shell with an admin-only `/firewall` placeholder route
- M3: the **privileged helper** (`helper/`) — Unix socket, newline-delimited JSON, named-op dispatch, per-op validation, `subprocess.run` with argument lists, hard timeouts. Extend it; do not create a second privilege path.
- M4: added sensor ops to the same helper — follow that pattern exactly
- M8: `incidents` — containment actions link back to the incident that justified them

## This is the most dangerous module in the platform

Everything here can take the network down. A wrong rule blocks the gateway and the platform loses the ability to un-block it. The guardrails below are not suggestions.

- **Gateway, DNS servers and the platform's own IPs can NEVER be blocked.** Enforced in the helper, independently of the API.
- **Every rule carries a mandatory TTL.** No permanent blocks exist in this system, at any layer, through any code path.
- The API runs unprivileged; only the helper touches iptables.
- Never `shell=True`, never string concatenation, argument lists only.
- All IPs, CIDRs and ports validated with strict typed checks on both sides of the socket.
- `admin` only. Every action audited, successes and refusals alike.

## Part 1 — The protection guard

`helper/guards.py` — computed at helper startup and refreshed periodically, never supplied by the caller:

1. **Default gateway(s)** — read from the kernel routing table (`/proc/net/route` or netlink), not from config. A config value can drift from reality; the routing table cannot.
2. **DNS servers** — parsed from `/etc/resolv.conf` plus any configured override.
3. **The host's own addresses** — every IP on every interface.
4. **`PROTECTED_IPS`** from env.
5. **Anything outside `MONITORED_NETWORK`** — this platform contains hosts on the network it watches; it is not an internet firewall. Refuse targets outside that scope.

`is_protected(ip) -> (bool, reason)` checks membership in the union, including whether a supplied **CIDR overlaps** any protected address. A `/24` block that happens to contain the gateway must be refused — checking only exact IP equality is the bug that takes the network down.

A refusal returns a structured error with the reason. The helper logs every refusal at warning level with the caller's request id.

Unit-test this module harder than anything else in the codebase: exact match, CIDR containment, `0.0.0.0/0`, the broadcast and network addresses, IPv6 forms if the host has any, and a target equal to the helper's own address.

## Part 2 — Helper ops

| op | params | behaviour |
|---|---|---|
| `fw_apply` | `{action_id, target, direction, protocol?, port?, comment}` | insert an iptables DROP rule |
| `fw_revoke` | `{action_id}` | delete the rule matching that action id |
| `fw_list` | none | list active SentinelCore-managed rules |
| `fw_reconcile` | `{expected: [...]}` | compare kernel state to the expected set, report drift |

Implementation rules:

- All managed rules live in a **dedicated chain** (`SENTINELCORE`), created by the helper at startup and jumped to from `INPUT` and `FORWARD`. Never insert into `INPUT` directly — a dedicated chain means the platform's rules are identifiable, listable, and removable as a unit without touching anything else on the host.
- Every rule carries `-m comment --comment "sentinelcore:<action_id>"`. This is how a rule is located for revocation without relying on rule numbers, which shift as rules are added and deleted.
- `target` accepts an IP or CIDR, validated and guard-checked **inside** the helper, after the API has already checked it. Assume the API is compromised.
- `direction`: `inbound` (match `-s`), `outbound` (match `-d`), or `both` (two rules). Enum, mapped to fixed flags.
- `protocol` / `port` optional, strictly validated (`tcp`/`udp` only, port 1–65535).
- Idempotent: applying an `action_id` that already exists in the chain succeeds without duplicating. Revoking one that is absent succeeds — the desired end state is what matters.
- **Persistence is deliberately absent.** Managed rules must not survive a host reboot; the database is the source of truth and reconciliation restores what should still be live. A stale DROP surviving a reboot with no record is exactly the failure mode TTLs exist to prevent.

## Part 3 — Model

`backend/app/models/firewall_action.py` — the canonical `firewall_actions` table:

| column | type | notes |
|---|---|---|
| `id` | UUID pk | used as the iptables comment tag |
| `target` | cidr | stored as CIDR; a single IP is a `/32` |
| `direction` | enum | inbound / outbound / both |
| `protocol` | str(4) | nullable |
| `port` | int | nullable |
| `reason` | text | **required** |
| `incident_id` | UUID fk incidents | nullable, `ON DELETE SET NULL` |
| `ttl_seconds` | int | **NOT NULL**, checked `> 0` |
| `expires_at` | timestamptz | NOT NULL, indexed — `created_at + ttl` |
| `status` | enum | `pending` / `active` / `expired` / `revoked` / `failed` |
| `created_by` | UUID fk users | NOT NULL |
| `created_at` | timestamptz | |
| `revoked_at` / `revoked_by` | | nullable |
| `error` | text | nullable |
| `applied_at` | timestamptz | when the helper confirmed |

Enforce the TTL bounds in a **database check constraint** as well as in pydantic: `ttl_seconds BETWEEN 60 AND 86400` (min 1 minute, max 24 hours, both configurable but bounded). A layer that can be bypassed is not a control.

## Part 4 — Service and expiry worker

`backend/app/services/firewall.py`

- `apply(request, user)` — validate, guard-check (API side), persist as `pending`, call the helper, then mark `active` + `applied_at` or `failed` + `error`. Persist **before** calling the helper: a rule applied to the kernel with no database row is an orphan nobody can find.
- `revoke(action_id, user, reason)` — call the helper, mark `revoked`, record who and when.
- Rate-limit: cap active blocks (`MAX_ACTIVE_BLOCKS`, default 100) and refuse beyond it. Containment automation going wrong should hit a wall, not a dead network.

**Expiry worker** (in the existing worker container), every 15 seconds:

- Select `active` rows with `expires_at <= now()`, revoke each via the helper, mark `expired`. Log every expiry.
- On failure, retry with backoff and alert after N attempts — an un-expirable block is an incident in itself.

**Reconciliation**, on worker startup and every 5 minutes:

- Compare `fw_list` against `active` rows. Kernel rule with no DB row → remove it (an orphan). DB row `active` with no kernel rule → re-apply if unexpired, else mark `expired`. Record drift in the audit log; silent drift between intent and enforcement is how a SOC ends up trusting a block that does not exist.

## Part 5 — Endpoints

Router at `/api/firewall`, every mutating route `require_role("admin")`:

- `GET /actions` — viewer-readable. Filter by status, target, incident, time. Show remaining TTL as a computed field.
- `POST /actions` — body `{target, direction, protocol?, port?, ttl_seconds, reason, incident_id?}`. `reason` and `ttl_seconds` required. Returns 201 with the action, or **422 with the protection reason** when the guard refuses. A guard refusal is still audited (`firewall.blocked_attempt`) — an attempt to block the gateway is a signal worth keeping.
- `DELETE /actions/{id}` — revoke early, optional reason, audited.
- `POST /actions/{id}/extend` — body `{additional_seconds}`, capped at the same maximum total. Extending is how a legitimate long containment happens: explicitly, repeatedly, and on the record.
- `GET /status` — helper reachability, chain present, active rule count, kernel/DB drift count, last reconciliation time.
- `POST /reconcile` — force a reconciliation pass.

## Part 6 — Frontend

Replace the `/firewall` placeholder (admin-only route):

- **Active blocks** table: target, direction, port/proto, reason, linked incident, created by, **countdown to expiry** as a live timer, and Revoke / Extend actions. The live countdown is the point — an operator should always see how long containment has left.
- **New block** modal: target input with inline validation that calls a lightweight pre-check endpoint so a protected target is rejected *before* submission with the reason shown ("192.168.10.1 is the default gateway"); TTL as preset chips (15m / 1h / 4h / 24h) plus custom; required reason textarea; optional incident linkage.
- **Confirmation step** restating the target, scope and duration in plain language: "Block all inbound traffic from 192.168.10.57 for 1 hour." Type-to-confirm for a CIDR wider than `/29` — blocking a range is not the same gesture as blocking a host.
- **History** table of expired/revoked/failed actions with reasons and actors.
- **Status banner** when the helper is unreachable or drift is non-zero, because in that state the UI is showing intent, not reality.
- **"Contain" button on the M8 incident detail page** for admins, pre-filling the target from the incident's `src_ip` and the reason from the incident number — that is where containment decisions are actually made.

## Definition of done

- Blocking the gateway IP is refused by the API **and independently by the helper** when the API check is bypassed, with the reason returned and the attempt audited.
- Blocking a CIDR that merely *contains* the gateway or a protected IP is refused.
- A target outside `MONITORED_NETWORK` is refused.
- A block with no `ttl_seconds` is rejected by pydantic, and a direct database insert without one violates the check constraint.
- An applied block actually drops traffic (verify with a live ping/connection test), and the rule appears in the `SENTINELCORE` chain with its `sentinelcore:<uuid>` comment.
- The block auto-expires within 15s of its TTL and traffic flows again, with the row marked `expired`.
- Deleting the kernel rule manually and waiting for reconciliation re-applies it; adding a stray tagged rule with no DB row gets cleaned up; both are logged.
- Killing the helper leaves the API up, shows the status banner, and marks new attempts `failed` rather than silently succeeding.
- A `viewer` and an `analyst` both receive 403 on every mutation; every action and refusal is in `audit_log` with the actor.
- Reaching `MAX_ACTIVE_BLOCKS` refuses further blocks with a clear message.
- Tests: the guard module (exact, CIDR containment, `0.0.0.0/0`, own IP, gateway, DNS, out-of-scope), TTL bounds at both layers, idempotent apply/revoke, expiry worker, reconciliation in both drift directions, RBAC matrix.

## Out of scope

Automatic containment triggered by correlation rules without a human (deliberately — a platform that auto-blocks on a rule will eventually auto-block the gateway), host-based agents, switch/router ACL integration, NAC, and IPv6 rules unless the host uses IPv6.
