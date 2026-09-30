# U07 — Threat model of SentinelCore itself — Implementation Prompt

Self-contained task prompt. Paste the whole file. Output: `docs/threat-model.md` (and a Word/PDF export for the report if the college wants one).

## Why

The proposal lists a **written threat model of the platform itself** as a deliverable: what it protects, assumed adversaries, exposed surface, and the specific control implemented for each threat. Nothing like it exists in the repo. The controls below were found in the codebase or `TEST_REPORT.md`; **verify each one in the code before citing it** and give the file path. Do not claim a control that you cannot point to.

## Structure

1. **Scope and assumptions** — single Linux host, Docker Compose, isolated lab network, mirrored sensor interface, trusted physical host.
2. **Assets to protect** — network map/inventory, event/incident data, credentials and JWT secret, firewall control path, audit trail, uploaded PCAPs (may contain sensitive traffic), report files.
3. **Adversaries** — (a) unauthenticated network attacker reaching the web UI, (b) malicious/low-privilege user (viewer/analyst) escalating, (c) attacker-controlled traffic and PCAP contents processed by the platform, (d) compromised backend process, (e) insider admin abusing containment.
4. **Data-flow diagram** (Mermaid) with trust boundaries: browser | nginx | backend/worker | Postgres/Redis | helper (root-capable) | host/kernel/Suricata.
5. **Attack surface** table: every exposed port, endpoint group, Unix socket, volume, and input channel (admin config, network traffic, analyst decisions, uploaded files).
6. **Threat table** using STRIDE. Columns: ID, threat, component, STRIDE category, likelihood, impact, control implemented (with file path), test that proves it, residual risk.
7. **Out of scope / accepted risk** — encrypted traffic is opaque to payload inspection; physical access; host OS compromise; DoS from very high traffic (measured in U09).
8. **Review log** — date, who, what changed.

## Threats to cover (seed list — one row each, add more)

| ID | Threat | Expected control (verify in code) |
|---|---|---|
| T01 | Command injection via scan target/params | typed validators (`helper/validation.py`, `test_asset_validation.py`), argv lists, no `shell=True`, CI guard (U04) |
| T02 | Web tier compromise escalates to root | unprivileged API (uid ≠ 0), helper only reachable via Unix socket, fixed op set, per-op validation |
| T03 | Helper asked to run arbitrary code | enumerated ops only, strict params, logging of every call with requester |
| T04 | Blocking the gateway/DNS/self (self-DoS) | `helper/guards.py` protection guard incl. CIDR overlap, routing-table-derived gateway |
| T05 | Permanent or forgotten firewall blocks | mandatory TTL 60 s–24 h, reconcile against `firewall_actions` |
| T06 | Credential stuffing / brute force on login | `login_throttle.py`, Argon2, generic error for unknown user |
| T07 | Token theft/replay, forged JWT | 15 min access / 7 day refresh, signature check, `tokens_valid_from` revocation |
| T08 | Privilege escalation between roles | `require_role`, RBAC matrix in `e2e_test.py`, frontend route guards (defence in depth only) |
| T09 | Audit log tampering / repudiation | append-only trigger + hash chain (U02) |
| T10 | Malicious PCAP (dissector bugs, zip bombs, path traversal) | magic-byte check, UUID storage, sha256 dedup, tshark `-n`, timeout + rlimits, isolation decision (U03) |
| T11 | Secrets in repo/config | `.env` untracked, `.env.example`, `SECRET_KEY` not the placeholder (test) |
| T12 | Stored XSS via alert/signature/hostname text | React escaping, no `dangerouslySetInnerHTML` (grep and confirm), report HTML escaping in WeasyPrint templates |
| T13 | Poisoned threat-intel feed / IOC injection | source allow-list, private/RFC1918 IOC refused, severity never downgraded; feed fetch is admin-configured |
| T14 | Event flood / resource exhaustion | buffered Redis ingestion, retention, partitioning, indexes; limits measured in U09 |
| T15 | Report/PCAP download of another user's files | ownership checks (tested in e2e), admin-only raw download |
| T16 | Container breakout / excess capabilities | `cap_drop`, only helper has `NET_ADMIN`/`NET_RAW`, read-only mounts (verify `docker-compose.yml`) |
| T17 | Scanning third-party infrastructure | `MONITORED_NETWORK` scope check, lab-only policy |

## Rules for writing it

- Every "control" cell has a repo path or test name. If none exists, write **GAP** and open an issue — do not hide it.
- Rate likelihood/impact with a simple 1–3 scale and explain the scale once.
- Be honest about residual risk (e.g. helper compromise = root on the host).
- Keep it ~6–10 pages; tables over prose.

## Done when

Every T-row has a verified control or an explicit GAP, and the document is linked from the README and referenced by the validation report.
