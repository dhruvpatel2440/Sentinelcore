# U06 — M13: Basic vulnerability checks (Nikto + SSLScan) — Implementation Prompt

Self-contained task prompt. Paste the whole file. **Phase 2 / optional.** Start only after U01–U03 and U07–U09 are done or safely under way.

## Project context

Proposal feature 11: *"Basic vulnerability checks against discovered web services"* (Nikto and SSLScan). Nothing exists in the repo for this yet. Follow the **M10 pattern exactly**: new ops go in the privileged helper (`helper/helper/ops/`), validated on both sides of the socket, argv lists only, hard timeouts. No second privilege path. Read `Modules/M03-asset-discovery_1.md` and `Modules/M10-firewall_1.md` for conventions.

## Scope (keep it small)

Two scan types only:

- `web_scan` — Nikto against one `host:port` that M3 already discovered as an HTTP(S) service.
- `tls_scan` — SSLScan against one `host:port` discovered as TLS-capable.

Not in scope: exploitation, authenticated scans, crawling beyond Nikto defaults, scheduling.

## Safety rules (non-negotiable)

- Target must be an **existing asset + open port in the inventory**, inside `MONITORED_NETWORK`. Reject anything else, including hostnames, URLs, and CIDRs. Users choose an asset/port id, not a free-text target.
- Never scan protected IPs unless an admin explicitly confirms (default: refuse gateway/DNS/self).
- Admin-only to launch; analysts and viewers can read findings. Every launch and result is audited.
- One scan at a time per asset, global concurrency cap (e.g. 2), per-scan wall-clock timeout (Nikto: 10 min, SSLScan: 60 s).
- Add a "lab only" confirmation checkbox in the UI and log it.
- Output parsed as data (Nikto `-Format json`/`xml`, SSLScan `--xml=`), never echoed into a shell or rendered as HTML unescaped.

## Backend

1. **Migration `0013_m13_vuln_scans.py`**: `vuln_scans` (id, asset_id, port_id, scan_type, status, requested_by, started_at, finished_at, error) and `vuln_findings` (id, scan_id, severity, title, description, reference/OSVDB-CVE if present, raw_line_hash). Enum types for `scan_type` and `status`.
2. **Helper ops** `vuln_nikto`, `vuln_sslscan`: params `{scan_id, host, port, tls}`; validation in `helper/validation.py` reuses `validate_target`/port validators; binary paths resolved like `iptables_path`; install `nikto` and `sslscan` in `helper/Dockerfile`; write output to a helper-owned temp dir and return the parsed XML/JSON path or content size-capped (e.g. 2 MB).
3. **Backend service** `services/vuln.py` mirroring `services/discovery.py`: create scan row → call helper → parse → store findings → update status. Runs in the worker, not in the request.
4. **Routes** `api/routes/vuln.py`: `POST /vuln/scans` (admin), `GET /vuln/scans`, `GET /vuln/scans/{id}`, `GET /vuln/findings?asset_id=`.
5. **Severity mapping**: Nikto findings default to `low`/`medium` unless a CVE reference is present; SSLScan: SSLv2/3, TLS 1.0/1.1, weak ciphers (RC4/3DES/NULL/EXPORT), expired or self-signed cert → mapped to `medium`/`high`/`info`. Put the mapping table in one file with tests.
6. Optional: feed high-severity findings into the asset's criticality/confidence score used by correlation.

## Frontend

- Asset detail page → "Vulnerability checks" tab: launch buttons on eligible ports (admin only), list of scans, findings table with severity badges.
- New sidebar entry only if you also add a global findings list; otherwise keep it inside asset detail.
- Reports (M9): add an optional "Vulnerability summary" section only if trivial; otherwise leave it.

## Tests

- Helper: validation rejects hostnames, URLs, `; id`, CIDR, port 0/65536, out-of-scope IP; argv is a list; timeout kills the process.
- Parser tests with fixture Nikto and SSLScan outputs (include a malformed one).
- RBAC matrix; audit rows written; second concurrent scan on the same asset → 409.
- Lab test only: run against Metasploitable and record findings count in the validation report.

## Done when

An admin can run Nikto and SSLScan against a discovered Metasploitable web service, findings appear on the asset, and injection-shaped targets are all refused. If you run out of time, ship SSLScan only and state that in the report.
