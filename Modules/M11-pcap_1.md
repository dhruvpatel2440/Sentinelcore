# M11 — PCAP Analysis — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore is a modular network detection and incident response platform.

- Backend: Python 3.11 / FastAPI (async), SQLAlchemy 2.0 + asyncpg, Alembic
- Frontend: React 18 + Vite + Tailwind, dark slate theme, shell from M2
- Parsing: tshark / PyShark, Scapy
- `.gitignore` already excludes `*.pcap`

## What already exists

- M1: users, RBAC, `audit_log`, Redis
- M2: app shell with a `/pcap` placeholder route, shared `Table`, `Badge`, `Modal`, `useToast`
- M3: `assets` — flow endpoints resolve to known assets
- M5: `events` and the worker container
- M6: event search UI patterns to mirror
- M8: `incidents` — a capture can be attached as evidence

## Objective

Let an analyst upload a capture and understand it: what talked to what, over which protocols, carrying what. Offline PCAP analysis is where an investigation goes when the live sensor's alerts are not enough.

## Threat model — read this before writing the upload handler

A PCAP is attacker-controlled data, often *literally* captured from an attack. Every component that touches it must assume hostility:

- The uploaded bytes are untrusted. **Never** use the client-supplied filename in any path.
- tshark's dissectors have a long CVE history. Parsing runs sandboxed and resource-capped, never as root, never with network access.
- Extracted strings (hostnames, URIs, user agents, TLS SNI, DNS names) are attacker-chosen and end up rendered in the UI and in M9 reports — escape on output, always.
- A crafted capture can be a decompression or complexity bomb. Cap size, time, memory, and output rows.

## Part 1 — Upload

`POST /api/pcap/upload` — `require_role("analyst","admin")`, multipart.

- **Stream to disk in chunks**; never read the whole body into memory. Enforce `MAX_PCAP_SIZE_MB` (default 500) *during* the stream and abort past the limit — a `Content-Length` check alone is trivially lied about.
- **Validate by magic bytes**, not extension: pcap `0xa1b2c3d4` / `0xd4c3b2a1` (and the nanosecond variants `0xa1b23c4d` / `0x4d3cb2a1`), pcapng `0x0a0d0d0a`. Reject anything else before any parser runs.
- Storage path is `PCAP_STORAGE_PATH/<uuid>.pcap` — a generated UUID, with the original filename kept only as a database string for display. Resolve the final path and assert it stays under the storage root.
- Compute SHA-256 while streaming. If a capture with the same hash exists, return the existing record instead of storing a duplicate — captures get re-uploaded constantly during an investigation.
- Store as `uploaded`, enqueue parsing on Redis, return 202. Audit the upload.
- Reject gzip/zip containers in v1 rather than decompressing attacker-supplied archives.

## Part 2 — Models

(Additions to the canonical list — note them in the migration message.)

`pcap_files` — `id` UUID, `filename` (original, display only), `stored_path`, `sha256` unique, `size_bytes`, `status` enum(`uploaded`/`parsing`/`parsed`/`failed`), `packet_count`, `first_packet_ts`, `last_packet_ts`, `duration_seconds`, `link_type`, `capture_interface`, `error`, `uploaded_by` fk users, `uploaded_at`, `parsed_at`, `incident_id` fk nullable.

`pcap_flows` — `id`, `pcap_id` fk cascade, `stream_id` int, `protocol`, `src_ip` inet, `src_port`, `dst_ip` inet, `dst_port`, `packet_count`, `byte_count`, `start_ts`, `end_ts`, `duration_ms`, `app_protocol` (http/dns/tls/…), `summary` text, `src_asset_id` / `dst_asset_id` fk nullable. Indexes on `(pcap_id, byte_count DESC)`, `(pcap_id, start_ts)`, `(src_ip)`, `(dst_ip)`.

`pcap_artifacts` — `id`, `pcap_id` fk cascade, `flow_id` fk nullable, `artifact_type` enum(`dns_query`/`http_request`/`tls_sni`/`credential`/`file_transfer`/`user_agent`), `value` text, `detail` JSONB, `packet_number`, `ts`. Indexed on `(pcap_id, artifact_type)`. This table is what makes a capture searchable — "which captures mention this domain" is the question analysts ask.

## Part 3 — Parsing worker

`backend/app/pcap/parser.py`, running in the worker container.

Use **tshark via `subprocess`**, not PyShark's live API, for the bulk pass — PyShark wraps tshark anyway and is slower per packet. Argument lists only, `shell=False`, absolute binary path, hard timeout (`PCAP_PARSE_TIMEOUT_SECONDS`, default 300).

Passes:

1. **Metadata** — `capinfos -M` for packet count, time span, link type.
2. **Conversations** — `tshark -r <file> -q -z conv,tcp -z conv,udp` parsed into `pcap_flows`. Cap at `MAX_FLOWS_PER_PCAP` (default 50,000); beyond it, keep the top flows by bytes and record that truncation happened.
3. **Artifacts** — one `tshark -T ek`/`-T json` pass with `-e` field extraction for DNS queries, HTTP host/URI/method/user-agent, TLS SNI, and basic-auth credentials. Field extraction (`-T fields -e`) is far cheaper than full JSON output; prefer it and parse line by line so memory stays flat regardless of capture size.

Sandboxing: run tshark as a **non-root user** with no network namespace access, `ulimit` on CPU and address space, and `--disable-protocol` for dissectors you do not need. Wrap everything so a parser crash marks the file `failed` with the error — never leaves it stuck in `parsing`. Add a startup reconciliation that fails any `parsing` row older than the timeout.

Enrichment: resolve flow endpoints to M3 assets, same Redis-cached IP→asset map M5 uses.

Progress: publish percentage to Redis so the UI can show a real progress bar on a 400MB capture rather than an indefinite spinner.

## Part 4 — Endpoints

Router at `/api/pcap`:

- `GET /` — list captures (all authenticated roles), filter by status, uploader, incident, date. Paginated.
- `GET /{id}` — metadata, parse status/progress, protocol breakdown, top talkers.
- `GET /{id}/flows` — paginated, filterable by ip/port/protocol/app_protocol, sortable by bytes/packets/start time.
- `GET /{id}/flows/{flow_id}/packets` — packet list for one flow, paginated, generated on demand by a targeted `tshark -r <file> -Y "tcp.stream eq N"` — do **not** store every packet of every capture in PostgreSQL. A 500MB capture is tens of millions of rows nobody will query in full.
- `GET /{id}/flows/{flow_id}/follow` — reassembled stream content (`-z follow,tcp,ascii,N`), capped in size, returned as text with a clear truncation marker. Treat as untrusted text in the UI.
- `GET /{id}/artifacts` — filter by type, search by value.
- `POST /{id}/attach` — analyst+, link the capture to an incident, audited.
- `DELETE /{id}` — uploader or admin, removes row and file, audited.
- `GET /{id}/download` — original file, **admin only**, audited. A capture may contain credentials and personal data; downloading it is a privileged act.
- Retention job deleting captures past `PCAP_RETENTION_DAYS` (default 30) unless attached to an open incident.

## Part 5 — Frontend

Replace the `/pcap` placeholder.

**Upload view**: drag-and-drop with client-side size and extension pre-checks (server still validates), real upload progress, then a parse-progress bar driven by polling. Show clear, specific errors — "not a valid pcap/pcapng file" beats "upload failed".

**Capture list**: filename, size, packet count, time span, status badge, uploader, linked incident, uploaded at.

**Capture detail**:

- Summary cards: packets, duration, flow count, unique hosts, protocol distribution (a simple bar breakdown is enough).
- **Top talkers** table: IP, packets, bytes in/out, resolved asset name linked to M3.
- **Flows table**: the core view — src → dst with ports, protocol, app protocol, packets, bytes, duration, start time. Sort by bytes descending by default; the biggest transfer is usually the interesting one. Filter bar mirroring M6's patterns and URL-synced filter state.
- **Flow detail drawer**: packet list, and a "Follow stream" tab rendering reassembled content in a monospace block with hex/ASCII toggle. Render as text nodes, never `dangerouslySetInnerHTML`.
- **Artifacts tab**: grouped by type — DNS queries, HTTP requests, TLS SNI, user agents — each searchable, each with a pivot into M6 event search for the same indicator.
- **Attach to incident** action, and an "Upload PCAP" entry point on the M8 incident detail page so evidence lands on the right incident.

## Definition of done

- A 100MB capture uploads with visible progress and parses within the timeout; flows and artifacts are populated and counts match `capinfos`.
- A non-PCAP file renamed `evil.pcap` is rejected at magic-byte validation, before any parser runs.
- A filename of `../../etc/passwd` is stored under a UUID inside the storage root and displayed harmlessly as text.
- Re-uploading an identical capture returns the existing record rather than duplicating storage.
- A deliberately malformed capture marks the file `failed` with a readable error; the worker survives and processes the next item.
- Follow-stream on an HTTP flow shows the request and response; content containing `<script>` renders as literal text.
- Killing the worker mid-parse leaves no row stuck in `parsing` after restart.
- A `viewer` cannot upload, attach, or download; only an admin can download the raw file; all three are audited.
- Flow endpoints matching known assets show the asset name linked to M3.
- Tests: magic-byte validator across all four pcap variants plus pcapng and a rejected file, path containment on storage, size-cap abort mid-stream, conversation parser against a fixture capture with known counts, artifact extraction fixtures, truncation behaviour past `MAX_FLOWS_PER_PCAP`.

## Out of scope

Live packet capture (the platform is PCAP-upload based by design — M4's Suricata handles live traffic), replaying captures through Suricata, file carving and extracted-object export, TLS decryption, and deep protocol decoding beyond the artifact types listed.
