# M12 — Threat Intelligence — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

SentinelCore is a modular network detection and incident response platform.

- Backend: Python 3.11 / FastAPI (async), SQLAlchemy 2.0 + asyncpg, Alembic
- Frontend: React 18 + Vite + Tailwind, dark slate theme, shell from M2
- DB: PostgreSQL 16 | Redis | worker container running M5 pipeline, M7 correlation, M9 reports, M11 parsing

## What already exists

- M1: users, RBAC, `audit_log`, Redis
- M2: app shell with an `/intel` placeholder route
- M3: `assets`
- M5: the `events` table and ingest pipeline (Redis Stream → batch writer with an enrichment pass) — **IOC matching hooks into that existing enrichment pass**, it does not get its own second pipeline
- M7: correlation rules — IOC matches become a rule input
- M8: `incidents`
- M11: `pcap_artifacts` — DNS queries, TLS SNI, HTTP hosts are all matchable indicators

## Objective

Implement the canonical `ioc` table and make it earn its place: known-bad indicators arriving from feeds and analysts, matched against live traffic fast enough to run inline on every event, and surfaced where an analyst is already looking.

## Part 1 — Model

`backend/app/models/ioc.py` — the canonical `ioc` table:

| column | type | notes |
|---|---|---|
| `id` | UUID pk | |
| `indicator` | text | the normalized value |
| `ioc_type` | enum | `ip` \| `cidr` \| `domain` \| `url` \| `md5` \| `sha1` \| `sha256` \| `email` |
| `source_id` | UUID fk ioc_sources | nullable — null means manually added |
| `confidence` | int | 0–100 |
| `severity` | enum | critical / high / medium / low / info |
| `threat_type` | str(64) | c2, phishing, malware, scanner, tor_exit, … |
| `description` | text | |
| `tags` | JSONB | array of strings |
| `first_seen` / `last_seen` | timestamptz | last_seen updated on each feed refresh |
| `expires_at` | timestamptz | nullable — **intel goes stale and stale intel is worse than none** |
| `is_active` | bool | |
| `added_by` | UUID fk users | nullable |
| `created_at` / `updated_at` | | |

Unique on `(indicator, ioc_type, source_id)` — the same IP from two feeds is two rows with independent confidence, and agreement across sources is itself a signal.

Indexes: `(indicator)` hash or btree, `(ioc_type, is_active)`, `(expires_at)`. For CIDR indicators store an `inet`/`cidr` shadow column with a GiST index so containment lookups work.

`ioc_sources` — `id`, `name`, `url`, `format` enum(`csv`/`json`/`txt`/`misp`/`stix`), `parser_config` JSONB (column mapping, delimiter, skip rows), `enabled`, `default_confidence`, `default_severity`, `refresh_interval_hours`, `last_fetch_at`, `last_status`, `last_error`, `indicator_count`, `ttl_days` (how long its indicators stay valid).

`ioc_matches` — `id`, `ioc_id` fk, `event_id` bigint nullable, `pcap_artifact_id` fk nullable, `matched_value`, `matched_field` (`src_ip`/`dst_ip`/`dns_query`/`tls_sni`/`http_host`), `incident_id` fk nullable, `ts`. Indexed on `(ioc_id, ts DESC)` and `(event_id)`. This is the evidence trail — "why did this alert" must always be answerable.

## Part 2 — Normalization

`backend/app/intel/normalize.py` — get this right or matching silently fails:

- **Domains**: lowercase, strip trailing dot, IDNA-encode unicode, strip a leading `www.` only into a separate `apex` field (never destructively).
- **URLs**: lowercase scheme and host, preserve path case.
- **IPs**: parse to `ipaddress`; reject private, loopback, link-local and multicast addresses from public feeds with a warning — a feed listing `192.168.1.1` as malicious will match half your network.
- **Hashes**: lowercase hex, validate length per type (32/40/64).
- **Defanged input**: accept and normalize `hxxp://`, `[.]`, `(.)`, `[:]` — analysts paste indicators from reports in defanged form constantly, and rejecting them is a daily papercut.
- Reject indicators that are obviously noise: `0.0.0.0`, `localhost`, bare TLDs, and anything matching an allowlist of common infrastructure domains.

## Part 3 — Feed ingestion

`backend/app/intel/feeds.py`, scheduled in the worker per source `refresh_interval_hours`:

- Fetch over **HTTPS with certificate verification**, a timeout, and a response size cap. Feeds are third-party input into a security control — treat them as untrusted.
- Parse per `format` using `parser_config` (which column is the indicator, which is confidence). For CSV use the stdlib reader with a row cap.
- Normalize every indicator; count and log rejects rather than failing the batch.
- Upsert on the unique key: insert new, update `last_seen`, `confidence`, `expires_at = now() + ttl_days` for existing.
- **Prune by expiry, not by absence.** An indicator dropping out of one fetch may be a truncated download, not a retraction. Let `expires_at` handle removal.
- Record outcome in `ioc_sources.last_status` / `last_error` / `indicator_count`. A feed that has been failing for a week must be visible, because the platform is quietly less protected.
- Wrap each source independently — one broken feed never stops the others.

## Part 4 — The matcher

Matching runs on **every event**, so it must be O(1)-ish and never touch PostgreSQL on the hot path.

`backend/app/intel/matcher.py`:

- Maintain a Redis-backed lookup: a hash `ioc:exact` mapping normalized indicator → packed IOC metadata (id, severity, confidence, threat_type), rebuilt on feed refresh and updated incrementally on manual CRUD. Keep a `ioc:version` key so the worker can detect staleness and reload.
- CIDR indicators are far fewer — keep them in an in-process interval structure (a `pytricia`-style radix tree or a sorted list of networks) refreshed on version change.
- Hook into **M5's existing enrichment pass** in the batch writer: for each event check `src_ip`, `dst_ip`, and where present the DNS query name, TLS SNI, and HTTP host from `raw`.
- On a hit: write an `ioc_matches` row, stamp the event (add `ioc_match` boolean and `ioc_severity` columns to `events` — a migration on a partitioned table, so plan it), and **escalate severity** to at least the IOC's severity. Do not silently downgrade an event whose own severity is already higher.
- Publish hits to the Redis channel M7 consumes, so a correlation rule can match on `ioc_match = true`.
- Also run the matcher over M11 `pcap_artifacts` after a capture is parsed — retrospective matching of a capture against current intel.

**Retro-hunt**: a CLI command and an admin endpoint that scans the last N days of events against a specific IOC or a whole source. When a new C2 indicator lands, the first question is always "were we already talking to it?" — this answers it.

## Part 5 — Endpoints

Router at `/api/intel`:

- `GET /iocs` — all roles. Filters: type, severity, source, threat_type, tag, `is_active`, `q` (substring), `has_matches`. Paginated.
- `POST /iocs` — analyst+. Manual entry, accepts defanged input, normalizes, requires a description. Audited.
- `POST /iocs/bulk` — analyst+. Paste or upload a list; returns per-line accepted/rejected with reasons. Analysts work from report paste-ins, not one form at a time.
- `PATCH /iocs/{id}` / `DELETE /iocs/{id}` — analyst+ for manual IOCs; feed-sourced IOCs can only be deactivated, not edited, or the next refresh silently reverts the change. Audited.
- `GET /iocs/{id}` — detail with recent matches and affected assets.
- `GET /lookup?value=` — all roles. Normalizes and checks a single indicator, returning matches with source and confidence. The endpoint analysts will use most; make it fast and forgiving of input format.
- `GET /sources`, `POST /sources`, `PATCH /sources/{id}`, `DELETE /sources/{id}` — admin, audited.
- `POST /sources/{id}/refresh` — admin, 202 + background fetch.
- `GET /matches` — filter by time, severity, ioc, asset. This is the "what known-bad have we touched" view.
- `POST /retrohunt` — admin, `{ioc_id|source_id, days}`, 202, results as matches.
- `GET /stats` — active IOCs by type and source, matches over time, top matched indicators, per-source health.

## Part 6 — Frontend

Replace the `/intel` placeholder:

- **Lookup bar** pinned at the top — paste any indicator, defanged or not, get a verdict card immediately. Highest-traffic feature on the page.
- **IOC table**: indicator, type, severity, confidence, source, threat type, tags, match count, last seen, active toggle. Filter bar with URL-synced state, mirroring M6.
- **Add IOC** modal with single and bulk-paste tabs, live normalization preview ("`hxxp://evil[.]com` → `evil.com`"), and a per-line result summary for bulk.
- **Sources tab** (admin): table with enabled toggle, indicator count, last fetch, status badge, refresh-now action, and a prominent failure banner for any source failing for more than a day.
- **Matches tab**: recent matches with indicator, event/artifact link, asset, severity, timestamp, and a pivot into M6 or M11.
- **IOC detail**: metadata, all sources reporting it, match history timeline, affected assets, and a "Create incident" action for analysts.
- **Enrichment surfaced where analysts already are**: an IOC badge on matching rows in M6 event search, in M8 incident indicators (src/dst IP), and on M11 artifacts. The badge links to the IOC detail. This cross-module surfacing is what makes the module worth building — an IOC list nobody visits is dead weight.

## Definition of done

- A configured feed fetches, normalizes and upserts; the indicator count is visible and a second refresh updates `last_seen` without creating duplicates.
- Traffic to an IP present in the IOC set produces an `ioc_matches` row, the event is stamped and severity-escalated, and the badge appears in M6 search.
- A CIDR indicator matches an address inside its range.
- `hxxp://evil[.]com` pasted into lookup and into bulk-add both normalize to `evil.com` and match the existing IOC.
- A feed containing `192.168.10.1` logs a rejection rather than poisoning the platform against its own network.
- IOC matching adds negligible latency to the M5 pipeline — measure events/sec with matching on and off and record both figures.
- A feed source returning 500 is marked failed and surfaced in the UI; the other sources still refresh.
- A retro-hunt over 7 days for a new indicator returns historical matches.
- Expired IOCs stop matching; deactivating an IOC removes it from the Redis lookup within one version cycle.
- An `analyst` can add and deactivate IOCs but not manage sources (403); a `viewer` can look up but not write. All writes audited.
- Tests: normalizer across defanged forms, IDNA domains, every hash length, private-IP rejection; CIDR containment matching; upsert idempotency across two fetches; matcher hit/miss with a seeded Redis set; severity-escalation never downgrades; RBAC matrix.

## Out of scope

Outbound sharing of intel (MISP push, STIX/TAXII export), commercial feed integrations requiring API keys and quotas, automated blocking on IOC match (M10 stays human-initiated by design), reputation scoring models, and malware sandbox detonation.
