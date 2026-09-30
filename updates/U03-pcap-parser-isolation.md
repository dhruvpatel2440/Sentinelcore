# U03 — Resolve the "backend never calls subprocess" contradiction (M11 tshark) — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

`CLAUDE.md` and the proposal say: *"The FastAPI backend runs entirely unprivileged and never invokes subprocess directly under any circumstance."*
`backend/app/pcap/parser.py` currently calls `asyncio.create_subprocess_exec` (4 places, lines ~86, 205, 367, 405) to run `tshark`/`capinfos`. It uses argv lists, absolute binary paths, `-n`, timeouts, and `_limit_resources` (rlimits), and runs as the unprivileged `appuser` — but it still breaks the written rule. An examiner will find it.

## Decision (read before coding)

Do **not** move tshark into the privileged helper. PCAPs are attacker-controlled input and tshark dissectors have a long CVE history; parsing them inside the one root-capable component is the worst place for it.

Choose one of these two options and state the choice in the PR:

- **Option A (cheap, honest): amend the rule.** Rewrite the rule to: *"The API process never runs privileged operations and never invokes a shell. The only permitted subprocess use is `app/pcap/parser.py`: fixed argv lists, absolute paths, no network name-resolution, wall-clock timeout, rlimits, unprivileged user."* Update `CLAUDE.md`, the proposal wording for the report, and the threat model.
- **Option B (stronger, recommended if time allows): isolate the parser.** Create a separate `pcap-worker` service.
  - Own container, own image with `tshark`, no root, `cap_drop: [ALL]`, `read_only: true`, `network_mode: none`, tmpfs for scratch, low memory/CPU limits.
  - Backend never runs tshark; it enqueues a job (Redis stream `pcap_jobs`) and reads results from a `pcap_results` stream / DB rows.
  - Shared volume mounted **read-only** for the uploaded file; worker writes only structured JSON results.
  - Remove `tshark` from the backend image.

## Tasks (Option B; for Option A do only steps 5–6)

1. Move the parsing functions from `backend/app/pcap/parser.py` into `pcap_worker/` (keep the same hardening: `-n`, argv lists, timeout, rlimits).
2. Define the job/result schema (Pydantic) shared by both sides: `pcap_id`, `sha256`, `status`, `flows[]`, `artifacts[]`, `error`.
3. Backend: `POST /pcap` stores the file (existing magic-byte + UUID-filename logic stays), enqueues the job, returns `202` with status `queued`. Add a status field transition `queued → parsing → parsed|failed` and a timeout after which a stuck job becomes `failed` (the E2E test currently asserts "parse always resolves — never stuck"; keep that true).
4. `docker-compose.yml`: add `pcap-worker` with the restrictions above and healthcheck.
5. Add a CI/unit guard `backend/tests/test_no_subprocess.py`: fail if `subprocess`, `os.system`, `os.popen` or `create_subprocess_*` appear anywhere under `backend/app/` (Option B) or anywhere except `pcap/parser.py` (Option A). Also fail on `shell=True` repo-wide.
6. Update `CLAUDE.md`, and `TEST_REPORT.md` invariant wording to match the choice.

## Tests

- Upload valid pcap → flows appear; upload renamed non-pcap → rejected before enqueue.
- Worker killed mid-job → job ends `failed` within the timeout.
- Decompression/complex-file case (use a truncated or oversized-field pcap fixture) → worker hits limits and fails cleanly, backend unaffected.
- Existing M11 e2e checks (path traversal, sha256 dedup, admin-only raw download) still pass.

## Done when

- The guard test passes and the written rule matches the code exactly.
- One paragraph in the report explains why the parser is **not** in the helper.
