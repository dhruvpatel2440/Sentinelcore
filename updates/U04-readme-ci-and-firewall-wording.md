# U04 — README, CI pipeline, and firewall wording — Implementation Prompt

Self-contained task prompt. Paste the whole file.

## Project context

`README.md` is empty (0 lines). There is no CI (`.github/` missing). The proposal says nftables; the code uses `iptables` in `helper/helper/ops/firewall.py`. Note: on Debian/Ubuntu 24.04 the `iptables` binary is normally `iptables-nft` (it programs the kernel nftables backend), and `helper/helper/config.py` already documents this. Verify that on the host image before writing the wording.

## Task 1 — README.md

Write it for a stranger who has 10 minutes. Sections:

1. What it is (3 sentences: non-AI, rule-traceable, one-command deploy).
2. Architecture diagram (Mermaid): Browser → nginx → React / FastAPI → Postgres + Redis; FastAPI → helper (Unix socket) → nmap / Suricata control / firewall; Suricata → EVE → pipeline → events → correlation → incidents; `pcap` path.
3. Requirements: Ubuntu Server 24.04, Docker + Compose, mirrored interface (VirtualBox promiscuous mode note; WSL unsupported).
4. Quick start (`cp .env.example .env`, what to edit, `docker compose up --build`, seed admin, URL, default ports). Copy commands from the repo, don't invent them; run them once on a clean VM to confirm.
5. Roles table (viewer / analyst / admin).
6. Module list M0–M12 with one line each and a link to `Modules/`.
7. Security design: privilege separation, TTL-only firewall blocks, protected IPs.
8. Testing: unit tests, `e2e_test.py`, `e2e_browser.py`.
9. Lab-only warning: scanning/attacks only on your own isolated network.
10. Team, mentors, licence.

## Task 2 — CI (`.github/workflows/ci.yml`)

Jobs (run on PR and push to `main`):

- **backend-tests**: Python version matching `backend/Dockerfile`; install `requirements.txt`; start a Postgres and Redis service container; `alembic upgrade head`; `pytest backend`.
- **helper-tests**: `pytest helper`.
- **frontend-build**: Node 20, `npm ci`, `npm run build`.
- **guardrails** (no external services): fail if any of these match under `backend/` or `helper/` (excluding test strings that name the rule): `shell=True`, tracked `.env`, hard-coded `SECRET_KEY = "`, `os.system(`.
- **compose-config**: `docker compose config -q`.
- Cache pip and npm. Keep total runtime under ~5 minutes.

If any test needs Suricata or a real interface, mark it and skip it in CI with a clear reason rather than deleting it.

## Task 3 — Firewall wording

- Run `iptables --version` inside the helper container and record the output (`(nf_tables)` or `(legacy)`).
- If `nf_tables`: change docs and report text to "firewall rules are applied via `iptables` on the kernel's nftables backend (`iptables-nft`)".
- If time allows and you *want* literal nftables: implement `nft` ops in `helper/helper/ops/firewall.py` behind the same op names (`fw_apply`, `fw_revoke`, `fw_list`, `fw_reconcile`), keep the dedicated chain/table, keep all guards. Otherwise do not.
- Do not change the protection guard or TTL rules.

## Done when

- A teammate can deploy from the README alone on a fresh VM.
- CI is green on a PR and red when you deliberately add `shell=True` in a scratch branch.
- Firewall wording is the same in README, CLAUDE.md, and the report.
