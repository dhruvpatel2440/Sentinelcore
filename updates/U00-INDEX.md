# SentinelCore — Upgrade Pack (U01–U09)

Follow-up work after M0–M12 were completed on the `dhruv` branch.
Each file is a **self-contained Claude Code prompt** in the same style as `Modules/M*.md`. Paste the whole file into Claude Code, one at a time.

## Order (do not reshuffle)

| # | File | Type | Effort | Why this position |
|---|---|---|---|---|
| U01 | `U01-merge-and-branches.md` | Git housekeeping | 30 min | `main` is still at M5. Everything else builds on a correct `main` |
| U02 | `U02-audit-log-immutability.md` | Code + migration | 2–3 h | Proposal promises an append-only audit trail; currently not enforced |
| U03 | `U03-pcap-parser-isolation.md` | Design + code | 3–4 h | Backend calls `subprocess` (tshark), which contradicts the "never" rule |
| U04 | `U04-readme-ci-and-firewall-wording.md` | Docs + CI | 2–3 h | Empty README, no CI, iptables vs nftables wording |
| U05 | `U05-dashboard-top-talkers.md` | Code | 2–3 h | Proposal feature 8 is only partly done |
| U06 | `U06-vuln-checks-M13.md` | New module (Phase 2) | 1–2 days | Proposal feature 11 (Nikto/SSLScan). Optional — do after U07–U09 if time is short |
| U07 | `U07-threat-model.md` | Document | 1 day | Required deliverable in the proposal |
| U08 | `U08-validation-plan.md` | Lab testing | 3–5 days | Detection results, FP rate, reduction ratio |
| U09 | `U09-performance-footprint.md` | Measurement | 1–2 days | CPU/RAM/storage evidence for the "lightweight" claim |

## Rules that apply to every prompt

- Follow `CLAUDE.md`. No `shell=True`, no string-built commands, API stays unprivileged, all root work goes through the helper.
- One branch per upgrade: `git checkout -b upgrade/uNN-short-name`, PR into `main`.
- Run the unit tests and `scripts/e2e_test.py` before every PR.
- Do not weaken an existing test to make a change pass.
- Every new write action is audited via `audit.record()`.

## Priority if time runs out

Must: U01, U02, U03, U07, U08, U09.
Should: U04, U05.
Optional: U06 (Phase 2). If you skip it, say so in the report as "out of scope, designed only".
