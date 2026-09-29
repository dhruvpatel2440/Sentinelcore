# U01 — Merge `dhruv` into `main` and clean up branches

Run these yourself in a terminal (not a Claude Code coding task). Takes ~30 minutes.

## Situation

- `main` = commit `e23979e` (work up to M5).
- `dhruv` = commit `0c98a3e` ("complte all modules") — contains M6–M12, tests, `TEST_REPORT.md`, `Modules/`.
- `nisarg` = stale (initial setup only).
- Later commits were authored by Nisarg (M6–M10 and the "complte all modules" commit), so make sure both names appear in the weekly report.

## Steps

```bash
git fetch --all --prune
git checkout main && git pull

# 1. See exactly what is being merged
git log --oneline main..origin/dhruv
git diff --stat main origin/dhruv | tail -5

# 2. Safety tag before the merge
git tag pre-m12-merge main

# 3. Open a PR on GitHub: base=main, compare=dhruv
#    Title: "M6–M12: search, correlation, incidents, reporting, firewall, PCAP, threat intel"
#    Description: paste the "Result" block from TEST_REPORT.md
#    Reviewer: the teammate who did NOT write the last commit
```

## Before merging, check

- [ ] `git ls-files | grep -E '^\.env$'` prints nothing
- [ ] `.env.example` has every variable the code reads (`grep -rn "getenv\|settings\." backend helper`)
- [ ] `docker compose down -v && docker compose up --build` succeeds on a clean VM
- [ ] `docker compose exec backend python -m scripts.e2e_test` passes
- [ ] `TEST_REPORT.docx` is not needed in git (keep the `.md`; `.docx` can go in a release asset)

## After merge

```bash
git checkout main && git pull
git tag v0.12.0 -m "Phase 1 modules complete (M0–M12)"
git push origin v0.12.0

# Bring the stale branch up to date, or delete it
git push origin --delete nisarg      # only if nothing unmerged is on it
```

## Branch policy from now on

- `main` is protected: PR + 1 review required, no direct pushes (GitHub → Settings → Branches).
- Branch names: `upgrade/uNN-name`, `fix/short-name`.
- Squash-merge, PR title = commit message.
- Each teammate creates their weekly-report evidence from `git log --author` on `main`, not from feature branches.

## Done when

`main` contains `backend/app/correlation`, `backend/app/pcap`, `backend/app/intel`, `backend/app/reports`, and the tag `v0.12.0` exists.
