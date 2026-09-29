# U08 — Detection validation in the isolated lab — Test Plan + Claude Code Prompt

Self-contained. Paste sections 6–7 into Claude Code for the tooling; sections 1–5 are the plan you follow by hand in the lab.

## 1. Why this matters

The proposal treats validation as a deliverable: detection results per attack class, false-positive rate on a benign baseline, alert-to-incident reduction ratio, and honest disclosure of misses. `TEST_REPORT.md` covers the *platform* (210/210), but explicitly does **not** cover Suricata's detection accuracy or load. This document closes that gap.

## 2. Rules

- Lab network only, under your control. Never scan or attack college or third-party systems.
- **Write the pass criteria (section 4) and commit them before running anything.** Do not edit them after seeing results.
- Report misses. Never remove a failed test from the set.
- Record exact versions: Suricata 8.0.6, ruleset name + date, SentinelCore commit hash, correlation rules export.

## 3. Lab layout

- Sensor host (Ubuntu Server 24.04, SentinelCore) with a mirrored/promiscuous interface.
- Attacker VM (Kali or Ubuntu with Nmap, Hydra, Metasploit).
- Target VM: Metasploitable 2.
- Optional benign client VM(s) generating normal traffic.
- Everything on an isolated host-only/internal VirtualBox network. Snapshot every VM before starting.

## 4. Attack classes and pass criteria (edit thresholds once, then freeze)

Each class is run **10 times** (vary timing, ports, and tool flags). "Detected" = an alert with the expected category/signature **and** it appears inside an incident.

| ID | Attack | Tool / how | Expected detection | Pass criterion |
|---|---|---|---|---|
| A1 | TCP SYN scan | `nmap -sS` (fast and `-T2` slow) | scan / recon signatures → one recon incident | ≥ 9/10 runs produce an incident |
| A2 | Service/version scan | `nmap -sV -A` | scan/recon | ≥ 8/10 |
| A3 | Ping sweep | `nmap -sn` /24 | ICMP sweep | ≥ 8/10 |
| A4 | SSH brute force | `hydra` against Metasploitable ssh | brute-force / repeated auth | ≥ 9/10, single incident per run |
| A5 | FTP brute force | `hydra` ftp | same | ≥ 9/10 |
| A6 | Known exploit | Metasploit `vsftpd_234_backdoor`, `samba usermap_script` | exploit signatures | ≥ 7/10 (report which are missed) |
| A7 | Web scan | `nikto` against Metasploitable web | web-scan signatures | ≥ 8/10 |
| A8 | Malicious PCAP replay | `tcpreplay` (or the M11 upload path) of public labelled captures | matches ground truth | report precision/recall per capture; no threshold, disclose all |

Suggested public capture sources: Malware-Traffic-Analysis.net exercises, Stratosphere IPS datasets, CIC-IDS2017 (pick small labelled slices). Keep a table: capture name, source, what is known-malicious, and the expected alert type.

Other criteria:

- **Time to alert**: median ≤ 10 s from first malicious packet to alert (measure: EVE `timestamp` vs attack start log).
- **Benign baseline** (48 h minimum, 4–8 h if time-boxed — state which): normal browsing, DNS, SSH between lab hosts, package updates, file transfers, a nightly Nmap discovery scan by the platform itself. False-positive **incidents** ≤ 1 per 8 h *after* tuning. Report FP incidents before and after tuning.
- **Reduction ratio** = raw Suricata alerts ÷ incidents created, per attack class and overall. Target ≥ 20:1 overall for scan/brute-force classes.
- **Containment check**: for a chosen brute-force incident, request a block → admin approval → rule live → attacker traffic dropped → TTL expiry removes it. Protected IPs refused.

## 5. Procedure

1. Snapshot VMs; record versions/commits; reset the platform DB or note the start time.
2. Freeze the criteria file (`validation/criteria.md`), commit, tag `validation-start`.
3. Baseline run **first** (no attacks). Record FPs. Tune rules/overrides/correlation once, document each change (rule id, reason, before/after count). Then re-run a shorter baseline to confirm.
4. Run A1–A8 with the runner script; each run logs `attack_id, run_no, start_ts, end_ts, params`.
5. Collect results with the collector script; export incidents and raw alerts per run window.
6. Compute the metrics; fill `validation/RESULTS.md`.
7. Write "Gaps and limitations": missed classes, encrypted traffic (TLS payloads invisible), evasion by very slow scans, single-sensor placement, ruleset dependence.

## 6. Claude Code prompt — validation tooling

> Read `CLAUDE.md` and `Modules/M07-correlation_1.md`. Create a `validation/` directory with:
>
> 1. `criteria.md` — the table from sections 4 above, verbatim, no numbers changed.
> 2. `scripts/run_attacks.sh` — takes `--target IP --attacker-iface IFACE`, refuses to run unless the target is inside a `LAB_CIDR` env var (default `192.168.10.0/24`) and is not the gateway or the platform host. Runs each attack N times with a random 30–90 s gap, writing one JSON line per run to `validation/runs/<attack>.jsonl` with UTC start/end, exact command argv, and tool version. Use `set -euo pipefail`, quote every variable, no `eval`.
> 3. `scripts/collect.py` — logs in through `/api/auth/login` (creds from env), and for each run window queries `/api/events`, `/api/incidents` and the correlation candidates endpoint, then writes `validation/out/<attack>-<run>.json` (counts of raw alerts, incidents, first-alert latency, severity, signature names). Use keyset pagination; never load unbounded pages.
> 4. `scripts/metrics.py` — reads the outputs and produces `validation/RESULTS.md` tables: detection rate per class, median/p95 time-to-alert, reduction ratio per class and overall, false-positive incidents per hour from a baseline window (`--baseline-from/--baseline-to`), and a list of missed runs with reasons.
> 5. Unit tests for `metrics.py` on small fixture data (including a zero-division case).
>
> Do not modify platform code. No `shell=True` in any Python.

## 7. Deliverables

- `validation/criteria.md` (frozen), `validation/RESULTS.md`, raw `runs/` and `out/`, screenshots of two full incident investigations, tuning change log, and a "Gaps" section.
- One summary table for the viva: attack class → detected/attempted → median time to alert → reduction ratio.
