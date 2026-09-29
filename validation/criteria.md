# U08 — Detection validation pass criteria

Frozen before any attack run per U08 §2: "Write the pass criteria and commit
them before running anything. Do not edit them after seeing results." This
file is the table from `updates/U08-validation-plan.md` §4, copied verbatim
— no numbers changed. If a threshold later looks wrong, that is a finding
for the "Gaps and limitations" section of `validation/RESULTS.md`, not a
reason to edit this file.

Record exact versions before the first run: Suricata version, ruleset name +
date, SentinelCore commit hash (`git rev-parse HEAD`), correlation rules
export. Fill in below once the lab run starts:

- Suricata version: _(fill in)_
- Ruleset name + date: _(fill in)_
- SentinelCore commit: _(fill in — `git rev-parse HEAD`)_
- Correlation rules export: _(fill in — path/hash)_
- Run start (UTC): _(fill in)_

## Attack classes and pass criteria

Each class is run **10 times** (vary timing, ports, and tool flags).
"Detected" = an alert with the expected category/signature **and** it
appears inside an incident.

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

Suggested public capture sources: Malware-Traffic-Analysis.net exercises,
Stratosphere IPS datasets, CIC-IDS2017 (pick small labelled slices). Keep a
table: capture name, source, what is known-malicious, and the expected
alert type.

## Other criteria

- **Time to alert**: median ≤ 10 s from first malicious packet to alert
  (measure: EVE `timestamp` vs attack start log).
- **Benign baseline** (48 h minimum, 4–8 h if time-boxed — state which):
  normal browsing, DNS, SSH between lab hosts, package updates, file
  transfers, a nightly Nmap discovery scan by the platform itself. False-
  positive **incidents** ≤ 1 per 8 h *after* tuning. Report FP incidents
  before and after tuning.
- **Reduction ratio** = raw Suricata alerts ÷ incidents created, per attack
  class and overall. Target ≥ 20:1 overall for scan/brute-force classes.
- **Containment check**: for a chosen brute-force incident, request a block
  → admin approval → rule live → attacker traffic dropped → TTL expiry
  removes it. Protected IPs refused.

## Procedure

1. Snapshot VMs; record versions/commits (above); reset the platform DB or
   note the start time.
2. Freeze this file, commit, tag `validation-start`.
3. Baseline run **first** (no attacks). Record FPs. Tune rules/overrides/
   correlation once, document each change (rule id, reason, before/after
   count) in `validation/tuning-log.md`. Then re-run a shorter baseline to
   confirm.
4. Run A1–A8 with `scripts/run_attacks.sh`; each run logs `attack_id,
   run_no, start_ts, end_ts, params` to `validation/runs/<attack>.jsonl`.
5. Collect results with `scripts/collect.py`; export incidents and raw
   alerts per run window to `validation/out/<attack>-<run>.json`.
6. Compute the metrics with `scripts/metrics.py`; fills `validation/RESULTS.md`.
7. Write "Gaps and limitations": missed classes, encrypted traffic (TLS
   payloads invisible), evasion by very slow scans, single-sensor
   placement, ruleset dependence.

## Rules

- Lab network only, under your control. Never scan or attack college or
  third-party systems.
- Report misses. Never remove a failed test from the set.
