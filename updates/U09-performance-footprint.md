# U09 — Performance, throughput ceiling, and resource footprint — Test Plan + Claude Code Prompt

Self-contained. The proposal claims "lightweight". This file produces the evidence and finds the honest throughput ceiling. Do it on the same sensor VM used in U08, with the VM's CPU/RAM fixed and written down (e.g. 4 vCPU / 8 GB).

## 1. What to measure

| Metric | How | Report as |
|---|---|---|
| Idle footprint | 30 min with no traffic: `docker stats --no-stream` every 10 s | avg/max CPU %, RSS per container, total RAM |
| Sustained load footprint | replay traffic at fixed rates for 30 min each | same, per rate |
| Throughput ceiling | increase replay rate until Suricata drops or the pipeline backlog grows | max Mbps and events/s with 0 drops |
| Packet loss | Suricata stats (`capture.kernel_drops`, `capture.kernel_packets` in `stats.log`/EVE stats) | % dropped per rate |
| Ingestion lag | Redis stream length / pending entries; time from EVE write to row in `events` | p50/p95 lag, max backlog |
| Correlation cost | correlation worker CPU and candidate-evaluation time at 10×/100× event volume | ms per evaluation cycle |
| API latency | `/events`, `/events/facets`, `/incidents`, dashboard endpoints under load (`hey`/`k6`/`locust`, 20 users) | p50/p95/p99, error rate |
| Storage growth | DB size + `/var/log/suricata` + PCAP/report volumes at 0/1/6/24 h under a steady rate | GB per day, extrapolate to 30 days |
| Retention | confirm `retention.py` and partition dropping keep DB size flat after the configured window | before/after size |
| Cold start | `docker compose up` to healthy | seconds |

## 2. Load generation

- Use `tcpreplay --loop --mbps=N` on the attacker/traffic VM into the mirrored network, with a mixed capture (benign + a labelled malicious slice) at 10, 25, 50, 100, 250 Mbps (VirtualBox may cap this — record where the *lab* becomes the bottleneck).
- Also a synthetic **event flood**: push N EVE-format records/s straight onto the Redis stream (the E2E suite already shows how) to test the pipeline independent of Suricata. Try 100, 500, 1000, 5000 events/s.
- Run each level for a fixed duration; discard the first 2 minutes as warm-up.

## 3. Pass/fail expectations (freeze before testing, adjust the numbers to your VM)

- Idle: total RAM ≤ 2 GB, CPU < 5 %.
- At the target load (state it, e.g. 50 Mbps / 500 events/s): 0 % drops, p95 ingestion lag < 5 s, API p95 < 500 ms.
- The ceiling is a **finding, not a failure**: report where it breaks and what broke first (Suricata capture, Redis, writer, Postgres, correlation).
- Storage extrapolation must fit within the disk you recommend in the README.

## 4. Claude Code prompt — measurement tooling

> Read `CLAUDE.md`, `docker-compose.yml`, `backend/app/pipeline/worker.py`, `retention.py`. Create `validation/perf/` with:
>
> 1. `sample_stats.py` — samples `docker stats --no-stream --format json` (argv list, no shell) every 10 s for a given duration and writes CSV (timestamp, container, cpu %, mem bytes, net io, block io).
> 2. `suricata_drops.py` — reads Suricata's stats output/EVE `stats` events and reports kernel drops and percentage between two timestamps. Check `docker/suricata/suricata.yaml` for whether stats are enabled and enable them (`stats` in EVE) if not — show the diff.
> 3. `ingest_lag.py` — inserts N synthetic EVE records per second onto the Redis stream with a unique marker, then polls the DB until each appears and records the lag; also samples stream length and pending count. Refuse to run against anything but a stack whose env has `ENV=lab`.
> 4. `api_load.py` (or a `k6` script) — authenticates once, then hits a fixed list of read endpoints with N concurrent users for T seconds; outputs p50/p95/p99 and error rate.
> 5. `storage_growth.py` — records `pg_database_size`, per-table sizes for `events` partitions, and directory sizes for Suricata logs, PCAP and reports at intervals.
> 6. `report.py` — merges the CSVs into `validation/perf/RESULTS.md` with one table per metric and simple matplotlib PNG charts (CPU/RAM vs load, drops vs load, lag vs events/s).
>
> No `shell=True`. Do not change platform code except enabling Suricata stats output if required, and report exactly what you changed. Add basic unit tests for the parsing/aggregation functions.

## 5. Deliverables

- `validation/perf/RESULTS.md` with the tables and charts above, VM specs, versions and commit hash.
- A one-line claim you can defend in the viva, for example: "At X Mbps / Y events/s on a Z-vCPU, W-GB VM, SentinelCore used A GB RAM and B % CPU with 0 % packet loss; the first bottleneck was ___."
- Recommended minimum hardware for the README, based on the measurements.
