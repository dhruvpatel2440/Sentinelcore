# U09 — Performance, throughput ceiling, and resource footprint

**Not yet run.** No lab VM with a fixed CPU/RAM budget, a mirrored traffic
generator, or sustained `tcpreplay` capability is available in this
environment — this file is a placeholder, not `report.py`'s output.

The tooling itself is built and verified:

- `sample_stats.py` — parses `docker stats --no-stream --format json`
  (argv-list `subprocess.run`, no shell) into numeric CPU%/memory/net/block
  I/O. Smoke-tested against the real running stack in this repo (7
  containers sampled successfully).
- `suricata_drops.py` — reads EVE `stats` events and computes windowed
  packet-drop percentage from the delta between two cumulative-counter
  samples. Smoke-tested against the real `/var/log/suricata/eve.json` in
  this repo (93 stats events found, parsed correctly). **No config change
  was needed**: `docker/suricata/suricata.yaml` already has
  `stats: enabled: yes, interval: 30` (lines 37-40) and the EVE `stats`
  output type with `totals: yes` (lines 76-79).
- `ingest_lag.py` — pushes synthetic EVE records onto the same Redis stream
  (`stream:events`) the real M5 pipeline consumes, polls Postgres until
  each appears, computes p50/p95/max lag. Refuses to run unless `ENV=lab`
  is set.
- `api_load.py` — stdlib-only (urllib + threads) concurrent read-endpoint
  load generator with p50/p95/p99 latency and error rate.
- `storage_growth.py` — `pg_database_size`, per-partition `events` sizes,
  and directory sizes for Suricata logs/PCAP/report storage.
- `report.py` — merges all of the above into Markdown tables, with
  matplotlib PNG charts when matplotlib is installed (degrades to
  tables-only otherwise — verified both paths).
- 30 unit tests in `validation/perf/tests/test_perf_tools.py`, all passing,
  covering every parsing/aggregation function (`parse_size`,
  `drops_between`, `lag_stats`, `compute_latency_stats`, `dir_size_bytes`,
  `summarize_stats_csv`, and the matplotlib-missing degradation path).

To produce a real `RESULTS.md`: fix the lab VM's CPU/RAM and record it, run
`sample_stats.py` for a 30-minute idle baseline and then at each
`tcpreplay`/synthetic-event-flood rate from U09 §2, run `suricata_drops.py`
and `ingest_lag.py` at each rate, run `api_load.py` under concurrent users,
run `storage_growth.py` across the 0/1/6/24h checkpoints, then run
`report.py` — it will overwrite this file with the real, computed report
and PNG charts.
