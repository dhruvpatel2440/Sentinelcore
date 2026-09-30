"""Unit tests for the U09 perf tooling's parsing/aggregation functions.
No Docker, Postgres, Redis, or Suricata needed — everything here is a pure
function over fixture data."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api_load  # noqa: E402
import ingest_lag  # noqa: E402
import report  # noqa: E402
import sample_stats  # noqa: E402
import storage_growth  # noqa: E402
import suricata_drops  # noqa: E402

UTC = timezone.utc


# ---------------------------------------------------------------------------
# sample_stats.py
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("0B", 0.0),
        ("145.9MiB", 145.9 * 1024**2),
        ("11.22GiB", 11.22 * 1024**3),
        ("2.91MB", 2.91 * 1000**2),
        ("96.2kB", 96.2 * 1000),
    ],
)
def test_parse_size(text, expected):
    assert sample_stats.parse_size(text) == pytest.approx(expected, rel=1e-6)


def test_parse_pair():
    left, right = sample_stats.parse_pair("2.91MB / 2.99MB")
    assert left == pytest.approx(2.91 * 1000**2)
    assert right == pytest.approx(2.99 * 1000**2)


def test_parse_cpu_pct():
    assert sample_stats.parse_cpu_pct("13.48%") == pytest.approx(13.48)


def test_parse_docker_stats_line():
    line = {
        "Name": "sentinelcore-backend-1",
        "CPUPerc": "13.48%",
        "MemUsage": "145.9MiB / 11.22GiB",
        "NetIO": "2.91MB / 2.99MB",
        "BlockIO": "96.2MB / 324kB",
    }
    parsed = sample_stats.parse_docker_stats_line(line)
    assert parsed["container"] == "sentinelcore-backend-1"
    assert parsed["cpu_pct"] == pytest.approx(13.48)
    assert parsed["mem_bytes"] == pytest.approx(145.9 * 1024**2)


def test_parse_size_rejects_unknown_unit():
    with pytest.raises(ValueError):
        sample_stats.parse_size("42XB")


# ---------------------------------------------------------------------------
# suricata_drops.py
# ---------------------------------------------------------------------------


def test_drops_between_computes_delta_not_raw_counter():
    events = [
        (datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC), 1000, 5),
        (datetime(2026, 1, 1, 0, 0, 30, tzinfo=UTC), 5000, 20),
        (datetime(2026, 1, 1, 0, 1, 0, tzinfo=UTC), 9000, 40),
    ]
    result = suricata_drops.drops_between(
        events, datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC), datetime(2026, 1, 1, 0, 1, 0, tzinfo=UTC)
    )
    assert result["packets"] == 8000
    assert result["drops"] == 35
    assert result["drop_pct"] == pytest.approx(35 / 8000 * 100)


def test_drops_between_zero_packets_is_zero_pct_not_a_crash():
    events = [
        (datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC), 100, 0),
        (datetime(2026, 1, 1, 0, 0, 30, tzinfo=UTC), 100, 0),
    ]
    result = suricata_drops.drops_between(
        events, datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC), datetime(2026, 1, 1, 0, 0, 30, tzinfo=UTC)
    )
    assert result["drop_pct"] == 0.0


def test_drops_between_fewer_than_two_samples_reports_note():
    events = [(datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC), 100, 0)]
    result = suricata_drops.drops_between(
        events, datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC), datetime(2026, 1, 1, 0, 1, 0, tzinfo=UTC)
    )
    assert result["drop_pct"] is None
    assert "fewer than 2" in result["note"]


def test_parse_ts_handles_suricata_microsecond_offset_format():
    ts = suricata_drops._parse_ts("2026-09-24T10:01:12.352113+0000")
    assert ts.year == 2026
    assert ts.tzinfo is not None


# ---------------------------------------------------------------------------
# ingest_lag.py
# ---------------------------------------------------------------------------


def test_lag_stats_basic():
    sent_at = {"a": 100.0, "b": 101.0, "c": 102.0}
    seen_at = {"a": 101.0, "b": 103.0, "c": 104.5}
    result = ingest_lag.lag_stats(sent_at, seen_at)
    assert result["sent"] == 3
    assert result["seen"] == 3
    assert result["missing"] == 0
    assert result["max_s"] == pytest.approx(2.5)


def test_lag_stats_counts_missing_markers():
    sent_at = {"a": 100.0, "b": 101.0}
    seen_at = {"a": 101.0}
    result = ingest_lag.lag_stats(sent_at, seen_at)
    assert result["seen"] == 1
    assert result["missing"] == 1


def test_lag_stats_empty_input_no_crash():
    result = ingest_lag.lag_stats({}, {})
    assert result["sent"] == 0
    assert result["p50_s"] is None


def test_build_eve_record_shape():
    rec = ingest_lag.build_eve_record("marker-1", 5)
    assert rec["event_type"] == "alert"
    assert rec["alert"]["signature"] == "PERFTEST marker-1"


def test_require_lab_env_refuses_without_env_lab(monkeypatch):
    monkeypatch.delenv("ENV", raising=False)
    with pytest.raises(SystemExit):
        ingest_lag.require_lab_env()


def test_require_lab_env_allows_env_lab(monkeypatch):
    monkeypatch.setenv("ENV", "lab")
    ingest_lag.require_lab_env()  # must not raise


# ---------------------------------------------------------------------------
# api_load.py
# ---------------------------------------------------------------------------


def test_compute_latency_stats_basic():
    results = [(200, 0.010), (200, 0.020), (200, 0.030), (500, 0.005)]
    stats = api_load.compute_latency_stats(results)
    assert stats["count"] == 4
    assert stats["error_rate"] == pytest.approx(0.25)
    assert stats["p50_ms"] == pytest.approx(15.0)


def test_compute_latency_stats_empty_no_crash():
    stats = api_load.compute_latency_stats([])
    assert stats["count"] == 0
    assert stats["error_rate"] is None


def test_compute_latency_stats_zero_status_counts_as_error():
    results = [(0, 30.0)]  # connection failure
    stats = api_load.compute_latency_stats(results)
    assert stats["error_rate"] == 1.0


# ---------------------------------------------------------------------------
# storage_growth.py
# ---------------------------------------------------------------------------


def test_dir_size_bytes(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"x" * 100)
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.txt").write_bytes(b"y" * 250)
    assert storage_growth.dir_size_bytes(tmp_path) == 350


def test_dir_size_bytes_missing_dir_is_zero(tmp_path):
    assert storage_growth.dir_size_bytes(tmp_path / "does-not-exist") == 0


# ---------------------------------------------------------------------------
# report.py
# ---------------------------------------------------------------------------


def test_summarize_stats_csv():
    rows = [
        {"container": "backend", "cpu_pct": "10.0", "mem_bytes": "1000"},
        {"container": "backend", "cpu_pct": "20.0", "mem_bytes": "2000"},
        {"container": "worker", "cpu_pct": "5.0", "mem_bytes": "500"},
    ]
    summary = report.summarize_stats_csv(rows)
    assert summary["backend"]["avg_cpu_pct"] == pytest.approx(15.0)
    assert summary["backend"]["max_cpu_pct"] == pytest.approx(20.0)
    assert summary["worker"]["samples"] == 1


def test_render_stats_table_includes_total_ram():
    summary = {"backend": {"avg_cpu_pct": 10, "max_cpu_pct": 20, "avg_mem_bytes": 1e8, "max_mem_bytes": 2e8, "samples": 3}}
    lines = report.render_stats_table("Idle", summary)
    assert any("Total avg RAM" in l for l in lines)


def test_render_drops_table_handles_none_pct():
    lines = report.render_drops_table([("50Mbps", {"packets": 0, "drops": 0, "drop_pct": None})])
    assert any("n/a" in l for l in lines)


def test_render_lag_table_smoke():
    lines = report.render_lag_table({"rate_per_sec": 500, "sent": 100, "seen": 100, "missing": 0, "p50_s": 1.2, "p95_s": 2.5, "max_s": 3.0})
    assert any("500" in l for l in lines)


def test_render_api_load_table_smoke():
    lines = report.render_api_load_table({"users": 20, "duration_s": 60, "p50_ms": 45.0, "p95_ms": 120.0, "p99_ms": 300.0, "error_rate": 0.0})
    assert any("20" in l for l in lines)


def test_try_render_charts_degrades_without_matplotlib(tmp_path, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "matplotlib":
            raise ImportError("simulated: matplotlib not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    lines = report.try_render_charts(tmp_path, [], None)
    assert any("matplotlib is not installed" in l for l in lines)
