"""Unit tests for validation/scripts/metrics.py, run against small fixture
data (no network, no real platform)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import metrics  # noqa: E402


def _run(attack_id, run_no, *, incidents=1, events=20, latency=5.0, start="2026-01-01T00:00:00Z", end="2026-01-01T00:05:00Z"):
    return {
        "attack_id": attack_id,
        "run_no": run_no,
        "start_ts": start,
        "end_ts": end,
        "raw_alert_count": events,
        "incident_count": incidents,
        "candidate_count": incidents,
        "first_alert_latency_seconds": latency if incidents else None,
        "severities": {},
        "top_signatures": [],
        "incident_ids": [f"inc-{run_no}"] if incidents else [],
    }


# ---------------------------------------------------------------------------
# class_metrics
# ---------------------------------------------------------------------------


def test_all_runs_detected_pass_at_threshold():
    runs = [_run("A1", i, incidents=1) for i in range(1, 11)]  # 10/10
    m = metrics.class_metrics("A1", runs)
    assert m["attempted"] == 10
    assert m["detected"] == 10
    assert m["threshold"] == 9
    assert m["passed"] is True


def test_below_threshold_fails():
    runs = [_run("A1", i, incidents=1) for i in range(1, 9)] + [
        _run("A1", 9, incidents=0),
        _run("A1", 10, incidents=0),
    ]  # 8/10, threshold is 9
    m = metrics.class_metrics("A1", runs)
    assert m["detected"] == 8
    assert m["passed"] is False
    assert len(m["missed"]) == 2


def test_a8_has_no_threshold_and_is_not_graded():
    runs = [_run("A8", 1, incidents=1)]
    m = metrics.class_metrics("A8", runs)
    assert m["threshold"] is None
    assert m["passed"] is None


def test_zero_incidents_reduction_ratio_is_none_not_a_crash():
    """The literal zero-division case the U08 prompt calls out explicitly."""
    runs = [_run("A6", i, incidents=0, events=5) for i in range(1, 11)]
    m = metrics.class_metrics("A6", runs)
    assert m["total_incidents"] == 0
    assert m["reduction_ratio"] is None  # not ZeroDivisionError, not NaN
    assert m["detected"] == 0
    assert m["passed"] is False
    assert len(m["missed"]) == 10


def test_reduction_ratio_computed_correctly():
    runs = [_run("A1", 1, incidents=2, events=100)]
    m = metrics.class_metrics("A1", runs)
    assert m["reduction_ratio"] == pytest.approx(50.0)


def test_median_and_p95_latency():
    runs = [_run("A1", i, incidents=1, latency=v) for i, v in enumerate([2.0, 4.0, 6.0, 8.0, 10.0], start=1)]
    m = metrics.class_metrics("A1", runs)
    assert m["median_latency_s"] == pytest.approx(6.0)
    assert m["p95_latency_s"] == pytest.approx(9.6)


def test_undetected_runs_excluded_from_latency_but_counted_in_missed():
    runs = [_run("A1", 1, incidents=1, latency=3.0), _run("A1", 2, incidents=0)]
    m = metrics.class_metrics("A1", runs)
    assert m["median_latency_s"] == pytest.approx(3.0)
    assert m["missed"] == [{"run_no": 2, "reason": "no incident created in the run window"}]


# ---------------------------------------------------------------------------
# baseline_fp_rate
# ---------------------------------------------------------------------------


def test_baseline_fp_rate_computed_from_window(tmp_path):
    baseline_file = tmp_path / "BASELINE-1.json"
    baseline_file.write_text(
        json.dumps(
            {
                "attack_id": "BASELINE",
                "start_ts": "2026-01-01T00:00:00Z",
                "end_ts": "2026-01-01T08:00:00Z",
                "incident_count": 2,
            }
        )
    )
    result = metrics.baseline_fp_rate(baseline_file)
    assert result["hours"] == pytest.approx(8.0)
    assert result["incidents_per_hour"] == pytest.approx(0.25)


def test_baseline_fp_rate_missing_file_returns_none(tmp_path):
    assert metrics.baseline_fp_rate(tmp_path / "does-not-exist.json") is None


def test_baseline_fp_rate_none_path_returns_none():
    assert metrics.baseline_fp_rate(None) is None


# ---------------------------------------------------------------------------
# load_runs
# ---------------------------------------------------------------------------


def test_load_runs_groups_by_attack_and_skips_baseline(tmp_path):
    (tmp_path / "A1-1.json").write_text(json.dumps(_run("A1", 1)))
    (tmp_path / "A1-2.json").write_text(json.dumps(_run("A1", 2)))
    (tmp_path / "A2-1.json").write_text(json.dumps(_run("A2", 1)))
    (tmp_path / "BASELINE-1.json").write_text(
        json.dumps({"attack_id": "BASELINE", "start_ts": "x", "end_ts": "y", "incident_count": 0})
    )

    grouped = metrics.load_runs(tmp_path)
    assert set(grouped.keys()) == {"A1", "A2"}
    assert len(grouped["A1"]) == 2
    assert len(grouped["A2"]) == 1


# ---------------------------------------------------------------------------
# render_report — smoke test, not a golden-file comparison
# ---------------------------------------------------------------------------


def test_render_report_does_not_crash_with_empty_input():
    report = metrics.render_report({}, None)
    assert "Detection rate per class" in report
    assert "No baseline file supplied" in report


def test_render_report_includes_pass_fail_and_missed_section():
    by_attack = {"A1": [_run("A1", i, incidents=1) for i in range(1, 11)]}
    report = metrics.render_report(by_attack, None)
    assert "PASS" in report
    assert "## Missed runs" in report
    assert "None." in report
