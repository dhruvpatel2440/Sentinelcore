#!/usr/bin/env python3
"""U08 §6.4 — metrics.

Pure aggregation over `collect.py`'s output files (`validation/out/*.json`)
— makes no network calls itself, so it is unit-testable on fixture data.
Produces `validation/RESULTS.md`: detection rate per class, median/p95
time-to-alert, reduction ratio per class and overall, false-positive
incidents/hour from a baseline window, and a list of missed runs with
reasons.

"Detected" here means the practical, automatable proxy: at least one
incident was open in the run's window (`incident_count > 0`). The full
criteria in `validation/criteria.md` additionally requires the incident to
carry the *expected* category/signature for that attack class — this
script cannot verify that automatically (no expected-signature mapping is
codified anywhere), so a human must still eyeball each `incident_ids` list
against the expected signature before signing off a pass. This limitation
is written into the generated report, not hidden.

"Reduction ratio" is raw *events* (the platform's post-pipeline,
deduplicated `events` table) divided by incidents, not raw Suricata EVE
lines — no API exposes a pre-pipeline EVE count, so this is the closest
available proxy and is labelled as such in the report.

Baseline false-positive rate convention: run `collect.py` once against a
synthetic run file `validation/runs/BASELINE.jsonl` containing one entry
whose `start_ts`/`end_ts` spans the whole baseline period. That produces
`validation/out/BASELINE-1.json`, which this script reads via
`--baseline-file` (defaults to that path) to compute incidents/hour.

Usage:
    python3 metrics.py --out-dir ../out [--baseline-file ../out/BASELINE-1.json] \\
        [--report ../RESULTS.md]
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

# Must match validation/criteria.md verbatim — if the criteria change,
# update both together.
PASS_CRITERIA = {
    "A1": 9,  # out of 10
    "A2": 8,
    "A3": 8,
    "A4": 9,
    "A5": 9,
    "A6": 7,
    "A7": 8,
    # A8 has no numeric threshold — precision/recall is reported, not graded.
}

ATTACK_LABELS = {
    "A1": "TCP SYN scan",
    "A2": "Service/version scan",
    "A3": "Ping sweep",
    "A4": "SSH brute force",
    "A5": "FTP brute force",
    "A6": "Known exploit",
    "A7": "Web scan",
    "A8": "Malicious PCAP replay",
}


def load_runs(out_dir: Path) -> dict[str, list[dict]]:
    """Group collect.py's per-run JSON files by attack_id, excluding BASELINE."""
    by_attack: dict[str, list[dict]] = {}
    for path in sorted(out_dir.glob("*.json")):
        data = json.loads(path.read_text())
        attack_id = data.get("attack_id")
        if attack_id == "BASELINE":
            continue
        by_attack.setdefault(attack_id, []).append(data)
    return by_attack


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * pct
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def class_metrics(attack_id: str, runs: list[dict]) -> dict:
    attempted = len(runs)
    detected_runs = [r for r in runs if r.get("incident_count", 0) > 0]
    detected = len(detected_runs)

    latencies = [
        r["first_alert_latency_seconds"]
        for r in detected_runs
        if r.get("first_alert_latency_seconds") is not None
    ]
    total_events = sum(r.get("raw_alert_count", 0) for r in runs)
    total_incidents = sum(r.get("incident_count", 0) for r in runs)
    reduction_ratio = (total_events / total_incidents) if total_incidents else None

    missed = [
        {"run_no": r["run_no"], "reason": "no incident created in the run window"}
        for r in runs
        if r.get("incident_count", 0) == 0
    ]

    threshold = PASS_CRITERIA.get(attack_id)
    passed = (detected >= threshold) if threshold is not None else None

    return {
        "attack_id": attack_id,
        "label": ATTACK_LABELS.get(attack_id, attack_id),
        "attempted": attempted,
        "detected": detected,
        "threshold": threshold,
        "passed": passed,
        "median_latency_s": statistics.median(latencies) if latencies else None,
        "p95_latency_s": _percentile(latencies, 0.95),
        "total_events": total_events,
        "total_incidents": total_incidents,
        "reduction_ratio": reduction_ratio,
        "missed": missed,
    }


def baseline_fp_rate(baseline_file: Path | None) -> dict | None:
    if baseline_file is None or not baseline_file.exists():
        return None
    data = json.loads(baseline_file.read_text())
    start = data["start_ts"]
    end = data["end_ts"]

    def _parse(ts: str):
        from datetime import datetime

        return datetime.fromisoformat(ts.replace("Z", "+00:00"))

    hours = max((_parse(end) - _parse(start)).total_seconds() / 3600.0, 1e-9)
    incidents = data.get("incident_count", 0)
    return {
        "start_ts": start,
        "end_ts": end,
        "hours": hours,
        "incident_count": incidents,
        "incidents_per_hour": incidents / hours,
    }


def render_report(by_attack: dict[str, list[dict]], baseline: dict | None) -> str:
    lines = ["# U08 — Detection validation results", ""]
    lines.append(
        "Generated by `validation/scripts/metrics.py` from `validation/out/*.json`. "
        "Pass/fail thresholds are frozen in `validation/criteria.md` and duplicated "
        "here only as a constant to grade against — see that file for the authoritative numbers."
    )
    lines.append("")
    lines.append("## Detection rate per class")
    lines.append("")
    lines.append("| Class | Attack | Attempted | Detected | Threshold | Pass? | Median TTA (s) | p95 TTA (s) | Reduction ratio (events:incidents) |")
    lines.append("|---|---|---|---|---|---|---|---|---|")

    overall_events = 0
    overall_incidents = 0

    for attack_id in sorted(by_attack):
        m = class_metrics(attack_id, by_attack[attack_id])
        overall_events += m["total_events"]
        overall_incidents += m["total_incidents"]
        threshold_str = f"{m['threshold']}/10" if m["threshold"] is not None else "n/a (report only)"
        pass_str = "n/a" if m["passed"] is None else ("PASS" if m["passed"] else "FAIL")
        ratio_str = f"{m['reduction_ratio']:.1f}:1" if m["reduction_ratio"] is not None else "n/a (0 incidents)"
        median_str = f"{m['median_latency_s']:.1f}" if m["median_latency_s"] is not None else "—"
        p95_str = f"{m['p95_latency_s']:.1f}" if m["p95_latency_s"] is not None else "—"
        lines.append(
            f"| {attack_id} | {m['label']} | {m['attempted']} | {m['detected']} | "
            f"{threshold_str} | {pass_str} | {median_str} | {p95_str} | {ratio_str} |"
        )

    overall_ratio = (overall_events / overall_incidents) if overall_incidents else None
    lines.append("")
    lines.append(
        f"**Overall reduction ratio**: {overall_ratio:.1f}:1 (target ≥ 20:1 for scan/brute-force classes)"
        if overall_ratio is not None
        else "**Overall reduction ratio**: n/a — zero incidents across all runs"
    )
    lines.append("")

    lines.append("## Missed runs")
    lines.append("")
    any_missed = False
    for attack_id in sorted(by_attack):
        m = class_metrics(attack_id, by_attack[attack_id])
        for miss in m["missed"]:
            any_missed = True
            lines.append(f"- {attack_id} run {miss['run_no']}: {miss['reason']}")
    if not any_missed:
        lines.append("None.")
    lines.append("")

    lines.append("## Baseline false-positive rate")
    lines.append("")
    if baseline is None:
        lines.append("No baseline file supplied — run `collect.py` against a `BASELINE` run window first.")
    else:
        lines.append(f"Window: {baseline['start_ts']} to {baseline['end_ts']} ({baseline['hours']:.1f}h)")
        lines.append("")
        lines.append(f"- Incidents in window: {baseline['incident_count']}")
        lines.append(f"- Incidents/hour: {baseline['incidents_per_hour']:.3f}")
        lines.append("- Pass criterion: ≤ 1 false-positive incident per 8h *after tuning*")
    lines.append("")

    lines.append("## Limitations of this automated pass")
    lines.append("")
    lines.append(
        "- \"Detected\" = at least one incident was open in the run window. The full "
        "criteria also require the incident to carry the *expected* category/signature "
        "— verify each `incident_ids` entry by hand before signing off."
    )
    lines.append(
        "- Reduction ratio uses `events` (post-pipeline, deduplicated) as the numerator, "
        "not raw Suricata EVE lines — no API exposes a pre-pipeline count."
    )
    lines.append(
        "- A8 (malicious PCAP replay) has no pass/fail threshold by design — report "
        "precision/recall per capture by hand against its ground-truth label."
    )
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default="validation/out")
    parser.add_argument("--baseline-file", default="validation/out/BASELINE-1.json")
    parser.add_argument("--report", default="validation/RESULTS.md")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    by_attack = load_runs(out_dir)
    baseline = baseline_fp_rate(Path(args.baseline_file))

    report = render_report(by_attack, baseline)
    Path(args.report).write_text(report)
    print(f"wrote {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
