#!/usr/bin/env python3
"""U09 §4.6 — merges the CSV/JSONL outputs from the other perf scripts into
`validation/perf/RESULTS.md`, with one table per metric plus PNG charts
(CPU/RAM vs load, drops vs load, lag vs events/s) when matplotlib is
available.

Charts are optional: this is validation-only tooling, so `matplotlib` is
not added to `backend/requirements.txt` — install it once in whatever
environment runs the real lab measurement (`pip install matplotlib`) if you
want the PNGs; the Markdown tables are produced either way.

    python3 report.py --stats-csv idle.csv --sustained-csv sustained_50mbps.csv:50Mbps \\
        --drops-json drops_50mbps.json:50Mbps --lag-json ingest_lag.json \\
        --api-load-json api_load.json --storage-jsonl storage_growth.jsonl \\
        --out RESULTS.md
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


def load_stats_csv(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader(f))


def summarize_stats_csv(rows: list[dict]) -> dict[str, dict]:
    """Per-container avg/max CPU% and avg/max memory bytes — pure function
    over already-parsed CSV rows, unit-tested with fixture rows."""
    by_container: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_container[row["container"]].append(row)

    summary = {}
    for container, samples in by_container.items():
        cpu = [float(s["cpu_pct"]) for s in samples]
        mem = [float(s["mem_bytes"]) for s in samples]
        summary[container] = {
            "avg_cpu_pct": sum(cpu) / len(cpu),
            "max_cpu_pct": max(cpu),
            "avg_mem_bytes": sum(mem) / len(mem),
            "max_mem_bytes": max(mem),
            "samples": len(samples),
        }
    return summary


def render_stats_table(title: str, summary: dict[str, dict]) -> list[str]:
    lines = [f"### {title}", "", "| Container | Avg CPU % | Max CPU % | Avg RAM (MB) | Max RAM (MB) | Samples |",
             "|---|---|---|---|---|---|"]
    total_avg_mem = 0.0
    for container in sorted(summary):
        s = summary[container]
        total_avg_mem += s["avg_mem_bytes"]
        lines.append(
            f"| {container} | {s['avg_cpu_pct']:.1f} | {s['max_cpu_pct']:.1f} | "
            f"{s['avg_mem_bytes'] / 1e6:.1f} | {s['max_mem_bytes'] / 1e6:.1f} | {s['samples']} |"
        )
    lines.append("")
    lines.append(f"**Total avg RAM across containers**: {total_avg_mem / 1e6:.1f} MB ({total_avg_mem / 1e9:.2f} GB)")
    lines.append("")
    return lines


def render_drops_table(entries: list[tuple[str, dict]]) -> list[str]:
    lines = ["### Packet loss vs load", "", "| Load | Packets | Drops | Drop % |", "|---|---|---|---|"]
    for label, data in entries:
        drop_pct = data.get("drop_pct")
        pct_str = f"{drop_pct:.3f}%" if drop_pct is not None else "n/a"
        lines.append(f"| {label} | {data.get('packets', 0)} | {data.get('drops', 0)} | {pct_str} |")
    lines.append("")
    return lines


def render_lag_table(data: dict) -> list[str]:
    lines = ["### Ingestion lag", "", "| Rate (events/s) | Sent | Seen | Missing | p50 (s) | p95 (s) | Max (s) |",
              "|---|---|---|---|---|---|---|"]
    p50 = data.get("p50_s")
    p95 = data.get("p95_s")
    mx = data.get("max_s")
    lines.append(
        "| {rate} | {sent} | {seen} | {missing} | {p50} | {p95} | {mx} |".format(
            rate=data.get("rate_per_sec", "—"),
            sent=data.get("sent", 0),
            seen=data.get("seen", 0),
            missing=data.get("missing", 0),
            p50=f"{p50:.2f}" if p50 is not None else "n/a",
            p95=f"{p95:.2f}" if p95 is not None else "n/a",
            mx=f"{mx:.2f}" if mx is not None else "n/a",
        )
    )
    lines.append("")
    return lines


def render_api_load_table(data: dict) -> list[str]:
    lines = ["### API latency under load", "",
              "| Users | Duration (s) | p50 (ms) | p95 (ms) | p99 (ms) | Error rate |",
              "|---|---|---|---|---|---|"]
    p50, p95, p99 = data.get("p50_ms"), data.get("p95_ms"), data.get("p99_ms")
    err = data.get("error_rate")
    lines.append(
        "| {users} | {dur} | {p50} | {p95} | {p99} | {err} |".format(
            users=data.get("users", "—"),
            dur=data.get("duration_s", "—"),
            p50=f"{p50:.1f}" if p50 is not None else "n/a",
            p95=f"{p95:.1f}" if p95 is not None else "n/a",
            p99=f"{p99:.1f}" if p99 is not None else "n/a",
            err=f"{err:.2%}" if err is not None else "n/a",
        )
    )
    lines.append("")
    return lines


def render_storage_table(samples: list[dict]) -> list[str]:
    lines = ["### Storage growth", "", "| Timestamp | DB size (MB) | Events (MB) | Suricata logs (MB) | PCAP (MB) | Reports (MB) |",
              "|---|---|---|---|---|---|"]
    for s in samples:
        lines.append(
            "| {ts} | {db:.1f} | {ev:.1f} | {logs:.1f} | {pcap:.1f} | {rep:.1f} |".format(
                ts=s.get("timestamp", "—"),
                db=s.get("db_size_bytes", 0) / 1e6,
                ev=s.get("events_total_bytes", 0) / 1e6,
                logs=s.get("suricata_logs_bytes", 0) / 1e6,
                pcap=s.get("pcap_bytes", 0) / 1e6,
                rep=s.get("reports_bytes", 0) / 1e6,
            )
        )
    lines.append("")
    return lines


def try_render_charts(out_dir: Path, drops_entries: list[tuple[str, dict]], lag_data: dict | None) -> list[str]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return [
            "_matplotlib is not installed in this environment — charts skipped. "
            "`pip install matplotlib` and re-run report.py to include them._",
            "",
        ]

    lines = []
    if drops_entries:
        labels = [label for label, _ in drops_entries]
        values = [d.get("drop_pct") or 0 for _, d in drops_entries]
        fig, ax = plt.subplots()
        ax.bar(labels, values)
        ax.set_ylabel("Drop %")
        ax.set_title("Packet loss vs load")
        path = out_dir / "drops_vs_load.png"
        fig.savefig(path)
        plt.close(fig)
        lines.append(f"![Packet loss vs load]({path.name})")
        lines.append("")

    if lag_data and lag_data.get("stream_samples"):
        samples = lag_data["stream_samples"]
        t0 = samples[0]["t"]
        xs = [s["t"] - t0 for s in samples]
        ys = [s["stream_length"] for s in samples]
        fig, ax = plt.subplots()
        ax.plot(xs, ys)
        ax.set_xlabel("seconds")
        ax.set_ylabel("Redis stream length")
        ax.set_title("Stream backlog during ingest_lag run")
        path = out_dir / "lag_backlog.png"
        fig.savefig(path)
        plt.close(fig)
        lines.append(f"![Stream backlog]({path.name})")
        lines.append("")

    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stats-csv", action="append", default=[], help="path[:label], repeatable")
    parser.add_argument("--drops-json", action="append", default=[], help="path:label, repeatable")
    parser.add_argument("--lag-json")
    parser.add_argument("--api-load-json")
    parser.add_argument("--storage-jsonl")
    parser.add_argument("--out", default="validation/perf/RESULTS.md")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    lines = ["# U09 — Performance, throughput ceiling, and resource footprint", ""]

    for entry in args.stats_csv:
        path_str, _, label = entry.partition(":")
        rows = load_stats_csv(Path(path_str))
        summary = summarize_stats_csv(rows)
        lines.extend(render_stats_table(label or path_str, summary))

    drops_entries: list[tuple[str, dict]] = []
    for entry in args.drops_json:
        path_str, _, label = entry.partition(":")
        data = json.loads(Path(path_str).read_text())
        drops_entries.append((label or path_str, data))
    if drops_entries:
        lines.extend(render_drops_table(drops_entries))

    lag_data = None
    if args.lag_json:
        lag_data = json.loads(Path(args.lag_json).read_text())
        lines.extend(render_lag_table(lag_data))

    if args.api_load_json:
        data = json.loads(Path(args.api_load_json).read_text())
        lines.extend(render_api_load_table(data))

    if args.storage_jsonl:
        samples = [json.loads(l) for l in Path(args.storage_jsonl).read_text().splitlines() if l.strip()]
        lines.extend(render_storage_table(samples))

    lines.extend(try_render_charts(out_dir, drops_entries, lag_data))

    out_path.write_text("\n".join(lines))
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
