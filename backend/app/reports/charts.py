"""Matplotlib chart rendering for M9 PDF reports — PNG at a fixed DPI,
embedded as a base64 data URI. No JS chart libraries: the PDF renderer has no
browser engine running scripts.
"""

from __future__ import annotations

import base64
import io

import matplotlib

matplotlib.use("Agg")  # headless container, no display server

import matplotlib.pyplot as plt  # noqa: E402

DPI = 110
FIGSIZE = (6.4, 3.2)
COLORS = {
    "critical": "#f43f5e", "high": "#fb923c", "medium": "#facc15", "low": "#38bdf8", "info": "#94a3b8",
}
DEFAULT_COLOR = "#38bdf8"


def _to_data_uri(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def bar_chart(labels: list[str], values: list[int], *, title: str = "") -> str:
    if not labels:
        labels, values = ["no data"], [0]
    colors = [COLORS.get(str(label).lower(), DEFAULT_COLOR) for label in labels]
    fig, ax = plt.subplots(figsize=FIGSIZE)
    ax.bar(labels, values, color=colors)
    ax.set_title(title, fontsize=10)
    ax.tick_params(axis="x", labelrotation=30, labelsize=8)
    ax.tick_params(axis="y", labelsize=8)
    fig.tight_layout()
    return _to_data_uri(fig)


def line_chart(x_labels: list[str], series: dict[str, list[int]], *, title: str = "") -> str:
    if not x_labels:
        x_labels, series = ["no data"], {"count": [0]}
    fig, ax = plt.subplots(figsize=FIGSIZE)
    for name, values in series.items():
        ax.plot(x_labels, values, marker="o", markersize=3, label=name, color=COLORS.get(name.lower(), DEFAULT_COLOR))
    ax.set_title(title, fontsize=10)
    ax.tick_params(axis="x", labelrotation=45, labelsize=7)
    ax.tick_params(axis="y", labelsize=8)
    if len(series) > 1:
        ax.legend(fontsize=7)
    fig.tight_layout()
    return _to_data_uri(fig)
