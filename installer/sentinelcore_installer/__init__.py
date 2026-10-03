"""SentinelCore installer and management CLI. Python standard library only."""

from pathlib import Path

__all__ = ["__version__"]


def _read_version() -> str:
    # From a source checkout the repo's VERSION file is the single source of
    # truth. An installed package ships its own VERSION under /usr/share
    # (see common.current_version), so this is only a development fallback.
    try:
        return (Path(__file__).resolve().parents[2] / "VERSION").read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


__version__ = _read_version()
