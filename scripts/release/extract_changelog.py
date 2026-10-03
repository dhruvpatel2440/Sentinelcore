#!/usr/bin/env python3
"""Print the CHANGELOG section for one version (used as the GitHub release notes).

    extract_changelog.py <version> <CHANGELOG.md>
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def section(text: str, version: str) -> str:
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, flags=re.S | re.M)
    if not m:
        raise ValueError(f"no CHANGELOG section for {version}")
    return m.group(1).strip() + "\n"


if __name__ == "__main__":
    try:
        print(section(Path(sys.argv[2]).read_text(encoding="utf-8"), sys.argv[1]), end="")
    except (ValueError, IndexError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
