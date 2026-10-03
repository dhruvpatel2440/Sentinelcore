#!/usr/bin/env python3
"""Bump the version in its single home (the VERSION file) and open a changelog section.

    python scripts/release/bump_version.py patch|minor|major|X.Y.Z
"""
from __future__ import annotations

import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def next_version(current: str, how: str) -> str:
    m = SEMVER.match(current.strip())
    if not m:
        raise ValueError(f"current version '{current.strip()}' is not X.Y.Z")
    major, minor, patch = map(int, m.groups())
    if how == "major":
        return f"{major + 1}.0.0"
    if how == "minor":
        return f"{major}.{minor + 1}.0"
    if how == "patch":
        return f"{major}.{minor}.{patch + 1}"
    if SEMVER.match(how):
        return how
    raise ValueError("argument must be major, minor, patch or X.Y.Z")


def update_changelog(text: str, version: str, today: str) -> str:
    if f"## [{version}]" in text:
        raise ValueError(f"CHANGELOG already has a section for {version}")
    marker = "## [Unreleased]"
    if marker not in text:
        raise ValueError("CHANGELOG has no '## [Unreleased]' heading")
    head, _, rest = text.partition(marker)
    body, sep, tail = rest.partition("\n## [")
    # Unreleased stays at the top (now empty); its old content moves under the version.
    return head + f"{marker}\n\n## [{version}] - {today}{body}" + (sep + tail if sep else "")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    version_file, changelog = ROOT / "VERSION", ROOT / "CHANGELOG.md"
    try:
        new = next_version(version_file.read_text(encoding="utf-8"), sys.argv[1])
        text = update_changelog(changelog.read_text(encoding="utf-8"), new, date.today().isoformat())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    version_file.write_text(new + "\n", encoding="utf-8")
    changelog.write_text(text, encoding="utf-8")
    print(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
