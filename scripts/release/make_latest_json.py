#!/usr/bin/env python3
"""Write latest.json, the updater contract read by `sentinelcore update`.

The file is signed (latest.json.asc) in CI. It carries the checksums of the
downloadable files, so a verified latest.json authenticates everything it lists.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$")


def parse_sums(text: str) -> dict[str, str]:
    sums = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and len(parts[0]) == 64:
            sums[parts[1].strip().lstrip("*")] = parts[0]
    return sums


def build(version: str, base_url: str, sums: dict[str, str], min_compat: str, notes: str) -> dict:
    if not SEMVER.match(version) or not SEMVER.match(min_compat):
        raise ValueError("version and min-compatible-version must be semantic versions")
    base = base_url.rstrip("/")
    wanted = {
        "installer_package": f"sentinelcore-installer-{version}.tar.gz",
        "deb": f"sentinelcore_{version}_all.deb",
        "offline_bundle": f"sentinelcore-offline-{version}.tar.gz",
        "install_sh": "install.sh",
        "images_manifest": "images.json",
    }
    files = {}
    for key, name in wanted.items():
        if name not in sums:
            raise ValueError(f"{name} is not listed in SHA256SUMS")
        files[key] = {"name": name, "url": f"{base}/{name}", "sha256": sums[name]}
    return {
        "version": version,
        "released": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "min_compatible_version": min_compat,
        "migration_notes": notes,
        "files": files,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--version", required=True)
    p.add_argument("--base-url", required=True, help="https URL where the files are published")
    p.add_argument("--sums", required=True, type=Path)
    p.add_argument("--min-compatible-version", default="0.1.0")
    p.add_argument("--notes", default="")
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    if not a.base_url.startswith("https://"):
        print("error: --base-url must be https", file=sys.stderr)
        return 1
    try:
        data = build(a.version, a.base_url, parse_sums(a.sums.read_text(encoding="utf-8")),
                     a.min_compatible_version, a.notes)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    a.out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
