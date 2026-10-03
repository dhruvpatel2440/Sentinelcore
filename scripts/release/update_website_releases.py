#!/usr/bin/env python3
"""Rewrite website/src/data/releases.json from a published release.

    update_website_releases.py --latest latest.json --sums SHA256SUMS \
        --key-file release-key.asc --repo owner/sentinelcore-releases \
        --out website/src/data/releases.json

Everything comes from the release's own signed files (latest.json lists URLs and
checksums; SHA256SUMS is cross-checked). Refuses to write anything incomplete, so
the website can never claim a release that does not fully exist.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# latest.json "files" key -> website download id, label order preserved from the page
ID_MAP = {
    "installer_package": "package",
    "install_sh": "installer",
    "deb": "deb",
    "offline_bundle": "offline",
}
FPR_RE = re.compile(r"^[0-9A-F]{40}$")


def parse_sums(text: str) -> dict[str, str]:
    sums = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and len(parts[0]) == 64:
            sums[parts[1].strip().lstrip("*")] = parts[0].lower()
    return sums


def fingerprint_of(key_file: Path) -> str:
    res = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--show-keys", str(key_file)],
        capture_output=True, text=True, check=False,
    )
    for line in res.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9].upper()
    raise ValueError(f"no fingerprint found in {key_file} (is it a real public key?)")


def build(existing: dict, latest: dict, sums: dict[str, str], fingerprint: str, repo: str) -> dict:
    if not FPR_RE.match(fingerprint):
        raise ValueError("fingerprint must be 40 hex characters")
    version = latest["version"]
    tag = f"v{version}"
    base = f"https://github.com/{repo}/releases/download/{tag}"
    by_id = {d["id"]: d for d in existing["downloads"]}
    for key, site_id in ID_MAP.items():
        entry = latest["files"].get(key)
        if not entry:
            raise ValueError(f"latest.json has no '{key}' file")
        name, sha = entry["name"], entry["sha256"].lower()
        if sums.get(name) != sha:
            raise ValueError(f"{name}: latest.json checksum does not match SHA256SUMS")
        if not entry["url"].startswith(base + "/"):
            raise ValueError(f"{name}: url {entry['url']} is not under {base}/")
        d = by_id[site_id]
        d["file"], d["url"], d["sha256"] = name, entry["url"], sha
        if site_id == "installer":
            d["command"] = f"curl -fsSL {entry['url']} | sudo sh"
        elif site_id == "package":
            d["command"] = f"tar xzf {name} && cd {name.removesuffix('.tar.gz')} && sudo ./install.sh"
    out = dict(existing)
    out.update(
        status="available",
        version=version,
        released=latest["released"],
        releasesRepo=f"https://github.com/{repo}",
        signingKey={"fingerprint": fingerprint, "url": f"{base}/release-key.asc"},
    )
    out["downloads"] = [by_id[i] for i in [d["id"] for d in existing["downloads"]]]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--latest", required=True, type=Path)
    ap.add_argument("--sums", required=True, type=Path)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True, type=Path)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--fingerprint")
    g.add_argument("--key-file", type=Path)
    a = ap.parse_args()
    try:
        fpr = (a.fingerprint or fingerprint_of(a.key_file)).replace(" ", "").upper()
        data = build(
            json.loads(a.out.read_text(encoding="utf-8")),
            json.loads(a.latest.read_text(encoding="utf-8")),
            parse_sums(a.sums.read_text(encoding="utf-8")),
            fpr, a.repo,
        )
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    a.out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"updated {a.out} for {data['version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
