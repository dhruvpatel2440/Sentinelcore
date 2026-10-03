#!/usr/bin/env python3
"""Write images.json: the release's pinned image references.

    make_images_manifest.py --version 1.2.3 --out images.json \
        --image BACKEND_IMAGE ghcr.io/o/sentinelcore-backend:1.2.3 sha256:... \
        --image DB_IMAGE postgres:16-alpine sha256:...

Every image must come with a digest. A release with an unpinned image is refused.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED = {"DB_IMAGE", "REDIS_IMAGE", "NGINX_IMAGE", "BACKEND_IMAGE", "HELPER_IMAGE", "FRONTEND_IMAGE"}


def build(version: str, images: list[tuple[str, str, str]]) -> dict:
    out: dict[str, dict] = {}
    for var, ref, digest in images:
        if not DIGEST_RE.match(digest):
            raise ValueError(f"{var}: '{digest}' is not a sha256 digest")
        last = ref.rsplit("/", 1)[-1]
        if "@" in ref or ":" not in last or ref.endswith(":latest"):
            raise ValueError(f"{var}: reference '{ref}' must be name:tag with a fixed tag, no digest, not latest")
        out[var] = {"ref": ref, "digest": digest}
    missing = REQUIRED - out.keys()
    if missing:
        raise ValueError(f"missing images: {', '.join(sorted(missing))}")
    return {"version": version, "images": dict(sorted(out.items()))}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--version", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--image", nargs=3, action="append", metavar=("VAR", "REF", "DIGEST"), required=True)
    args = p.parse_args()
    try:
        manifest = build(args.version, [tuple(i) for i in args.image])
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
