"""Tests for the release helper scripts. Run: python -m pytest scripts/release"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import bump_version as bv  # noqa: E402
import extract_changelog as ec  # noqa: E402
import make_images_manifest as mim  # noqa: E402
import make_latest_json as mlj  # noqa: E402

D = "sha256:" + "a" * 64
ALL = [(v, f"example.io/{v.lower()}:1.0.0", D) for v in sorted(mim.REQUIRED)]


def test_manifest_requires_every_image_and_digest():
    m = mim.build("1.0.0", ALL)
    assert m["images"]["BACKEND_IMAGE"]["digest"] == D
    with pytest.raises(ValueError):
        mim.build("1.0.0", ALL[:-1])
    with pytest.raises(ValueError):
        mim.build("1.0.0", [(v, r, "sha256:short") for v, r, _ in ALL])


@pytest.mark.parametrize("ref", ["example.io/x", "example.io/x:latest", "example.io/x:1@sha256:" + "a" * 64])
def test_manifest_rejects_unpinned_refs(ref):
    bad = [(v, ref, D) for v, _, _ in ALL]
    with pytest.raises(ValueError):
        mim.build("1.0.0", bad)


def test_bump_versions():
    assert bv.next_version("1.2.3", "patch") == "1.2.4"
    assert bv.next_version("1.2.3", "minor") == "1.3.0"
    assert bv.next_version("1.2.3", "major") == "2.0.0"
    assert bv.next_version("1.2.3", "3.0.1") == "3.0.1"
    for bad in ("huge", "1.2"):
        with pytest.raises(ValueError):
            bv.next_version("1.2.3", bad)


def test_changelog_bump_moves_unreleased_content():
    text = "# Changelog\n\n## [Unreleased]\n\n### Added\n- thing\n\n## [0.1.0] - 2026-01-01\n- old\n"
    out = bv.update_changelog(text, "0.2.0", "2026-02-02")
    assert "## [Unreleased]\n\n## [0.2.0] - 2026-02-02" in out
    assert ec.section(out, "0.2.0").strip().endswith("- thing")
    assert "- old" not in ec.section(out, "0.2.0")
    with pytest.raises(ValueError):
        bv.update_changelog(out, "0.2.0", "x")


def test_latest_json_contains_signed_checksums():
    sums = {
        "sentinelcore-installer-1.0.0.tar.gz": "a" * 64,
        "sentinelcore_1.0.0_all.deb": "b" * 64,
        "sentinelcore-offline-1.0.0.tar.gz": "c" * 64,
        "install.sh": "d" * 64,
        "images.json": "e" * 64,
    }
    data = mlj.build("1.0.0", "https://example.com/dl/", sums, "0.1.0", "none")
    assert data["files"]["deb"]["url"] == "https://example.com/dl/sentinelcore_1.0.0_all.deb"
    assert data["files"]["deb"]["sha256"] == "b" * 64
    assert data["min_compatible_version"] == "0.1.0"
    json.dumps(data)
    del sums["install.sh"]
    with pytest.raises(ValueError):
        mlj.build("1.0.0", "https://example.com", sums, "0.1.0", "")
    with pytest.raises(ValueError):
        mlj.build("v1", "https://example.com", sums, "0.1.0", "")
