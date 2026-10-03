import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import update_website_releases as uw  # noqa: E402

REPO = "owner/sentinelcore-releases"
BASE = f"https://github.com/{REPO}/releases/download/v1.2.3"
FILES = {
    "installer_package": "sentinelcore-installer-1.2.3.tar.gz",
    "install_sh": "install.sh",
    "deb": "sentinelcore_1.2.3_all.deb",
    "offline_bundle": "sentinelcore-offline-1.2.3.tar.gz",
}
SUMS = {name: format(i + 1, "x") * 64 for i, name in enumerate(FILES.values())}
LATEST = {
    "version": "1.2.3",
    "released": "2026-10-10",
    "files": {k: {"name": n, "url": f"{BASE}/{n}", "sha256": SUMS[n]} for k, n in FILES.items()},
}
EXISTING = json.loads((Path(__file__).parents[2] / "website/src/data/releases.json").read_text(encoding="utf-8"))
FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"


def test_builds_complete_available_release():
    out = uw.build(copy.deepcopy(EXISTING), LATEST, SUMS, FPR, REPO)
    assert out["status"] == "available" and out["version"] == "1.2.3"
    assert out["signingKey"]["fingerprint"] == FPR
    for d in out["downloads"]:
        assert d["url"].startswith(BASE + "/") and len(d["sha256"]) == 64
    installer = next(d for d in out["downloads"] if d["id"] == "installer")
    assert installer["command"].endswith("| sudo sh")


def test_refuses_checksum_mismatch_missing_file_and_foreign_url():
    bad_sums = dict(SUMS, **{"install.sh": "0" * 64})
    with pytest.raises(ValueError):
        uw.build(copy.deepcopy(EXISTING), LATEST, bad_sums, FPR, REPO)
    missing = copy.deepcopy(LATEST)
    del missing["files"]["deb"]
    with pytest.raises(ValueError):
        uw.build(copy.deepcopy(EXISTING), missing, SUMS, FPR, REPO)
    foreign = copy.deepcopy(LATEST)
    foreign["files"]["deb"]["url"] = "https://evil.example/x.deb"
    with pytest.raises(ValueError):
        uw.build(copy.deepcopy(EXISTING), foreign, SUMS, FPR, REPO)


def test_refuses_bad_fingerprint():
    with pytest.raises(ValueError):
        uw.build(copy.deepcopy(EXISTING), LATEST, SUMS, "not-a-fingerprint", REPO)
