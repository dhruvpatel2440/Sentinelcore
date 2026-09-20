"""M4 ruleset tests: zip-slip guard, override application, composition."""

from __future__ import annotations

import io
import tarfile
import zipfile

import pytest

from app.services.ruleset import (
    ExtractedRules,
    OverrideSpec,
    RulesetError,
    _is_safe_member,
    apply_overrides,
    compose,
    extract_rules,
)

SAMPLE_RULES = b"""\
alert tcp any any -> $HOME_NET 22 (msg:"SSH brute force"; sid:2001219; rev:5;)
alert http any any -> $HOME_NET any (msg:"Noisy scanner"; sid:2013028; rev:3;)
# alert tcp any any -> any any (msg:"Previously disabled"; sid:2100498; rev:7;)
alert dns any any -> any 53 (msg:"DNS tunnelling"; sid:2020000; rev:1;)
"""


def _zip_with(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    return buffer.getvalue()


def _tar_with(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for name, content in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


# --------------------------------------------------------------------------
# Zip-slip guard
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "../../../etc/cron.d/evil.rules",
        "../outside.rules",
        "/etc/suricata/absolute.rules",
        "/../../root/.ssh/authorized_keys.rules",
        "a/../../../../tmp/escape.rules",
        "C:\\windows\\system32\\evil.rules",
        "\\\\server\\share\\evil.rules",
        "sub/../../../escape.rules",
    ],
)
def test_unsafe_member_names_are_rejected(name):
    assert _is_safe_member(name) is False


@pytest.mark.parametrize(
    "name",
    ["emerging.rules", "rules/emerging-malware.rules", "a/b/c/deep.rules"],
)
def test_safe_member_names_are_accepted(name):
    assert _is_safe_member(name) is True


def test_zip_slip_member_is_not_extracted():
    archive = _zip_with(
        {
            "emerging.rules": SAMPLE_RULES,
            "../../../etc/cron.d/pwned.rules": b"malicious",
        }
    )
    result = extract_rules(archive)

    assert "emerging.rules" in result.files
    assert not any("pwned" in name for name in result.files)
    assert any("unsafe:" in s for s in result.skipped)


def test_tar_slip_member_is_not_extracted():
    archive = _tar_with(
        {
            "emerging.rules": SAMPLE_RULES,
            "../../../etc/passwd.rules": b"root::0:0::/:/bin/sh",
        }
    )
    result = extract_rules(archive)

    assert "emerging.rules" in result.files
    assert not any("passwd" in name for name in result.files)


def test_tar_symlink_members_are_skipped():
    """A symlink can escape the root even when its own name looks safe."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        link = tarfile.TarInfo(name="evil.rules")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/shadow"
        tf.addfile(link)

        content = tarfile.TarInfo(name="good.rules")
        content.size = len(SAMPLE_RULES)
        tf.addfile(content, io.BytesIO(SAMPLE_RULES))

    result = extract_rules(buffer.getvalue())
    assert "good.rules" in result.files
    assert "evil.rules" not in result.files


def test_non_rules_members_are_ignored():
    archive = _zip_with(
        {
            "emerging.rules": SAMPLE_RULES,
            "README.md": b"docs",
            "install.sh": b"#!/bin/sh\nrm -rf /",
            "classification.config": b"config",
        }
    )
    result = extract_rules(archive)
    assert set(result.files) == {"emerging.rules"}


def test_archive_with_no_rules_raises():
    with pytest.raises(RulesetError, match="no .rules"):
        extract_rules(_zip_with({"README.md": b"nothing here"}))


def test_unreadable_archive_raises():
    with pytest.raises(RulesetError):
        extract_rules(b"this is not an archive at all")


# --------------------------------------------------------------------------
# Override application
# --------------------------------------------------------------------------


def test_disabling_a_sid_comments_it_out():
    result, stats = apply_overrides(SAMPLE_RULES, [OverrideSpec(sid=2001219, action="disabled")])

    lines = result.splitlines()
    ssh_line = next(line for line in lines if b"2001219" in line)
    assert ssh_line.startswith(b"# DISABLED BY SENTINELCORE:")
    assert stats["disabled"] == 1

    # Other rules are untouched.
    scanner_line = next(line for line in lines if b"2013028" in line)
    assert scanner_line.startswith(b"alert")


def test_disabled_sid_is_removed_from_active_ruleset():
    """The M4 definition-of-done case."""
    result, _ = apply_overrides(SAMPLE_RULES, [OverrideSpec(sid=2013028, action="disabled")])
    active = [
        line for line in result.splitlines()
        if line.strip() and not line.strip().startswith(b"#")
    ]
    assert not any(b"2013028" in line for line in active)


def test_enabling_a_commented_sid_uncomments_it():
    result, stats = apply_overrides(SAMPLE_RULES, [OverrideSpec(sid=2100498, action="enabled")])
    active = [
        line for line in result.splitlines()
        if line.strip() and not line.strip().startswith(b"#")
    ]
    assert any(b"2100498" in line for line in active)
    assert stats["enabled"] == 1


def test_threshold_override_appends_a_threshold_line():
    result, stats = apply_overrides(
        SAMPLE_RULES,
        [
            OverrideSpec(
                sid=2001219,
                action="threshold",
                params={"type": "limit", "track": "by_src", "count": 5, "seconds": 300},
            )
        ],
    )
    assert b"threshold gen_id 1, sig_id 2001219" in result
    assert b"type limit" in result
    assert b"track by_src" in result
    assert stats["thresholds"] == 1


@pytest.mark.parametrize(
    "params",
    [
        {"type": "; rm -rf /", "track": "by_src", "count": 1, "seconds": 60},
        {"type": "limit", "track": "by_evil", "count": 1, "seconds": 60},
        {"type": "limit", "track": "by_src", "count": 0, "seconds": 60},
        {"type": "limit", "track": "by_src", "count": 99999999, "seconds": 60},
        {"type": "limit", "track": "by_src", "count": 1, "seconds": 0},
        {"type": "limit", "track": "by_src", "count": 1, "seconds": 999999},
    ],
)
def test_invalid_threshold_params_are_dropped_not_written(params):
    """Threshold values land in a Suricata config file — nothing free-form."""
    result, stats = apply_overrides(
        SAMPLE_RULES, [OverrideSpec(sid=2001219, action="threshold", params=params)]
    )
    assert stats["thresholds"] == 0
    assert b"rm -rf" not in result
    assert b"by_evil" not in result


def test_counts_active_rules():
    _, stats = apply_overrides(SAMPLE_RULES, [])
    assert stats["total"] == 3  # one of the four lines is commented out


def test_no_overrides_leaves_content_semantically_unchanged():
    result, _ = apply_overrides(SAMPLE_RULES, [])
    assert b"2001219" in result
    assert b"2013028" in result
    assert b"2020000" in result


# --------------------------------------------------------------------------
# Composition
# --------------------------------------------------------------------------


def test_compose_concatenates_all_files_deterministically():
    extracted = ExtractedRules(
        files={
            "b-second.rules": b'alert tcp any any -> any 80 (msg:"B"; sid:2;)\n',
            "a-first.rules": b'alert tcp any any -> any 22 (msg:"A"; sid:1;)\n',
        }
    )
    first, _ = compose(extracted, [])
    second, _ = compose(extracted, [])

    assert first == second  # sorted order makes the checksum stable
    assert first.index(b"a-first.rules") < first.index(b"b-second.rules")
    assert b'msg:"A"' in first and b'msg:"B"' in first


def test_compose_applies_overrides():
    extracted = ExtractedRules(files={"x.rules": SAMPLE_RULES})
    result, stats = compose(extracted, [OverrideSpec(sid=2001219, action="disabled")])
    assert stats["disabled"] == 1
    assert b"# DISABLED BY SENTINELCORE:" in result
