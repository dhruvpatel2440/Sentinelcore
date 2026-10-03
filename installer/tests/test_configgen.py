import json
import os
import stat
import sys

import pytest

from sentinelcore_installer import configgen as cg
from sentinelcore_installer import validators as v


def make_answers(**kw):
    a = cg.Answers(
        capture_interface="enp0s8",
        monitored_network="192.168.56.0/24",
        protected_ips=["192.168.56.1", "192.168.56.102"],
        admin_username="admin",
        admin_password="Sup3r-Secret-Passw0rd!",
        host_name="sentinel-lab",
    )
    for k, val in kw.items():
        setattr(a, k, val)
    return a


def test_env_contains_every_required_variable():
    env = cg.build_env(make_answers())
    for key in ["POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "SECRET_KEY", "CAPTURE_INTERFACE",
                "MONITORED_NETWORK", "PROTECTED_IPS", "SEED_ADMIN_USERNAME", "SEED_ADMIN_PASSWORD",
                "ENVIRONMENT", "EVENT_RETENTION_DAYS", "SURICATA_EVE_LOG", "HTTPS_PORT", "HTTP_PORT",
                "LISTEN_ADDRESS"]:
        assert env[key], key
    assert env["ENVIRONMENT"] == "production"
    assert env["PROTECTED_IPS"] == "192.168.56.1,192.168.56.102"


def test_generated_secrets_are_strong_and_unique():
    a, b = cg.build_env(make_answers()), cg.build_env(make_answers())
    assert len(a["SECRET_KEY"]) == 64 and a["SECRET_KEY"] != b["SECRET_KEY"]
    assert len(a["POSTGRES_PASSWORD"]) >= 24 and a["POSTGRES_PASSWORD"] != b["POSTGRES_PASSWORD"]
    assert a["SECRET_KEY"] != "change-this-to-a-very-long-random-string-minimum-32-chars"


def test_rerun_keeps_live_secrets():
    first = cg.build_env(make_answers())
    again = cg.build_env(make_answers(admin_password=""), existing=first)
    assert again["POSTGRES_PASSWORD"] == first["POSTGRES_PASSWORD"]
    assert again["SECRET_KEY"] == first["SECRET_KEY"]


def test_env_roundtrip_and_quoting():
    env = cg.build_env(make_answers(admin_password="Pa$$w0rd-with-$dollar&amp"))
    parsed = cg.parse_env(cg.render_env(env))
    assert parsed == env


def test_render_env_refuses_unsafe_values():
    with pytest.raises(v.ValidationError):
        cg.render_env({"X": "a'b"})
    with pytest.raises(v.ValidationError):
        cg.render_env({"X": "a\nb"})


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_env_file_is_0600(tmp_path):
    path = tmp_path / "etc" / "sentinelcore.env"
    cg.write_private_file(path, cg.render_env(cg.build_env(make_answers())))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert not list(path.parent.glob("*.tmp"))


def test_profile_contains_no_secrets(tmp_path):
    answers = make_answers()
    env = cg.build_env(answers)
    profile_text = json.dumps(cg.build_profile(answers))
    for key in cg.SECRET_ENV_KEYS:
        if key in env:
            assert env[key] not in profile_text, key
    assert answers.admin_password not in profile_text
    lowered = profile_text.lower()
    assert "secret" not in lowered and '"password"' not in lowered
    assert "password_source" in profile_text  # only HOW it is supplied


def test_profile_roundtrip_and_per_machine_values(tmp_path):
    answers = make_answers(admin_password_mode="generate")
    p = tmp_path / "install-profile.yaml"
    cg.write_profile(p, answers)
    loaded = cg.load_profile(p)
    assert loaded.capture_interface == "enp0s8"
    assert loaded.protected_ips == answers.protected_ips
    assert loaded.admin_password_mode == "generate"
    assert loaded.admin_password == ""


def test_load_profile_rejects_garbage(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(v.ValidationError):
        cg.load_profile(p)
    p.write_text(json.dumps({"admin_password": "x"}))
    with pytest.raises(v.ValidationError):
        cg.load_profile(p)
    p.write_text(json.dumps({"access": {}}))
    with pytest.raises(v.ValidationError):
        cg.load_profile(p)


def test_answers_validation_blocks_empty_protected_list():
    with pytest.raises(v.ValidationError):
        make_answers(protected_ips=[]).validate()


def test_dashboard_url():
    assert make_answers().dashboard_url == "https://localhost"
    assert make_answers(https_port=8443).dashboard_url == "https://localhost:8443"
    assert make_answers(listen_address="192.168.1.5").dashboard_url == "https://192.168.1.5"


def test_generate_password_meets_policy():
    for _ in range(20):
        pw = cg.generate_password()
        assert len(pw) >= 12 and v.validate_password(pw) == pw


# -- YAML profile -------------------------------------------------------------
def test_yaml_roundtrip_matches_profile():
    profile = cg.build_profile(make_answers())
    assert cg.parse_yaml(cg.dump_yaml(profile)) == profile


def test_written_profile_is_yaml_and_loads(tmp_path):
    p = tmp_path / "install-profile.yaml"
    cg.write_profile(p, make_answers())
    text = p.read_text()
    assert text.startswith("#") and "capture_interface:" in text and "{" not in text.split("\n", 1)[1][:20]
    assert cg.load_profile(p).monitored_network == "192.168.56.0/24"


def test_yaml_parser_handles_comments_quotes_and_lists():
    data = cg.parse_yaml('# c\na:\n  b: "x y"  \n  c: 5\n  d: true\n  e:\n    - 1.1.1.1\n    - "2.2.2.2"\nf: []\n')
    assert data == {"a": {"b": "x y", "c": 5, "d": True, "e": ["1.1.1.1", "2.2.2.2"]}, "f": []}


@pytest.mark.parametrize("bad", ["a: {b: 1}", "a: &x 1", "\ta: 1", "a:\n  b: 1\n c: 2", "just text"])
def test_yaml_parser_rejects_unsupported(bad):
    with pytest.raises(v.ValidationError):
        cg.parse_yaml(bad)


def test_installer_refuses_placeholder_manifest(monkeypatch):
    from sentinelcore_installer import install as inst

    monkeypatch.delenv("SENTINELCORE_ALLOW_UNPINNED", raising=False)
    placeholder = {"version": "0.0.0", "images": {"BACKEND_IMAGE": {"ref": "ghcr.io/OWNER/x:0.0.0", "digest": None}}}
    with pytest.raises(inst.InstallError):
        inst.assert_release_manifest(placeholder)
    real = {"version": "0.1.0", "images": {"BACKEND_IMAGE": {"ref": "ghcr.io/o/x:0.1.0", "digest": "sha256:" + "a" * 64}}}
    inst.assert_release_manifest(real)
    monkeypatch.setenv("SENTINELCORE_ALLOW_UNPINNED", "1")
    inst.assert_release_manifest(placeholder)
