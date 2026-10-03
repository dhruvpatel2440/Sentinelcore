import io
import json
import tarfile

import pytest

from sentinelcore_installer import cli, install as inst, netinfo, signing, validators as v
from sentinelcore_installer.configgen import Answers
from sentinelcore_installer.ui import UI
from sentinelcore_installer.wizard import Wizard


class ScriptedUI(UI):
    """Feeds canned answers keyed by screen title; records the screens seen."""

    interactive = True

    def __init__(self, script):
        self.script = {k: list(vals) for k, vals in script.items()}
        self.seen = []

    def _next(self, title):
        self.seen.append(title)
        vals = self.script.get(title)
        if not vals:
            raise AssertionError(f"unscripted screen: {title}")
        return vals.pop(0) if len(vals) > 1 else vals[0]

    def msg(self, title, text):
        self.seen.append(title)

    def yesno(self, title, text, yes="Yes", no="No", default_yes=True):
        return self._next(title)

    def input(self, title, text, default=""):
        val = self._next(title)
        return default if val == "<default>" else val

    def password(self, title, text):
        return self._next(title)

    def menu(self, title, text, items, default=None):
        val = self._next(title)
        return default if val == "<default>" else val

    def scroll(self, title, text, accept="Accept", decline="Decline"):
        return self._next(title)


@pytest.fixture
def fake_net(monkeypatch):
    ifaces = [
        netinfo.Interface("enp0s3", "UP", flags=["UP"], addresses=[("10.0.2.15", 24)]),
        netinfo.Interface("enp0s8", "UP", flags=["UP", "PROMISC"], addresses=[("192.168.56.102", 24)]),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_route", lambda: ("10.0.2.2", "enp0s3"))
    monkeypatch.setattr(netinfo, "dns_servers", lambda *a, **k: ["10.0.2.3"])


def test_wizard_quick_install_happy_path(fake_net):
    ui = ScriptedUI({
        "Licence agreement": [True],
        "Install type": ["quick"],
        "Capture interface": ["enp0s8"],
        "Monitored network": ["<default>"],
        "Protected IP addresses": ["<default>"],
        "Administrator account": ["admin"],
        "Administrator email (optional)": [""],
        "Administrator password": ["generate"],
        "Review": ["install"],
    })
    answers = Wizard(ui).run()
    assert answers is not None
    assert answers.capture_interface == "enp0s8"
    assert answers.monitored_network == "192.168.56.0/24"          # from the interface
    assert "10.0.2.2" in answers.protected_ips                      # gateway
    assert "10.0.2.3" in answers.protected_ips                      # DNS
    assert "192.168.56.102" in answers.protected_ips                # this host, added automatically
    assert answers.admin_password and answers.admin_password_mode == "generate"
    assert "Ports" not in ui.seen                                   # quick mode skips custom screens


def test_wizard_declined_eula_cancels(fake_net):
    ui = ScriptedUI({"Licence agreement": [False]})
    assert Wizard(ui).run() is None


def test_wizard_back_returns_to_previous_screen(fake_net):
    # Back from "Install type" shows the licence again; declining it then cancels.
    ui = ScriptedUI({"Licence agreement": [True, False], "Install type": [None]})
    assert Wizard(ui).run() is None


def test_wizard_reprompts_on_invalid_cidr(fake_net):
    ui = ScriptedUI({
        "Licence agreement": [True], "Install type": ["quick"],
        "Capture interface": ["enp0s8"],
        "Monitored network": ["not-a-network", "192.168.56.0/24"],
        "Protected IP addresses": ["10.0.2.2"],
        "Administrator account": ["admin"], "Administrator email (optional)": [""],
        "Administrator password": ["generate"], "Review": ["install"],
    })
    answers = Wizard(ui).run()
    assert answers and answers.monitored_network == "192.168.56.0/24"
    assert "Please check that value" in ui.seen


def test_wizard_warns_when_management_interface_chosen(fake_net):
    ui = ScriptedUI({
        "Licence agreement": [True], "Install type": ["quick"],
        "Capture interface": ["enp0s3", "enp0s8"],
        "This is your management interface": [False],               # "choose another"
        "Monitored network": ["<default>"], "Protected IP addresses": ["<default>"],
        "Administrator account": ["admin"], "Administrator email (optional)": [""],
        "Administrator password": ["generate"], "Review": ["install"],
    })
    answers = Wizard(ui).run()
    assert answers.capture_interface == "enp0s8"
    assert "This is your management interface" in ui.seen


def test_wizard_protected_list_cannot_be_emptied(fake_net):
    ui = ScriptedUI({
        "Licence agreement": [True], "Install type": ["quick"], "Capture interface": ["enp0s8"],
        "Monitored network": ["<default>"],
        "Protected IP addresses": ["", "10.0.2.2"],
        "Administrator account": ["admin"], "Administrator email (optional)": [""],
        "Administrator password": ["generate"], "Review": ["install"],
    })
    answers = Wizard(ui).run()
    assert answers.protected_ips[0] == "10.0.2.2"


# -- installer helpers -------------------------------------------------------
def test_image_refs_pin_digest_unless_offline():
    manifest = {"images": {"BACKEND_IMAGE": {"ref": "ghcr.io/x/b:1.0.0", "digest": "sha256:" + "a" * 64},
                           "DB_IMAGE": {"ref": "postgres:16-alpine", "digest": None}}}
    pinned = inst.image_refs(manifest)
    assert pinned["BACKEND_IMAGE"] == "ghcr.io/x/b:1.0.0@sha256:" + "a" * 64
    assert pinned["DB_IMAGE"] == "postgres:16-alpine"
    assert inst.image_refs(manifest, use_digest=False)["BACKEND_IMAGE"] == "ghcr.io/x/b:1.0.0"


def test_unhealthy_services_detection():
    rows = [{"Service": "db", "State": "running", "Health": "healthy"},
            {"Service": "helper", "State": "running", "Health": ""},
            {"Service": "backend", "State": "running", "Health": "starting"},
            {"Service": "worker", "State": "exited", "Health": ""}]
    assert inst.unhealthy_services(rows) == ["backend (running/starting)", "worker (exited)"]


def test_desktop_launcher_rejects_odd_urls(tmp_path, monkeypatch):
    monkeypatch.setattr(inst, "DESKTOP_FILE", tmp_path / "sc.desktop")
    inst.write_desktop_launcher("https://localhost;rm -rf /")
    assert not (tmp_path / "sc.desktop").exists()
    inst.write_desktop_launcher("https://localhost:8443")
    assert "Exec=xdg-open https://localhost:8443" in (tmp_path / "sc.desktop").read_text()


# -- CLI helpers --------------------------------------------------------------
def test_version_ordering():
    assert cli.is_newer("1.2.0", "1.1.9")
    assert cli.is_newer("v2.0.0", "1.99.99")
    assert not cli.is_newer("1.0.0", "1.0.0")
    assert cli.is_newer("1.0.0", "1.0.0-rc1")
    assert not cli.is_newer("1.0.0-rc1", "1.0.0")
    with pytest.raises(v.ValidationError):
        cli.parse_version("latest")


def test_last_stats_drops_uses_newest_event():
    lines = [
        json.dumps({"event_type": "alert"}),
        json.dumps({"event_type": "stats", "stats": {"capture": {"kernel_packets": 100, "kernel_drops": 1}}}),
        json.dumps({"event_type": "stats", "stats": {"capture": {"kernel_packets": 500, "kernel_drops": 25}}}),
        "garbage",
    ]
    assert cli.last_stats_drops("\n".join(lines)) == (500, 25)
    assert cli.last_stats_drops("nothing") is None


def test_safe_extract_blocks_traversal_and_links(tmp_path):
    evil = io.BytesIO()
    with tarfile.open(fileobj=evil, mode="w") as tar:
        data = b"x"
        info = tarfile.TarInfo("../escape.txt")
        info.size = 1
        tar.addfile(info, io.BytesIO(data))
    evil.seek(0)
    with tarfile.open(fileobj=evil) as tar, pytest.raises(v.ValidationError):
        cli.safe_extract(tar, tmp_path / "out")

    link = io.BytesIO()
    with tarfile.open(fileobj=link, mode="w") as tar:
        info = tarfile.TarInfo("l")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    link.seek(0)
    with tarfile.open(fileobj=link) as tar, pytest.raises(v.ValidationError):
        cli.safe_extract(tar, tmp_path / "out2")


def test_update_urls_must_be_https(tmp_path):
    with pytest.raises(v.ValidationError):
        cli._fetch("http://example.com/latest.json", tmp_path / "x")


def test_sha256sums_parse_and_verify(tmp_path):
    f = tmp_path / "pkg.deb"
    f.write_bytes(b"hello")
    digest = signing.sha256_file(f)
    sums = signing.parse_sha256sums(f"{digest}  pkg.deb\n# comment\n")
    signing.verify_checksum(f, sums)
    f.write_bytes(b"tampered")
    with pytest.raises(signing.SignatureError):
        signing.verify_checksum(f, sums)
    with pytest.raises(signing.SignatureError):
        signing.parse_sha256sums("nothex  file")
    with pytest.raises(signing.SignatureError):
        signing.verify_checksum(f, sums, "other.deb")


def test_run_rejects_string_commands():
    from sentinelcore_installer.common import run

    with pytest.raises(TypeError):
        run("ls -l; rm -rf /")  # type: ignore[arg-type]


def test_no_shell_true_in_package():
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "sentinelcore_installer"
    for path in root.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "shell=True" not in text, path
        assert "os.system(" not in text, path
