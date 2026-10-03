import pytest

from sentinelcore_installer import validators as v


# -- CIDR -------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("192.168.56.0/24", "192.168.56.0/24"),
    ("192.168.56.77/24", "192.168.56.0/24"),  # host bits normalised
    (" 10.0.0.0/8 ", "10.0.0.0/8"),
    ("10.1.2.3/32", "10.1.2.3/32"),
])
def test_cidr_ok(raw, expected):
    assert v.validate_cidr(raw) == expected


@pytest.mark.parametrize("raw", ["", "192.168.1.0", "192.168.1.0/33", "999.1.1.1/24", "::1/128",
                                 "fe80::/10", "0.0.0.0/0", "10.0.0.0/7", "a.b.c.d/24", "1.2.3.4/24; rm -rf /"])
def test_cidr_bad(raw):
    with pytest.raises(v.ValidationError):
        v.validate_cidr(raw)


# -- interface name -----------------------------------------------------------
@pytest.mark.parametrize("name", ["eth0", "enp0s8", "wlp3s0", "br_lan.10", "eth0:1"])
def test_iface_ok(name):
    assert v.validate_interface_name(name) == name


@pytest.mark.parametrize("name", ["", "lo", ".", "..", "a" * 16, "eth 0", "eth0;id", "eth0/../x", "$(id)", "eth\n0"])
def test_iface_bad(name):
    with pytest.raises(v.ValidationError):
        v.validate_interface_name(name)


def test_iface_must_exist_when_known_list_given():
    assert v.validate_interface_name("eth1", known=["eth0", "eth1"]) == "eth1"
    with pytest.raises(v.ValidationError):
        v.validate_interface_name("eth9", known=["eth0", "eth1"])


# -- ports -------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [("80", 80), (443, 443), (" 8443 ", 8443), ("65535", 65535), ("1", 1)])
def test_port_ok(raw, expected):
    assert v.validate_port(raw) == expected


@pytest.mark.parametrize("raw", ["0", "65536", "-1", "http", "", "80.5", "1e3"])
def test_port_bad(raw):
    with pytest.raises(v.ValidationError):
        v.validate_port(raw)


def test_port_pair_must_differ():
    assert v.validate_port_pair("80", "443") == (80, 443)
    with pytest.raises(v.ValidationError):
        v.validate_port_pair("443", "443")


# -- protected IPs -----------------------------------------------------------
def test_protected_ips_list_and_dedupe():
    assert v.validate_protected_ips("192.168.1.1, 192.168.1.1 8.8.8.8") == ["192.168.1.1", "8.8.8.8"]
    assert v.validate_protected_ips(["10.0.0.1", "10.0.0.2"]) == ["10.0.0.1", "10.0.0.2"]


@pytest.mark.parametrize("value", ["", "  ", [], [""], ",,,"])
def test_protected_ips_never_empty(value):
    with pytest.raises(v.ValidationError):
        v.validate_protected_ips(value)


@pytest.mark.parametrize("value", ["192.168.1.1, nope", "0.0.0.0", "224.0.0.1", "::1", "300.1.1.1", "10.0.0.0/24"])
def test_protected_ips_reject_invalid(value):
    with pytest.raises(v.ValidationError):
        v.validate_protected_ips(value)


# -- listen address / host / dir / user -------------------------------------
def test_listen_address():
    assert v.validate_listen_address("127.0.0.1") == "127.0.0.1"
    assert v.validate_listen_address("0.0.0.0") == "0.0.0.0"
    assert v.validate_listen_address("192.168.1.5", local_addresses=["192.168.1.5"]) == "192.168.1.5"
    with pytest.raises(v.ValidationError):
        v.validate_listen_address("192.168.1.9", local_addresses=["192.168.1.5"])
    with pytest.raises(v.ValidationError):
        v.validate_listen_address("localhost")


@pytest.mark.parametrize("path", ["/var/lib/sentinelcore/data", "/srv/sc", "/data//x/"])
def test_data_dir_ok(path):
    assert v.validate_data_dir(path).startswith("/")


@pytest.mark.parametrize("path", ["relative/path", "/", "/etc", "/var/../etc", "/srv/x\ny", "", "/usr"])
def test_data_dir_bad(path):
    with pytest.raises(v.ValidationError):
        v.validate_data_dir(path)


@pytest.mark.parametrize("name", ["admin", "dhruv.patel", "a_b-c9"])
def test_username_ok(name):
    assert v.validate_username(name) == name


@pytest.mark.parametrize("name", ["", "ab", "1admin", "ad min", "admin;id", "x" * 33, "ro/ot"])
def test_username_bad(name):
    with pytest.raises(v.ValidationError):
        v.validate_username(name)


def test_hostname_and_email_and_retention():
    assert v.validate_hostname("sentinel-01.lab") == "sentinel-01.lab"
    for bad in ["", "-bad", "a_b", "x" * 64]:
        with pytest.raises(v.ValidationError):
            v.validate_hostname(bad)
    assert v.validate_email("") == ""
    assert v.validate_email("a@b.co") == "a@b.co"
    with pytest.raises(v.ValidationError):
        v.validate_email("not-an-email")
    with pytest.raises(v.ValidationError):
        v.validate_email("a'b@c.com")
    assert v.validate_retention_days("90") == 90
    for bad in ["0", "3651", "x"]:
        with pytest.raises(v.ValidationError):
            v.validate_retention_days(bad)


# -- password strength -------------------------------------------------------
def test_password_too_short_is_rejected():
    score, msg = v.password_strength("Abc123!")
    assert score == 0 and "short" in msg.lower()
    with pytest.raises(v.ValidationError):
        v.validate_password("Abc123!xyz")  # 10 chars


def test_password_common_or_username_rejected():
    with pytest.raises(v.ValidationError):
        v.validate_password("adminadmin12")
    with pytest.raises(v.ValidationError):
        v.validate_password("MyAdmin-Pass-9", username="admin")


def test_password_needs_variety():
    with pytest.raises(v.ValidationError):
        v.validate_password("alllowercaseletters")
    with pytest.raises(v.ValidationError):
        v.validate_password("aaaaaaaaaaaaaaaa")


def test_password_rejects_quote_and_newline():
    for bad in ["Valid-Pass-123'x", "Valid-Pass-123\nx"]:
        with pytest.raises(v.ValidationError):
            v.validate_password(bad)


def test_password_good_scores_increase():
    s_ok, _ = v.password_strength("Tr1cky-Pass-9x")
    s_long, _ = v.password_strength("Tr1cky-Pass-9x-and-much-longer-1!")
    assert s_ok >= 2 and s_long >= s_ok
    assert v.validate_password("Tr1cky-Pass-9x") == "Tr1cky-Pass-9x"
