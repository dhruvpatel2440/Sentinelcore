"""Pure input validators. Every wizard answer passes through one of these.

All functions either return the normalised value or raise ValidationError with
a message that is safe to show the user verbatim.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

COMMON_PASSWORDS = frozenset(
    {
        "password", "password1", "password123", "123456789012", "qwertyuiop12",
        "administrator", "adminadmin12", "letmein12345", "changeme1234",
        "sentinelcore", "sentinelcore1", "welcome12345", "iloveyou1234",
    }
)

_IFNAME_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
_USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,31}$")
_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_EMAIL_RE = re.compile(r"^[^@\s'\"\\]+@[^@\s'\"\\]+\.[^@\s'\"\\]+$")

MIN_PASSWORD_LENGTH = 12  # backend/scripts/seed_admin.py rejects anything shorter


class ValidationError(ValueError):
    pass


def validate_cidr(value: str) -> str:
    """IPv4 network in CIDR form; host bits are normalised away."""
    text = (value or "").strip()
    if "/" not in text:
        raise ValidationError("Enter the network as an address and prefix, e.g. 192.168.1.0/24.")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValidationError(f"'{text}' is not a valid network: {exc}.") from exc
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValidationError("Only IPv4 networks are supported.")
    if net.prefixlen < 8:
        raise ValidationError("A prefix shorter than /8 is too large to monitor. Use /8 to /32.")
    return str(net)


def validate_ipv4(value: str) -> str:
    text = (value or "").strip()
    try:
        ip = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValidationError(f"'{text}' is not a valid IP address.") from exc
    if not isinstance(ip, ipaddress.IPv4Address):
        raise ValidationError("Only IPv4 addresses are supported.")
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        raise ValidationError(f"{ip} cannot be used as a protected address.")
    return str(ip)


def validate_protected_ips(values: Iterable[str] | str) -> list[str]:
    """Non-empty, de-duplicated, order-preserving list of valid IPv4 addresses."""
    if isinstance(values, str):
        items = [v for v in re.split(r"[,\s]+", values) if v]
    else:
        items = [v for v in values if v and v.strip()]
    if not items:
        raise ValidationError(
            "The protected list can never be empty: it must contain at least your "
            "gateway or this host, so containment can never cut you off."
        )
    seen: dict[str, None] = {}
    for item in items:
        seen[validate_ipv4(item)] = None
    return list(seen)


def validate_interface_name(value: str, known: Iterable[str] | None = None) -> str:
    text = (value or "").strip()
    if text in {".", ".."} or not _IFNAME_RE.fullmatch(text):
        raise ValidationError(
            "Interface names are 1-15 characters of letters, digits and . _ : @ - (for example eth1)."
        )
    if text == "lo":
        raise ValidationError("The loopback interface cannot be used for capture.")
    if known is not None and text not in set(known):
        raise ValidationError(f"No network interface named '{text}' exists on this machine.")
    return text


def validate_port(value: str | int, label: str = "Port") -> int:
    try:
        port = int(str(value).strip())
    except ValueError as exc:
        raise ValidationError(f"{label} must be a number between 1 and 65535.") from exc
    if not 1 <= port <= 65535:
        raise ValidationError(f"{label} must be between 1 and 65535.")
    return port


def validate_port_pair(http: str | int, https: str | int) -> tuple[int, int]:
    http_port = validate_port(http, "HTTP port")
    https_port = validate_port(https, "HTTPS port")
    if http_port == https_port:
        raise ValidationError("The HTTP and HTTPS ports must be different.")
    return http_port, https_port


def validate_listen_address(value: str, local_addresses: Iterable[str] | None = None) -> str:
    text = (value or "").strip()
    if text in {"127.0.0.1", "0.0.0.0"}:
        return text
    ip = validate_ipv4(text)
    if local_addresses is not None and ip not in set(local_addresses):
        raise ValidationError(f"{ip} is not an address of this machine.")
    return ip


def validate_username(value: str) -> str:
    text = (value or "").strip()
    if not _USERNAME_RE.fullmatch(text):
        raise ValidationError(
            "Usernames are 3-32 characters: start with a letter, then letters, digits, . _ or -."
        )
    return text


def validate_email(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if not _EMAIL_RE.fullmatch(text) or len(text) > 254:
        raise ValidationError("That does not look like an email address (or leave it blank).")
    return text


def validate_hostname(value: str) -> str:
    text = (value or "").strip().rstrip(".")
    if not text or len(text) > 253:
        raise ValidationError("Enter a host name.")
    if not all(_HOSTNAME_LABEL_RE.fullmatch(label) for label in text.split(".")):
        raise ValidationError(f"'{text}' is not a valid host name.")
    return text


def validate_data_dir(value: str) -> str:
    text = (value or "").strip()
    if not text.startswith("/"):
        raise ValidationError("Use an absolute path such as /var/lib/sentinelcore/data.")
    if ".." in text.split("/") or "\x00" in text or "\n" in text:
        raise ValidationError("The path must not contain '..' or control characters.")
    normalised = "/" + "/".join(part for part in text.split("/") if part)
    if normalised in {"/", "/etc", "/usr", "/bin", "/boot", "/dev", "/proc", "/sys", "/var", "/root", "/home"}:
        raise ValidationError(f"{normalised} is a system directory. Choose a dedicated folder.")
    return normalised


def validate_retention_days(value: str | int) -> int:
    try:
        days = int(str(value).strip())
    except ValueError as exc:
        raise ValidationError("Retention must be a whole number of days.") from exc
    if not 1 <= days <= 3650:
        raise ValidationError("Retention must be between 1 and 3650 days.")
    return days


def password_strength(password: str, username: str = "") -> tuple[int, str]:
    """Return (score 0-4, feedback). Score 3+ is acceptable; length >= 12 is mandatory."""
    if not password:
        return 0, "Enter a password."
    if "'" in password or "\n" in password or "\r" in password or "\x00" in password:
        return 0, "Do not use a single quote or line break (they cannot be stored safely)."
    if len(password) < MIN_PASSWORD_LENGTH:
        return 0, f"Too short: {len(password)} of at least {MIN_PASSWORD_LENGTH} characters."
    low = password.lower()
    if low in COMMON_PASSWORDS or (username and username.lower() in low):
        return 1, "Too guessable: avoid common passwords and your username."
    classes = sum(
        bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    if len(set(password)) < 6:
        return 1, "Too repetitive: use a wider mix of characters."
    score = 1 + (classes >= 3) + (len(password) >= 16) + (classes == 4 and len(password) >= 20)
    score = min(score, 4)
    if classes < 3:
        return min(score, 2), "Add upper-case, lower-case, digits or symbols (at least three kinds)."
    labels = {2: "Acceptable.", 3: "Good.", 4: "Excellent."}
    return score, labels.get(score, "Acceptable.")


def validate_password(password: str, username: str = "") -> str:
    score, feedback = password_strength(password, username)
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if score < 2 or classes < 3:
        raise ValidationError(feedback)
    return password
