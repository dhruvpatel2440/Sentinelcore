"""M12 indicator normalization.

Get this right or matching silently fails: a feed and an analyst's pasted
indicator must collapse to the exact same string, or the unique key in `ioc`
splits one indicator into two rows that never match each other.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.models.ioc import IocType

_HASH_LENGTHS = {IocType.MD5: 32, IocType.SHA1: 40, IocType.SHA256: 64}
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Noise an analyst or a sloppy feed will paste; matching on these would either
# match everything or match nothing usefully.
_NOISE_INDICATORS = {"0.0.0.0", "localhost", "127.0.0.1", "::1", "255.255.255.255"}

# Infrastructure so common that listing it as an IOC is almost always a feed
# error, not a real indicator — reject with a clear reason rather than poison
# matching against the platform's own dependencies.
_ALLOWLISTED_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "cloudflare.com", "amazonaws.com",
    "akamai.net", "akamaiedge.net", "microsoft.com", "windowsupdate.com", "apple.com",
    "root-servers.net",
}

_BARE_TLD_RE = re.compile(r"^[a-z]{2,24}$")


class NormalizationError(ValueError):
    """The indicator was rejected. `reason` is safe to show to a caller or
    log to a feed's reject counter — it never contains attacker HTML."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class NormalizedIndicator:
    value: str
    ioc_type: IocType
    apex: str | None = None  # domains only: value with a leading "www." stripped
    cidr_shadow: str | None = None  # cidr indicators only: str(ipaddress network)


def defang(raw: str) -> str:
    """Reverse the defanging analysts apply when pasting indicators from
    reports, so `hxxp://evil[.]com` becomes `http://evil.com` before typed
    parsing ever sees it."""
    text = raw.strip()
    text = re.sub(r"hxxps?://", lambda m: m.group(0).replace("hxx", "htt"), text, flags=re.IGNORECASE)
    text = re.sub(r"\[\.\]|\(\.\)|\[dot\]", ".", text, flags=re.IGNORECASE)
    text = re.sub(r"\[:\]", ":", text)
    text = re.sub(r"\[at\]|\(at\)", "@", text, flags=re.IGNORECASE)
    return text


def _reject_if_noise(domain_or_ip: str) -> None:
    if domain_or_ip in _NOISE_INDICATORS:
        raise NormalizationError(f"'{domain_or_ip}' is noise, not a usable indicator")


def normalize_ip(raw: str) -> NormalizedIndicator:
    try:
        addr = ipaddress.ip_address(raw.strip())
    except ValueError as exc:
        raise NormalizationError(f"'{raw}' is not a valid IP address") from exc

    _reject_if_noise(str(addr))
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        raise NormalizationError(f"'{addr}' is a private/loopback/link-local/multicast address — refusing to add")

    return NormalizedIndicator(value=str(addr), ioc_type=IocType.IP)


def normalize_cidr(raw: str) -> NormalizedIndicator:
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError as exc:
        raise NormalizationError(f"'{raw}' is not a valid CIDR block") from exc

    if net.is_private or net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
        raise NormalizationError(f"'{net}' overlaps private/loopback/link-local/multicast space — refusing to add")

    value = str(net)
    return NormalizedIndicator(value=value, ioc_type=IocType.CIDR, cidr_shadow=value)


def normalize_domain(raw: str) -> NormalizedIndicator:
    domain = raw.strip().lower().rstrip(".")
    if not domain:
        raise NormalizationError("empty domain")

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NormalizationError(f"'{raw}' is not a valid domain (IDNA encoding failed)") from exc

    _reject_if_noise(domain)
    if _BARE_TLD_RE.match(domain) and "." not in domain:
        raise NormalizationError(f"'{domain}' is a bare TLD, not a usable indicator")
    if domain in _ALLOWLISTED_DOMAINS or any(domain.endswith(f".{d}") for d in _ALLOWLISTED_DOMAINS):
        raise NormalizationError(f"'{domain}' is common infrastructure — refusing to add")

    # Strip a leading "www." only into a separate apex field; the original
    # value is preserved so "www.evil.com" and "evil.com" can both be tracked.
    apex = domain[4:] if domain.startswith("www.") else None
    return NormalizedIndicator(value=domain, ioc_type=IocType.DOMAIN, apex=apex)


def normalize_url(raw: str) -> NormalizedIndicator:
    parts = urlsplit(raw.strip())
    if not parts.scheme or not parts.netloc:
        raise NormalizationError(f"'{raw}' is not a valid URL")

    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    # Path, query and fragment case is preserved — a case-sensitive URI path
    # is common and destroying case there breaks the match.
    normalized = urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))
    return NormalizedIndicator(value=normalized, ioc_type=IocType.URL)


def normalize_hash(raw: str, ioc_type: IocType) -> NormalizedIndicator:
    value = raw.strip().lower()
    if not _HEX_RE.match(value):
        raise NormalizationError(f"'{raw}' is not hexadecimal")
    expected_len = _HASH_LENGTHS[ioc_type]
    if len(value) != expected_len:
        raise NormalizationError(f"'{raw}' is {len(value)} hex chars, expected {expected_len} for {ioc_type.value}")
    return NormalizedIndicator(value=value, ioc_type=ioc_type)


def normalize_email(raw: str) -> NormalizedIndicator:
    value = raw.strip().lower()
    if not _EMAIL_RE.match(value):
        raise NormalizationError(f"'{raw}' is not a valid email address")
    return NormalizedIndicator(value=value, ioc_type=IocType.EMAIL)


def detect_type(value: str) -> IocType | None:
    """Best-effort type detection for free-text lookup/bulk-add input."""
    try:
        ipaddress.ip_address(value)
        return IocType.IP
    except ValueError:
        pass
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return IocType.CIDR
        except ValueError:
            pass
    if value.lower().startswith(("http://", "https://")):
        return IocType.URL
    if _EMAIL_RE.match(value):
        return IocType.EMAIL
    if _HEX_RE.match(value.lower()):
        for ioc_type, length in _HASH_LENGTHS.items():
            if len(value) == length:
                return ioc_type
    if "." in value:
        return IocType.DOMAIN
    return None


_NORMALIZERS = {
    IocType.IP: normalize_ip,
    IocType.CIDR: normalize_cidr,
    IocType.DOMAIN: normalize_domain,
    IocType.URL: normalize_url,
    IocType.EMAIL: normalize_email,
    IocType.MD5: lambda v: normalize_hash(v, IocType.MD5),
    IocType.SHA1: lambda v: normalize_hash(v, IocType.SHA1),
    IocType.SHA256: lambda v: normalize_hash(v, IocType.SHA256),
}


def normalize(raw: str, ioc_type: IocType | None = None) -> NormalizedIndicator:
    """Defang, then normalize per `ioc_type` (or best-effort detected type).

    Raises `NormalizationError` with a human-readable reason on rejection —
    callers (bulk add, feed ingestion) collect these per-line rather than
    failing the whole batch.
    """
    refanged = defang(raw)
    if not refanged:
        raise NormalizationError("empty indicator")

    resolved_type = ioc_type or detect_type(refanged)
    if resolved_type is None:
        raise NormalizationError(f"could not determine indicator type for '{raw}'")

    normalizer = _NORMALIZERS.get(resolved_type)
    if normalizer is None:
        raise NormalizationError(f"unsupported indicator type '{resolved_type}'")

    return normalizer(refanged)
