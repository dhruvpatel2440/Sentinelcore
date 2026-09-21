from functools import cached_property
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Database
    database_url: str

    # Auth
    secret_key: str = "dev-only-placeholder-change-in-env"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    jwt_algorithm: str = "HS256"

    # Login throttling (M1) — per username+IP, backed by Redis
    login_max_attempts: int = 5
    login_lockout_seconds: int = 300

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # Network scope
    capture_interface: str = "eth1"
    monitored_network: str = "192.168.10.0/24"
    protected_ips: str = ""

    # Privileged helper (M3+). The API reaches root operations only via this
    # socket; it holds no NET_RAW/NET_ADMIN capability of its own.
    helper_socket_path: str = "/run/sentinelcore/helper.sock"

    # Suricata
    suricata_eve_log: str = "/var/log/suricata/eve.json"
    suricata_staging_dir: str = "/var/lib/sentinelcore/staging"

    # Pipeline
    event_retention_days: int = 90

    # M6 — event search
    max_search_window_days: int = 30
    search_facet_cache_seconds: int = 30

    # M7 — correlation engine
    correlation_interval_seconds: int = 30
    correlation_lookback_grace_seconds: int = 60
    correlation_rule_timeout_seconds: int = 60
    correlation_max_concurrent_rules: int = 4
    correlation_candidates_channel: str = "correlation:candidates"

    # Deployment
    environment: str = "development"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def cookie_secure(self) -> bool:
        """Refresh cookie is Secure in production; plain HTTP dev would drop it."""
        return self.is_production

    @cached_property
    def monitored_network_parsed(self) -> IPv4Network:
        net = ip_network(self.monitored_network, strict=False)
        if not isinstance(net, IPv4Network):
            raise ValueError("MONITORED_NETWORK must be an IPv4 network")
        return net

    @cached_property
    def protected_ips_parsed(self) -> frozenset[IPv4Address]:
        """IPs that may never be firewall-blocked (M10) — gateway, DNS, self."""
        out: set[IPv4Address] = set()
        for chunk in self.protected_ips.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            addr = ip_address(chunk)
            if not isinstance(addr, IPv4Address):
                raise ValueError(f"PROTECTED_IPS entry is not IPv4: {chunk}")
            out.add(addr)
        return frozenset(out)


settings = Settings()
