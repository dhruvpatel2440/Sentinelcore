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

    # M8 — incident promotion
    auto_promote_score: int = 70  # roughly the "high"/"critical" band
    incident_merge_window_minutes: int = 60

    # M9 — reporting
    report_storage_path: str = "/var/lib/sentinelcore/reports"
    max_report_window_days: int = 365
    max_concurrent_reports_per_user: int = 3
    report_retention_days: int = 30
    report_generation_timeout_seconds: int = 600
    report_queue_key: str = "reports:queue"

    # M10 — firewall containment
    max_active_blocks: int = 100
    firewall_expiry_interval_seconds: int = 15
    firewall_reconcile_interval_seconds: int = 300
    firewall_expiry_alert_after_attempts: int = 5

    # M11 — PCAP analysis
    pcap_storage_path: str = "/var/lib/sentinelcore/pcap"
    max_pcap_size_mb: int = 500
    pcap_parse_timeout_seconds: int = 300
    max_flows_per_pcap: int = 50_000
    pcap_retention_days: int = 30
    pcap_queue_key: str = "pcap:queue"
    pcap_upload_chunk_bytes: int = 1024 * 1024

    # M12 — threat intelligence
    intel_feed_max_response_mb: int = 50
    intel_feed_timeout_seconds: int = 30
    intel_feed_row_cap: int = 200_000
    intel_feed_scheduler_interval_seconds: int = 300
    intel_expiry_interval_seconds: int = 3600
    intel_match_email_min_confidence: int = 70  # E06 threshold

    # U10 — email notifications (Brevo)
    email_mode: str = "off"  # off | dry_run | brevo
    brevo_api_key: str = ""
    email_sender_address: str = ""
    email_sender_name: str = "SentinelCore"
    email_reply_to: str = ""
    app_base_url: str = "https://sentinel.lab"
    email_allowed_recipient_domains: str = ""  # comma list; empty = any registered user email
    email_daily_cap_per_recipient: int = 50
    email_global_daily_cap: int = 250
    email_max_attachment_mb: int = 5
    brevo_webhook_secret: str = ""
    incident_sla_minutes_critical: int = 15
    incident_sla_minutes_high: int = 60
    incident_sla_minutes_medium: int = 240
    email_outbox_drain_interval_seconds: int = 5
    email_outbox_reaper_stuck_minutes: int = 5
    email_health_scan_interval_seconds: int = 60
    email_outbox_retention_sent_days: int = 30
    email_outbox_retention_failed_days: int = 90
    email_send_empty_digest: bool = False

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
    def email_allowed_recipient_domains_parsed(self) -> frozenset[str]:
        return frozenset(
            d.strip().lower() for d in self.email_allowed_recipient_domains.split(",") if d.strip()
        )

    @cached_property
    def email_mode_resolved(self) -> str:
        """Falls back to `off` if `brevo` mode is missing its key/sender —
        never crashes the app over an email misconfiguration."""
        if self.email_mode == "brevo" and (not self.brevo_api_key or not self.email_sender_address):
            import logging

            logging.getLogger("sentinelcore.email").error(
                "EMAIL_MODE=brevo but BREVO_API_KEY or EMAIL_SENDER_ADDRESS is missing; "
                "falling back to EMAIL_MODE=off"
            )
            return "off"
        return self.email_mode

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
