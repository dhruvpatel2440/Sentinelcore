# SentinelCore — CLAUDE.md

## Project
Modular network detection and incident response platform.
Backend: Python/FastAPI | Frontend: React/Tailwind | DB: PostgreSQL
Sensor: Suricata | Discovery: Nmap + Scapy | Deploy: Docker Compose

## Build Order
M0 Infrastructure → M1 Auth/RBAC → M2 App Shell →
M3 Asset Discovery → M4 Suricata → M5 Event Pipeline →
M6 Search → M7 Correlation → M8 Incidents →
M9 Reporting → M10 Firewall → M11 PCAP → M12 Threat Intel

## CRITICAL Architecture Rules
- FastAPI backend runs UNPRIVILEGED, never as root
- All root (privileged, capability-requiring) operations go through
  privileged-helper via Unix socket
- The API process never runs privileged operations and never invokes a
  shell. The only permitted subprocess use in the whole backend is
  `backend/app/pcap/parser.py` (tshark/capinfos): fixed argv lists,
  absolute resolved binary paths, no network name-resolution (`-n`),
  wall-clock timeout, CPU/address-space rlimits, runs as the unprivileged
  `appuser` — never the helper. Enforced by
  `backend/tests/test_no_subprocess.py`. See U03 in `updates/` for why
  this is not routed through the helper: PCAPs are attacker-controlled
  input and tshark dissectors have a long CVE history, so parsing them
  inside the one root-capable component would be the worst place for it.
- NEVER use shell=True in subprocess calls
- NEVER build shell commands by string concatenation
- All IPs, CIDRs, ports validated with strict typed checks
- No user-supplied input ever reaches a shell string

## Roles
- viewer: read only
- analyst: triage and resolve incidents
- admin: full access + sensor + firewall containment

## Security Rules
- Argon2 password hashing always
- JWT access tokens 15min + refresh tokens 7 days
- Every write action logged to audit_log table
- Gateway, DNS, self IP can NEVER be blocked
- All firewall rules have mandatory TTL
- Firewall rules are applied via `iptables` on the kernel's nftables backend
  (`iptables-nft`) — Ubuntu/Debian 24.04's default `iptables` binary; confirm
  with `iptables --version` (reports `(nf_tables)`). `helper/helper/ops/firewall.py`
  and `helper/helper/config.py` document this. Same wording used in README.md
  and TEST_REPORT.md — do not drift.

## Database Tables
users, assets, asset_ports, events, incidents,
incident_history, ioc, firewall_actions, audit_log

## Never Do
- Never commit .env
- Never store secrets in code
- Never run API as root
- Never string-concatenate shell commands
