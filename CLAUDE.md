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
- All root operations go through privileged-helper via Unix socket
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

## Database Tables
users, assets, asset_ports, events, incidents,
incident_history, ioc, firewall_actions, audit_log

## Never Do
- Never commit .env
- Never store secrets in code
- Never run API as root
- Never string-concatenate shell commands
