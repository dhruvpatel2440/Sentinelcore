# SentinelCore installer

Linux installer, guided wizard and management CLI. **Python standard library
only**, so it runs on a fresh Ubuntu with nothing extra installed. It builds
*around* the app: nothing in `frontend/src`, `backend/app`, `helper/helper` or
the existing Dockerfiles/compose files is changed.

```
installer/
  sentinelcore                  CLI launcher  (installed as /usr/bin/sentinelcore)
  sentinelcore-installer        = `sentinelcore install`
  sentinelcore_installer/
    validators.py   CIDR, interface, ports, protected IPs, passwords, paths...
    netinfo.py      interfaces, gateway, DNS, host addresses (iproute2 JSON)
    configgen.py    answers -> sentinelcore.env (0600) + install-profile.yaml (no secrets)
    wizard.py       the screens (back/next, validation, review)
    ui.py           whiptail UI with a plain-text fallback
    preflight.py    root, OS, Docker/Compose, disk, RAM, ports, interfaces; Docker install
    install.py      idempotent install phases, health checks, rollback, final verification
    signing.py      SHA256SUMS + GnuPG detached-signature verification
    cli.py          install, start, stop, restart, status, logs, doctor, backup, restore,
                    update, uninstall, version
  tests/            unit tests (validators, config generation, wizard flow, helpers)
../packaging/       release compose, nginx conf, systemd unit, .deb/offline/install.sh builders
```

## Use

```bash
sudo sentinelcore install                         # guided wizard
sudo sentinelcore install --generate-only         # write config, install nothing
sudo sentinelcore install --config install-profile.yaml --non-interactive   # replay (admin password in $SENTINELCORE_ADMIN_PASSWORD)
sudo sentinelcore install --offline-bundle ./sentinelcore-offline-X.Y.Z      # no internet
sudo sentinelcore status | doctor | logs [service] | backup | restore FILE | update | uninstall [--purge]
```

## What gets written

| File | Content |
|---|---|
| `/etc/sentinelcore/sentinelcore.env` | every variable the stack needs, generated secrets, mode `0600`, root |
| `/etc/sentinelcore/install-profile.yaml` | the wizard answers **without secrets**: the replayable "customized package" |
| `/etc/sentinelcore/tls/` | self-signed certificate (SAN: localhost, host name, detected IPs) |
| `/opt/sentinelcore/` | compose file, nginx conf, Suricata conf, pinned image list (`release.env`) |
| `/var/log/sentinelcore-install.log` | the install log (secrets are never logged) |

## Design decisions worth knowing

- **Migrations and admin seeding** are done by the existing backend entrypoint on first boot; the installer then runs `alembic upgrade head` and `scripts.seed_admin` again (both idempotent) so the result is explicit in the log.
- **`SEED_ADMIN_PASSWORD` is removed** from `sentinelcore.env` once the installer has proven the admin can sign in, so the password does not stay on disk.
- **Re-runs keep live secrets** (database password, JWT key) so they cannot lock the stack out of its own data.
- **HSTS** defaults to 300 seconds. The shipped certificate is self-signed, and a long HSTS lifetime stops browsers from offering "proceed anyway". Raise `HSTS_MAX_AGE` in `sentinelcore.env` once you install a trusted certificate.
- **Data directory** holds backups. PostgreSQL, reports and captures stay in Docker-managed volumes (their ownership/permissions are set by the images).
- **Profile format** is YAML (a small built-in parser handles the subset the profile uses, so no PyYAML is needed); a JSON profile is also accepted.
- **Rollback** stops only the containers a failed run started; config files stay for debugging and data volumes are never deleted.

## Develop

```bash
cd installer
python -m pytest            # from the repo root: python -m pytest installer/tests scripts/release
```

Rules enforced by tests and CI: every external command is an argv list; no
`shell=True`, no `os.system`; no secret ever appears in an argv, a log line or
the profile.
