# Changelog

All notable changes to SentinelCore releases are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/). The version number lives in one
place: the `VERSION` file. Bump it with `python scripts/release/bump-version.py`.

## [Unreleased]

### Added
- Linux installer with guided setup wizard, generated configuration, `.deb`
  package, one-line `install.sh` and an offline bundle.
- `sentinelcore` command line tool: install, start, stop, restart, status, logs,
  doctor, backup, restore, update, uninstall, version.
- Signed release pipeline: public downloads, private source.
- Product website (static).

## [0.1.0] - unreleased

First packaged release candidate. Contains modules M0-M12 and the audit-log,
PCAP-isolation, dashboard and email upgrades already on `main`.
