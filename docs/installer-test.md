# Installer test record

**Status: NOT YET RUN on a clean VM.** What exists today:

- Unit tests for every validator, config generation, the wizard flow (scripted),
  version ordering, checksum parsing, tar-extraction safety and the
  no-shell-execution rule: `cd installer && python -m pytest` (109 pass, 1
  POSIX-only file-mode test is skipped on Windows and runs on Linux/CI).
- `bash -n` syntax checks on the three shell scripts.

Nothing below has been executed against real Docker, Suricata or systemd yet.
Fill the table in as each step is done, then update
[supported-platforms.md](supported-platforms.md).

## Environment

| Field | Value |
|---|---|
| Date | |
| Host / hypervisor | |
| VM image | Ubuntu 24.04 LTS Server, clean snapshot |
| VM resources | 2 vCPU, 4 GB RAM, 20 GB disk |
| Adapters | 1: NAT (internet). 2: host-only, Promiscuous Mode = Allow All |
| Package under test | `sentinelcore_<version>_all.deb` / `install.sh` build id |
| Tester | |

## Procedure and results

| # | Step | Expected | Result | Notes |
|---|---|---|---|---|
| 1 | Restore the clean snapshot; confirm no Docker installed | `docker` not found | | |
| 2 | `curl -fsSL <url>/install.sh \| sudo sh` | Signature OK, `.deb` installed, wizard starts | | |
| 3 | Wizard: accept EULA, Quick install, accept Docker install | Docker Engine + Compose installed | | |
| 4 | Pick the host-only adapter; confirm CIDR, protected IPs (gateway, DNS, host) | Values pre-filled correctly | | |
| 5 | Choose "generate password"; finish | Progress shows every phase `ok`; final verification all `ok`; password shown once | | |
| 6 | Open `https://localhost`, accept the certificate warning, log in | Dashboard loads | | |
| 7 | `sudo sentinelcore status` | All services healthy, sensor running on the chosen interface | | |
| 8 | Generate traffic from another VM on the host-only network; check events | Alerts/events appear | | |
| 9 | Reboot the VM | Stack comes back by itself (systemd unit), dashboard reachable | | |
| 10 | `sudo sentinelcore doctor` | No `fail` lines; any `warn` explained | | |
| 11 | `sudo sentinelcore backup` then `restore <file>` | Encrypted file created; restore succeeds | | |
| 12 | Run the installer again | Repairs/keeps data, no errors, admin still works | | |
| 13 | `sudo sentinelcore uninstall` | Services removed, data kept | | |
| 14 | `sudo sentinelcore install --config /etc/sentinelcore/install-profile.yaml --non-interactive` with `SENTINELCORE_ADMIN_PASSWORD` set | Same setup reproduced; new secrets generated | | |
| 15 | `sudo sentinelcore uninstall --purge` (type the host name) | Everything removed | | |
| 16 | Failure drill: occupy port 443 first | Pre-flight explains the problem and the fix | | |
| 17 | Failure drill: block the registry (firewall) during image pull | Rollback stops the stack, config left, clear message | | |
| 18 | Offline bundle on a VM with networking disabled | Install completes from local archives | | |

## Issues found

| # | Description | Severity | Fixed in |
|---|---|---|---|
| | | | |
