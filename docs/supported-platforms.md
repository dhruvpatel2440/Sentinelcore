# Supported platforms

SentinelCore installs on Linux with Docker Engine and Compose v2. WSL is **not**
supported: its virtualised networking cannot present a real promiscuous or
mirrored capture interface to Suricata.

Status meanings:

- **tested**: installed end to end on a clean VM with `install.sh`, the wizard
  completed, the dashboard opened, `sentinelcore doctor`, `backup` and
  `uninstall` ran. The date and VM are recorded in [installer-test.md](installer-test.md).
- **expected to work, untested**: same family, same packages, nobody has installed it yet.
- **not supported**: known not to work, or cannot work.

| Distribution | Version | Status | Notes |
|---|---|---|---|
| Ubuntu Server | 24.04 LTS | expected to work, untested | Reference platform; the app itself has been run here (see `TEST_REPORT.md`). The **installer** has not yet been run on a clean VM. |
| Ubuntu Server | 22.04 LTS | expected to work, untested | |
| Debian | 12 (bookworm) | expected to work, untested | |
| Other Linux with Docker Engine + Compose v2 | any | expected to work, untested | The `.deb` and `install.sh` are apt-only; other distributions would need a manual install. |
| Windows (native) | any | not supported | Linux only. |
| WSL 1 / WSL 2 | any | not supported | No real capture interface. |
| macOS | any | not supported | No `iptables`, no AF_PACKET capture. |

> **Maintainer:** change a row to **tested** only after completing the checklist
> in [installer-test.md](installer-test.md) on a clean VM snapshot. The website's
> Download page reads this table; it lists only rows marked *tested* as tested.

## Minimum hardware

| Resource | Minimum |
|---|---|
| CPU | 2 cores |
| RAM | 4 GB |
| Disk | 10 GB free (more for packet captures and event retention) |
| Network | One interface that can see the traffic to monitor (mirror/SPAN port, or a VirtualBox adapter with Promiscuous Mode "Allow All") |
| Ports | 80 and 443 free on the listen address (changeable in a Custom install) |
