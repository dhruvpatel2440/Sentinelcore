# SentinelCore releases

Signed downloads for **SentinelCore**, a modular network detection and incident
response platform. This repository contains **no source code**: only release
notes and a pointer to the files attached to each [release](../../releases).

## Install (Ubuntu / Debian, one command)

```bash
curl -fsSL https://github.com/dhruvpatel2440/sentinelcore-releases/releases/latest/download/install.sh | sudo sh
```

The script verifies a signature and checksum before installing anything, then
starts a guided setup wizard. Docker Engine is installed for you if missing
(only with your consent).

## Other downloads (each release)

| File | Use |
|---|---|
| `sentinelcore_<version>_all.deb` | The package. Then run `sudo sentinelcore install`. |
| `sentinelcore-offline-<version>.tar.gz` | Offline bundle for machines without internet. |
| `install.sh` / `install.sh.asc` | The one-line installer and its signature. |
| `SHA256SUMS` / `SHA256SUMS.asc` | Checksums and their signature. |
| `latest.json` / `latest.json.asc` | What `sentinelcore update` reads. |
| `release-key.asc` | The public key that signs every release. |
| `images.json` | Container images pinned by digest. |
| `sbom-*.spdx.json` | Software bill of materials per image. |

## Verify manually

```bash
gpg --show-keys release-key.asc      # compare the fingerprint with the website
gpg --import release-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

## Licence

All rights reserved. Use is subject to the End User Licence Agreement shown by
the installer. SentinelCore must only be used on networks you own or are
authorised to monitor.
