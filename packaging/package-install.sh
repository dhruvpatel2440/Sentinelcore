#!/bin/sh
# SentinelCore installer package: install.sh
#
#   tar xzf sentinelcore-installer-<version>.tar.gz
#   cd sentinelcore-installer-<version>
#   sudo ./install.sh
#
# 1. verifies every file against checksums/SHA256SUMS and the signature on it,
# 2. installs the `sentinelcore` command and release files (same layout as the .deb),
# 3. starts the guided wizard, which pulls the digest-pinned SentinelCore images.
# The application source is NOT in this package: it is compiled into the images.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
KEY_FPR="__RELEASE_KEY_FINGERPRINT__"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo ./install.sh"
case "$KEY_FPR" in
  __RELEASE*|"") die "this package was not built by the release pipeline (no signing key fingerprint); refusing to install" ;;
esac
command -v python3 >/dev/null 2>&1 || die "python3 is required (sudo apt-get install -y python3)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "python 3.10 or newer is required"
for tool in sha256sum gpg openssl; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required (sudo apt-get install -y gnupg openssl coreutils)"
done

cd "$HERE"
say "Verifying package signature and checksums ..."
if [ ! -f checksums/SHA256SUMS ] || [ ! -f signatures/SHA256SUMS.asc ] || [ ! -f packaging/release-key.asc ]; then
  die "checksums or signature missing from the package"
fi
GNUPGHOME="$(mktemp -d)"; export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT INT TERM
GOT_FPR="$(gpg --batch --with-colons --show-keys packaging/release-key.asc | awk -F: '$1=="fpr"{print $10; exit}')"
[ "$GOT_FPR" = "$KEY_FPR" ] || die "release key fingerprint mismatch; the package was modified"
gpg --batch --quiet --import packaging/release-key.asc
gpg --batch --status-fd 1 --verify signatures/SHA256SUMS.asc checksums/SHA256SUMS 2>/dev/null | grep -q '^\[GNUPG:\] VALIDSIG' \
  || die "signature on checksums/SHA256SUMS is INVALID"
sha256sum -c --quiet checksums/SHA256SUMS || die "a file does not match its checksum; re-download the package"
say "Package verified."

say "Installing the sentinelcore command ..."
LIB=/usr/lib/sentinelcore; SHARE=/usr/share/sentinelcore
rm -rf "$LIB/sentinelcore_installer"
install -d "$LIB" "$SHARE/nginx" "$SHARE/suricata" "$SHARE/systemd"
cp -r installer/sentinelcore_installer "$LIB/"
find "$LIB" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
install -m 0755 installer/sentinelcore /usr/bin/sentinelcore
install -m 0755 installer/sentinelcore-installer /usr/bin/sentinelcore-installer
install -m 0644 packaging/docker-compose.release.yml packaging/release.env.template packaging/EULA.txt \
  packaging/release-key.asc "$SHARE/"
install -m 0644 packaging/nginx/nginx.release.conf "$SHARE/nginx/"
install -m 0644 packaging/suricata/suricata.yaml "$SHARE/suricata/"
install -m 0644 packaging/systemd/sentinelcore.service "$SHARE/systemd/"
install -m 0644 images.json VERSION "$SHARE/"

say "Starting the setup wizard ..."
if [ -r /dev/tty ] && [ -z "${SENTINELCORE_NO_TTY_REDIRECT:-}" ]; then
  exec /usr/bin/sentinelcore install "$@" </dev/tty
fi
exec /usr/bin/sentinelcore install "$@"
