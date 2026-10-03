#!/usr/bin/env bash
# Build sentinelcore_<version>_all.deb with dpkg-deb.
#
#   packaging/build-deb.sh <version> [outdir]
#
# Env:
#   IMAGES_JSON   manifest with real digests (default: packaging/images.json)
#   RELEASE_KEY   public key file to ship as release-key.asc
#   RELEASE=1     fail instead of warn when the release key or digests are missing
#
# The package installs files and the CLI only. It deliberately does NOT run
# the wizard from a maintainer script: interactive prompts inside dpkg are
# unreliable. Users run `sudo sentinelcore install` afterwards.
set -euo pipefail

VERSION="${1:?usage: build-deb.sh <version> [outdir]}"
OUTDIR="${2:-dist}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+~][0-9A-Za-z.]+)?$ ]] || { echo "bad version: $VERSION" >&2; exit 2; }

IMAGES_JSON="${IMAGES_JSON:-$ROOT/packaging/images.json}"
fail_or_warn() { if [[ "${RELEASE:-0}" == "1" ]]; then echo "ERROR: $1" >&2; exit 1; else echo "WARNING: $1" >&2; fi; }

if grep -q '"digest": null' "$IMAGES_JSON"; then fail_or_warn "images.json has unpinned images (digest null)"; fi

install -d "$STAGE/DEBIAN" \
  "$STAGE/usr/bin" "$STAGE/usr/lib/sentinelcore" \
  "$STAGE/usr/share/sentinelcore/nginx" "$STAGE/usr/share/sentinelcore/suricata" \
  "$STAGE/usr/share/sentinelcore/systemd" "$STAGE/usr/share/doc/sentinelcore"

install -m 0755 "$ROOT/installer/sentinelcore" "$STAGE/usr/bin/sentinelcore"
install -m 0755 "$ROOT/installer/sentinelcore-installer" "$STAGE/usr/bin/sentinelcore-installer"
cp -r "$ROOT/installer/sentinelcore_installer" "$STAGE/usr/lib/sentinelcore/"
find "$STAGE/usr/lib/sentinelcore" -name '__pycache__' -type d -prune -exec rm -rf {} +

SHARE="$STAGE/usr/share/sentinelcore"
install -m 0644 "$ROOT/packaging/docker-compose.release.yml" "$SHARE/"
install -m 0644 "$ROOT/packaging/nginx/nginx.release.conf" "$SHARE/nginx/"
install -m 0644 "$ROOT/docker/suricata/suricata.yaml" "$SHARE/suricata/"
install -m 0644 "$ROOT/packaging/systemd/sentinelcore.service" "$SHARE/systemd/"
install -m 0644 "$ROOT/packaging/release.env.template" "$SHARE/"
install -m 0644 "$ROOT/packaging/EULA.txt" "$SHARE/"
install -m 0644 "$IMAGES_JSON" "$SHARE/images.json"
printf '%s\n' "$VERSION" > "$SHARE/VERSION"
install -m 0644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/sentinelcore/copyright"

if [[ -n "${RELEASE_KEY:-}" && -f "$RELEASE_KEY" ]]; then
  install -m 0644 "$RELEASE_KEY" "$SHARE/release-key.asc"
else
  fail_or_warn "no RELEASE_KEY given; shipping a placeholder (updates cannot be verified)"
  printf 'PLACEHOLDER - replace with the release public key\n' > "$SHARE/release-key.asc"
fi

cat > "$STAGE/DEBIAN/control" <<EOF
Package: sentinelcore
Version: $VERSION
Section: net
Priority: optional
Architecture: all
Maintainer: SentinelCore Team <noreply@invalid>
Depends: python3 (>= 3.10), openssl, iproute2, gnupg, ca-certificates
Recommends: whiptail, docker-ce | docker.io, docker-compose-plugin | docker-compose-v2
Homepage: https://github.com/dhruvpatel2440/sentinelcore-releases
Description: SentinelCore network detection and incident response platform
 Installer and management CLI for SentinelCore. After installing this package
 run "sudo sentinelcore install" to start the guided setup. Container images
 are pulled (and digest-verified) during that step.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  echo "SentinelCore files installed. Next step:  sudo sentinelcore install"
fi
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

mkdir -p "$OUTDIR"
OUT="$OUTDIR/sentinelcore_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT"
echo "built $OUT"
command -v lintian >/dev/null && lintian "$OUT" || echo "(lintian not installed: skipped)"
