#!/usr/bin/env bash
# Build the downloadable installer package (what the website's Download button serves).
#
#   scripts/release/build-installer-package.sh <version> <images.json> [outdir]
#
# Env (set by the release workflow):
#   KEY_FPR          fingerprint of the release key (baked into install.sh)
#   RELEASE_KEY      public key file to ship
#   GPG_KEY          key id used to sign checksums/SHA256SUMS
#   GPG_PASS_FILE    optional passphrase file for non-interactive signing
#
# The package contains no application source and no secrets: the application is
# inside the digest-pinned container images listed in images.json.
set -euo pipefail

VERSION="${1:?usage: build-installer-package.sh <version> <images.json> [outdir]}"
IMAGES_JSON="${2:?path to a released images.json}"
OUTDIR="${3:-dist}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAME="sentinelcore-installer-$VERSION"
: "${KEY_FPR:?KEY_FPR is required}"
: "${RELEASE_KEY:?RELEASE_KEY is required}"
: "${GPG_KEY:?GPG_KEY is required}"

# A package built from placeholder images must never be published.
if grep -Eq '"digest": *null|OWNER|:0\.0\.0' "$IMAGES_JSON"; then
  echo "ERROR: $IMAGES_JSON is not a real release manifest (null digests/placeholders)" >&2
  exit 1
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
P="$WORK/$NAME"
mkdir -p "$P/installer" "$P/packaging/nginx" "$P/packaging/systemd" "$P/packaging/suricata" "$P/checksums" "$P/signatures" "$OUTDIR"

sed "s|__RELEASE_KEY_FINGERPRINT__|$KEY_FPR|" "$ROOT/packaging/package-install.sh" > "$P/install.sh"
chmod 0755 "$P/install.sh"
install -m 0755 "$ROOT/installer/sentinelcore" "$ROOT/installer/sentinelcore-installer" "$P/installer/"
cp -r "$ROOT/installer/sentinelcore_installer" "$P/installer/"
find "$P" -name '__pycache__' -type d -prune -exec rm -rf {} +
install -m 0644 "$ROOT/packaging/docker-compose.release.yml" "$ROOT/packaging/release.env.template" "$ROOT/packaging/EULA.txt" "$P/packaging/"
install -m 0644 "$ROOT/packaging/nginx/nginx.release.conf" "$P/packaging/nginx/"
install -m 0644 "$ROOT/packaging/systemd/sentinelcore.service" "$P/packaging/systemd/"
install -m 0644 "$ROOT/docker/suricata/suricata.yaml" "$P/packaging/suricata/"
install -m 0644 "$RELEASE_KEY" "$P/packaging/release-key.asc"
install -m 0644 "$IMAGES_JSON" "$P/images.json"
install -m 0644 "$ROOT/LICENSE" "$P/LICENSE"
printf '%s\n' "$VERSION" > "$P/VERSION"
cat > "$P/README.md" <<EOF
# SentinelCore $VERSION installer

    sudo ./install.sh

Verifies the package signature, installs the \`sentinelcore\` command, then runs the
guided setup wizard. Requires Ubuntu/Debian, Docker (the wizard can install it), 4 GB RAM,
10 GB disk and internet access to pull the signed container images listed in images.json.
EOF

# no secret-looking files may ever be in the package
if find "$P" \( -name '.env' -o -name '*.pem' -o -name 'id_rsa*' -o -name '*private*' \) | grep -q .; then
  echo "ERROR: sensitive file in package" >&2; exit 1
fi

( cd "$P" && find . -type f ! -path './checksums/*' ! -path './signatures/*' -printf '%P\n' | sort | xargs sha256sum > checksums/SHA256SUMS )
pin=()
[[ -n "${GPG_PASS_FILE:-}" ]] && pin=(--pinentry-mode loopback --passphrase-file "$GPG_PASS_FILE")
gpg --batch --yes "${pin[@]}" --armor --detach-sign --local-user "$GPG_KEY" -o "$P/signatures/SHA256SUMS.asc" "$P/checksums/SHA256SUMS"

tar -C "$WORK" --owner=0 --group=0 -czf "$OUTDIR/$NAME.tar.gz" "$NAME"
echo "built $OUTDIR/$NAME.tar.gz"
