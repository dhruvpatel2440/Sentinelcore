#!/usr/bin/env bash
# Build the offline bundle: signed image archives + installer, for machines
# without internet access.
#
#   packaging/build-offline-bundle.sh <version> <deb> <images.json> [outdir]
#
# Requires every image in images.json to be present locally (docker pull first).
# Env: GPG_KEY (key id to sign SHA256SUMS with), GPG_PASS_FILE (optional passphrase
# file for non-interactive signing), RELEASE_KEY (public key file).
set -euo pipefail

VERSION="${1:?usage: build-offline-bundle.sh <version> <deb> <images.json> [outdir]}"
DEB="${2:?path to the .deb}"
IMAGES_JSON="${3:?path to images.json}"
OUTDIR="${4:-dist}"
NAME="sentinelcore-offline-$VERSION"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
B="$WORK/$NAME"
mkdir -p "$B/images" "$OUTDIR"

cp "$DEB" "$B/"
cp "$IMAGES_JSON" "$B/images.json"
[[ -n "${RELEASE_KEY:-}" && -f "${RELEASE_KEY:-}" ]] && cp "$RELEASE_KEY" "$B/release-key.asc"

# images.json -> "VAR ref" lines (python3 is a build-time dependency only)
python3 - "$IMAGES_JSON" > "$WORK/refs.txt" <<'PY'
import json, sys
for var, spec in json.load(open(sys.argv[1]))["images"].items():
    print(var, spec["ref"])
PY

while read -r var ref; do
  echo "saving $ref"
  docker image inspect "$ref" >/dev/null
  docker save -o "$B/images/${var}.tar" "$ref"
done < "$WORK/refs.txt"

cat > "$B/install-offline.sh" <<'EOS'
#!/bin/sh
# Offline install: verify, install the package, run the wizard with local images.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo ./install-offline.sh" >&2; exit 1; }
cd "$HERE"
sha256sum -c SHA256SUMS
if [ -f SHA256SUMS.asc ] && [ -f release-key.asc ]; then
  GNUPGHOME="$(mktemp -d)"; export GNUPGHOME
  gpg --batch --quiet --import release-key.asc
  gpg --batch --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2>/dev/null | grep -q '^\[GNUPG:\] VALIDSIG' \
    || { echo "signature INVALID" >&2; exit 1; }
else
  echo "no signature in this bundle; refusing to continue" >&2; exit 1
fi
dpkg -i "$HERE"/sentinelcore_*_all.deb
exec sentinelcore install --offline-bundle "$HERE" "$@"
EOS
chmod 0755 "$B/install-offline.sh"

# shellcheck disable=SC2094  # SHA256SUMS is excluded from the find, so it is not read while written
( cd "$B" && find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.asc -printf '%P\n' | sort | xargs sha256sum > SHA256SUMS )
if [[ -n "${GPG_KEY:-}" ]]; then
  pin=()
  [[ -n "${GPG_PASS_FILE:-}" ]] && pin=(--pinentry-mode loopback --passphrase-file "$GPG_PASS_FILE")
  gpg --batch --yes "${pin[@]}" --armor --detach-sign --local-user "$GPG_KEY" -o "$B/SHA256SUMS.asc" "$B/SHA256SUMS"
else
  echo "WARNING: GPG_KEY not set; the bundle is unsigned and the installer will refuse it." >&2
fi

tar -C "$WORK" -czf "$OUTDIR/$NAME.tar.gz" "$NAME"
echo "built $OUTDIR/$NAME.tar.gz"
