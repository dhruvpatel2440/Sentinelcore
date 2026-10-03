#!/bin/sh
# SentinelCore one-line installer.
#
#   curl -fsSL https://<releases-host>/install.sh | sudo sh
#
# Downloads the .deb, verifies checksum AND signature, installs it, then
# launches `sentinelcore install` (the guided wizard).
#
# Trust model: this script is fetched over HTTPS. The release key fingerprint
# below is baked in at release time; the key itself is fetched and must match
# it, so a swapped key is rejected. To verify this script too, download it,
# check install.sh.asc against the key published on the website, then run it.
set -eu

BASE_URL="${SENTINELCORE_BASE_URL:-https://github.com/dhruvpatel2440/sentinelcore-releases/releases/latest/download}"
KEY_FPR="__RELEASE_KEY_FINGERPRINT__"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: curl -fsSL <url> | sudo sh"
case "$KEY_FPR" in
  __RELEASE*|"") die "this script has no release key fingerprint baked in (unreleased build); refusing to continue" ;;
esac
[ -r /etc/os-release ] || die "cannot detect the operating system"
command -v apt-get >/dev/null 2>&1 || die "this installer needs apt (Ubuntu/Debian). See docs for other distributions."
for tool in gpg sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { say "installing missing tool: $tool"; apt-get update -qq && apt-get install -y -qq gnupg coreutils; }
done

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q --https-only -O "$2" "$1"; }
else
  apt-get update -qq && apt-get install -y -qq curl ca-certificates
  fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
fi

TMP="$(mktemp -d)"
GNUPGHOME="$TMP/gnupg"; export GNUPGHOME
mkdir -m 0700 "$GNUPGHOME"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "Downloading release metadata ..."
fetch "$BASE_URL/release-key.asc"    "$TMP/release-key.asc"
fetch "$BASE_URL/SHA256SUMS"         "$TMP/SHA256SUMS"
fetch "$BASE_URL/SHA256SUMS.asc"     "$TMP/SHA256SUMS.asc"

GOT_FPR="$(gpg --batch --with-colons --show-keys "$TMP/release-key.asc" | awk -F: '$1=="fpr"{print $10; exit}')"
[ "$GOT_FPR" = "$KEY_FPR" ] || die "release key fingerprint mismatch (got '$GOT_FPR'); aborting"
gpg --batch --quiet --import "$TMP/release-key.asc"
gpg --batch --status-fd 1 --verify "$TMP/SHA256SUMS.asc" "$TMP/SHA256SUMS" 2>/dev/null | grep -q '^\[GNUPG:\] VALIDSIG' \
  || die "signature on SHA256SUMS is INVALID; aborting"
say "Signature OK."

DEB_NAME="$(awk '{print $2}' "$TMP/SHA256SUMS" | grep -E '^sentinelcore_[0-9A-Za-z.+~-]+_all\.deb$' | head -n 1)"
[ -n "$DEB_NAME" ] || die "no .deb listed in SHA256SUMS"
say "Downloading $DEB_NAME ..."
fetch "$BASE_URL/$DEB_NAME" "$TMP/$DEB_NAME"
( cd "$TMP" && grep " $DEB_NAME\$" SHA256SUMS | sha256sum -c - ) || die "checksum mismatch for $DEB_NAME; aborting"

say "Installing the package ..."
apt-get install -y "$TMP/$DEB_NAME"

say "Starting the setup wizard ..."
# When piped from curl, stdin is the script; give the wizard the real terminal.
if [ -r /dev/tty ]; then
  exec sentinelcore install "$@" </dev/tty
fi
exec sentinelcore install "$@"
