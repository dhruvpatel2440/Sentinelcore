#!/usr/bin/env bash
# Smoke test for the installer package layout. Builds a package with a throw-away
# GPG key and a syntactically valid but fake images.json, then checks the result.
#   scripts/release/test_installer_package.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export GNUPGHOME="$WORK/gnupg"; mkdir "$GNUPGHOME"; chmod 0700 "$GNUPGHOME" 2>/dev/null || true  # chmod can be refused on Windows drives

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

# --- throw-away signing key (never leaves this directory) -------------------
cat > "$WORK/keyparams" <<'EOF'
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: SentinelCore Test
Name-Email: test@example.invalid
Expire-Date: 1d
%commit
EOF
gpg --batch --quiet --gen-key "$WORK/keyparams" 2>/dev/null
FPR="$(gpg --batch --with-colons --list-keys | awk -F: '$1=="fpr"{print $10; exit}')"
gpg --batch --armor --export "$FPR" > "$WORK/key.asc"

# --- fake but non-placeholder manifest -------------------------------------
"${PYTHON:-python3}" - "$WORK/images.json" <<'PY'
import json, sys
names = {"DB_IMAGE": "postgres:16-alpine", "REDIS_IMAGE": "redis:7.4-alpine", "NGINX_IMAGE": "nginx:1.27-alpine",
         "BACKEND_IMAGE": "ghcr.io/example/sentinelcore-backend:0.0.1-test",
         "HELPER_IMAGE": "ghcr.io/example/sentinelcore-helper:0.0.1-test",
         "FRONTEND_IMAGE": "ghcr.io/example/sentinelcore-frontend:0.0.1-test"}
json.dump({"version": "0.0.1-test",
           "images": {k: {"ref": v, "digest": "sha256:" + format(i + 1, "x") * 64} for i, (k, v) in enumerate(names.items())}},
          open(sys.argv[1], "w"), indent=2)
PY

# --- 1. builder rejects the checked-in placeholder manifest -----------------
if KEY_FPR="$FPR" RELEASE_KEY="$WORK/key.asc" GPG_KEY="$FPR" \
     "$ROOT/scripts/release/build-installer-package.sh" 0.0.1-test "$ROOT/packaging/images.json" "$WORK/bad" >/dev/null 2>&1; then
  fail "builder accepted the placeholder packaging/images.json"
fi
ok "builder rejects placeholder images.json"

# --- 2. build a package from the fake-but-valid manifest ---------------------
KEY_FPR="$FPR" RELEASE_KEY="$WORK/key.asc" GPG_KEY="$FPR" \
  "$ROOT/scripts/release/build-installer-package.sh" 0.0.1-test "$WORK/images.json" "$WORK/out" >/dev/null
TARBALL="$WORK/out/sentinelcore-installer-0.0.1-test.tar.gz"
[[ -f "$TARBALL" ]] || fail "package tarball not produced"
tar -xzf "$TARBALL" -C "$WORK"
P="$WORK/sentinelcore-installer-0.0.1-test"

[[ -x "$P/install.sh" ]] || fail "top-level install.sh missing or not executable"
if grep -q '__RELEASE_KEY_FINGERPRINT__' "$P/install.sh"; then fail "install.sh still has the fingerprint placeholder"; fi
grep -q "$FPR" "$P/install.sh" || fail "fingerprint not substituted into install.sh"
ok "install.sh present, executable, fingerprint substituted"

[[ -f "$P/checksums/SHA256SUMS" && -f "$P/signatures/SHA256SUMS.asc" ]] || fail "checksums/signatures missing"
gpg --batch --verify "$P/signatures/SHA256SUMS.asc" "$P/checksums/SHA256SUMS" 2>/dev/null || fail "gpg --verify failed"
( cd "$P" && sha256sum -c --quiet checksums/SHA256SUMS ) || fail "sha256sum -c failed"
ok "signature and checksums verify"

for f in packaging/suricata/suricata.yaml packaging/docker-compose.release.yml packaging/nginx/nginx.release.conf \
         packaging/release-key.asc images.json VERSION README.md LICENSE installer/sentinelcore installer/sentinelcore-installer; do
  [[ -f "$P/$f" ]] || fail "missing $f"
done
ok "required files present"

# --- 3. nothing that must not ship ------------------------------------------
if find "$P" \( -name '.env' -o -name '*.pem' -o -name 'id_rsa*' -o -name '__pycache__' -o -name '*.pyc' \) | grep -q .; then
  fail "forbidden file in package"
fi
for d in backend helper frontend; do [[ ! -e "$P/$d" ]] || fail "application directory $d/ is in the package"; done
ok "no secrets, caches or application source"

# --- 4. install.sh with a placeholder fingerprint must refuse ---------------
cp "$ROOT/packaging/package-install.sh" "$WORK/placeholder-install.sh"
if bash "$WORK/placeholder-install.sh" >"$WORK/refuse.log" 2>&1; then fail "install.sh with placeholder fingerprint exited 0"; fi
grep -Eq "run as root|signing key fingerprint" "$WORK/refuse.log" || fail "unexpected refusal message: $(cat "$WORK/refuse.log")"
ok "install.sh with placeholder fingerprint refuses to run"

echo "installer package smoke test passed"
