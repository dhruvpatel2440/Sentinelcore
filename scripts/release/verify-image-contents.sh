#!/usr/bin/env bash
# Fail if a release image contains anything that must not ship.
#   scripts/release/verify-image-contents.sh <image-ref>
set -euo pipefail
IMAGE="${1:?usage: verify-image-contents.sh <image>}"

cid="$(docker create "$IMAGE")"
listing="$(mktemp)"
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true; rm -f "$listing"' EXIT
docker export "$cid" | tar -t > "$listing"

bad=0
check() {  # description, extended regex
  if grep -E "$2" "$listing" | head -n 5 | grep -q .; then
    echo "FOUND ($1):"
    grep -E "$2" "$listing" | head -n 5
    bad=1
  fi
}
check "git metadata"         '(^|/)\.git(/|$)'
check "environment files"    '(^|/)\.env($|\.[A-Za-z]+$)'
check "backend tests"        '^app/tests?(/|$)'
check "helper tests"         '^opt/helper/(tests?|pytest\.ini)'
check "sourcemaps"           '^usr/share/nginx/html/.*\.map$'
check "frontend source"      '^(app|usr/share/nginx/html)/(src|node_modules)(/|$)'
check "project prompt/notes" '(^|/)(CLAUDE\.md|sentinelcore prompt|.*RUN-ORDER.*)'
check "private keys"         '(^|/)(id_rsa|id_ed25519)$'

echo "--- docker history: ENV/ARG lines that look like secrets ---"
if docker history --no-trunc --format '{{.CreatedBy}}' "$IMAGE" \
     | grep -Ei '(password|secret|api[_-]?key|token)=[^ ]{6,}'; then
  echo "FOUND: secret-looking value in image history"
  bad=1
fi

if [[ $bad -ne 0 ]]; then
  echo "FAIL: $IMAGE"
  exit 1
fi
echo "OK: $IMAGE"
