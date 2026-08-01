#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

MOCK_BIN="$TMP_DIR/mock-bin"
MOCK_CALLS="$TMP_DIR/curl-calls"
OUTPUT_DIR="$TMP_DIR/output"
mkdir -p "$MOCK_BIN" "$OUTPUT_DIR/example"
printf '<html>root</html>\n' > "$OUTPUT_DIR/index.html"
printf '<html>example</html>\n' > "$OUTPUT_DIR/example/index.html"

# The quoted lines are the literal body of the generated mock executable.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\\t" "$@" >> "$MOCK_CURL_CALLS"' \
    'printf "\\n" >> "$MOCK_CURL_CALLS"' \
    'if [[ " $* " == *" -w "* ]]; then' \
    '    printf "{\\"success\\":true,\\"purged\\":1}\\n200"' \
    'else' \
    '    printf "{\\"success\\":true,\\"purged\\":2}"' \
    'fi' \
    > "$MOCK_BIN/curl"
chmod 0755 "$MOCK_BIN/curl"

export ALLIUM_DEPLOY_TEST_MODE=1
export CF_ASSETS_ENABLED=true
export CF_ASSETS_REQUIRED=true
export CF_ASSETS_ALLOW_PROMOTION=true
export SITE_URL='https://metrics.1aeo.com'
export PAGES_PURGE_URL='https://1aeo-metrics.pages.dev'
export PURGE_SECRET='test-purge-secret'
export OUTPUT_DIR
export MOCK_CURL_CALLS="$MOCK_CALLS"
export PATH="$MOCK_BIN:$PATH"

# shellcheck source=../scripts/allium-deploy-update.sh
source "$ROOT_DIR/scripts/allium-deploy-update.sh"

purge_cdn >/dev/null

[[ "$(wc -l < "$MOCK_CALLS" | tr -d ' ')" == "3" ]] \
    || fail "expected search, metrics, and one HTML purge request"
if grep -vF 'https://1aeo-metrics.pages.dev/_purge' "$MOCK_CALLS" >/dev/null; then
    fail "a purge request did not use the direct Pages endpoint"
fi
grep -F 'https://metrics.1aeo.com/search-index.json' "$MOCK_CALLS" >/dev/null \
    || fail "search index did not use an absolute production cache key"
grep -F 'https://metrics.1aeo.com/metrics' "$MOCK_CALLS" >/dev/null \
    || fail "Prometheus metrics did not use an absolute production cache key"
grep -F 'https://metrics.1aeo.com/' "$MOCK_CALLS" >/dev/null \
    || fail "HTML batch did not contain absolute production cache keys"
pass "Pages rollback purge bypasses the Worker route and deletes production-host cache keys"

: > "$MOCK_CALLS"
# shellcheck disable=SC2034
PAGES_ROLLBACK_MAINTENANCE_ENABLED=false
maintain_pages_rollback_cache >/dev/null
[[ ! -s "$MOCK_CALLS" ]] || fail "disabled Pages rollback maintenance still invoked purge requests"
pass "disabled Pages rollback maintenance makes no purge requests"
