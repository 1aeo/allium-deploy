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
# Exercise the script default, not a value inherited from the caller.
unset PAGES_BULK_PURGE_ENABLED

# shellcheck source=../scripts/allium-deploy-update.sh
source "$ROOT_DIR/scripts/allium-deploy-update.sh"

purge_output=$(purge_cdn)

[[ "$(wc -l < "$MOCK_CALLS" | tr -d ' ')" == "3" ]] \
    || fail "expected search, metrics, and one HTML purge request"
[[ "$purge_output" == *"Found 2 HTML files to purge"* ]] \
    || fail "default run did not enumerate the generated HTML pages"
grep -F 'https://metrics.1aeo.com/example/' "$MOCK_CALLS" >/dev/null \
    || fail "default run skipped the bulk HTML purge"
if grep -vF 'https://1aeo-metrics.pages.dev/_purge' "$MOCK_CALLS" >/dev/null; then
    fail "a purge request did not use the direct Pages endpoint"
fi
grep -F 'https://metrics.1aeo.com/search-index.json' "$MOCK_CALLS" >/dev/null \
    || fail "search index did not use an absolute production cache key"
grep -F 'https://metrics.1aeo.com/metrics' "$MOCK_CALLS" >/dev/null \
    || fail "Prometheus metrics did not use an absolute production cache key"
grep -F 'https://metrics.1aeo.com/' "$MOCK_CALLS" >/dev/null \
    || fail "HTML batch did not contain absolute production cache keys"
pass "default Pages rollback purge bypasses the Worker route and purges every generated HTML page"

: > "$MOCK_CALLS"
PAGES_ROLLBACK_MAINTENANCE_ENABLED=true
PAGES_BULK_PURGE_ENABLED=false
purge_output=$(maintain_pages_rollback_cache)
[[ "$(wc -l < "$MOCK_CALLS" | tr -d ' ')" == "3" ]] \
    || fail "disabled bulk purge did not send exactly the search, metrics, and root requests"
if grep -vF 'https://1aeo-metrics.pages.dev/_purge' "$MOCK_CALLS" >/dev/null; then
    fail "a fixed purge request did not use the direct Pages endpoint"
fi
grep -F 'https://metrics.1aeo.com/search-index.json' "$MOCK_CALLS" >/dev/null \
    || fail "disabled bulk purge skipped the search index"
grep -F 'https://metrics.1aeo.com/metrics' "$MOCK_CALLS" >/dev/null \
    || fail "disabled bulk purge skipped Prometheus metrics"
grep -F '{"urls":["https://metrics.1aeo.com/"]}' "$MOCK_CALLS" >/dev/null \
    || fail "disabled bulk purge did not purge exactly the root page"
if grep -F 'https://metrics.1aeo.com/example/' "$MOCK_CALLS" >/dev/null; then
    fail "disabled bulk purge still purged generated HTML pages"
fi
[[ "$(grep -c 'PAGES_BULK_PURGE_ENABLED=false' <<< "$purge_output")" == "1" ]] \
    || fail "disabled bulk purge did not log one clear skip line"
pass "disabled bulk purge keeps only the fixed root, search-index, and metrics purges"

MOCK_CFPAGES_CALLS="$TMP_DIR/cfpages-calls"
MOCK_DEPLOY_DIR="$TMP_DIR/deploy"
mkdir -p "$MOCK_DEPLOY_DIR/scripts" "$MOCK_DEPLOY_DIR/logs"
# The quoted lines are the literal body of the generated mock executable.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'echo deploy >> "$MOCK_CFPAGES_CALLS"' \
    > "$MOCK_DEPLOY_DIR/scripts/allium-deploy-cfpages.sh"
chmod 0755 "$MOCK_DEPLOY_DIR/scripts/allium-deploy-cfpages.sh"
export MOCK_CFPAGES_CALLS
DEPLOY_DIR="$MOCK_DEPLOY_DIR"
require_current_deploy_checkout() { return 0; }
deploy_pages_for_schema_change >/dev/null
[[ "$(cat "$MOCK_CFPAGES_CALLS")" == "deploy" ]] \
    || fail "disabled bulk purge blocked the schema-triggered Pages deploy"
pass "disabled bulk purge leaves the schema-triggered search.js deploy running"

: > "$MOCK_CALLS"
: > "$MOCK_CFPAGES_CALLS"
PAGES_ROLLBACK_MAINTENANCE_ENABLED=false
for bulk_setting in true false; do
    PAGES_BULK_PURGE_ENABLED="$bulk_setting"
    purge_output=$(maintain_pages_rollback_cache)
    [[ ! -s "$MOCK_CALLS" ]] \
        || fail "disabled Pages rollback maintenance still invoked purge requests (bulk=$bulk_setting)"
    [[ "$purge_output" == *"Pages rollback maintenance disabled; skipping Pages purge"* ]] \
        || fail "disabled Pages rollback maintenance changed its skip message (bulk=$bulk_setting)"
    deploy_pages_for_schema_change >/dev/null
    [[ ! -s "$MOCK_CFPAGES_CALLS" ]] \
        || fail "disabled Pages rollback maintenance still deployed Pages (bulk=$bulk_setting)"
done
pass "disabled Pages rollback maintenance makes no purge requests or Pages deploys"

set +e
assert_boolean_setting PAGES_BULK_PURGE_ENABLED yes >/dev/null
status=$?
set -e
[[ "$status" -eq 2 ]] || fail "invalid Pages bulk purge boolean returned $status instead of 2"

# Run a copy so a deployed config.env in this checkout can never be read.
FAIL_CLOSED_DIR="$TMP_DIR/fail-closed"
mkdir -p "$FAIL_CLOSED_DIR/scripts"
cp "$ROOT_DIR/scripts/allium-deploy-update.sh" \
    "$ROOT_DIR/scripts/allium-deploy-lib.sh" \
    "$ROOT_DIR/scripts/allium-deploy-maintain-logs.sh" \
    "$FAIL_CLOSED_DIR/scripts/"
printf '%s\n' \
    'PAGES_ROLLBACK_MAINTENANCE_ENABLED=true' \
    'PAGES_BULK_PURGE_ENABLED=yes' \
    > "$FAIL_CLOSED_DIR/config.env"
: > "$MOCK_CALLS"
set +e
fail_closed_output=$(ALLIUM_DEPLOY_TEST_MODE=0 "$BASH" "$FAIL_CLOSED_DIR/scripts/allium-deploy-update.sh" 2>&1)
status=$?
set -e
[[ "$status" -eq 2 ]] || fail "invalid Pages bulk purge setting let the update run (exit $status)"
[[ "$fail_closed_output" == *"invalid PAGES_BULK_PURGE_ENABLED=yes; expected true or false"* ]] \
    || fail "invalid Pages bulk purge setting was not reported"
[[ "$fail_closed_output" != *"Starting metrics update"* ]] \
    || fail "invalid Pages bulk purge setting started a metrics update"
[[ ! -s "$MOCK_CALLS" ]] || fail "invalid Pages bulk purge setting sent purge requests"
pass "invalid Pages bulk purge setting stops the update before any work"
