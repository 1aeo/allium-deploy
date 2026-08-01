#!/usr/bin/env bash

set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

OUTPUT_DIR="$TMP_DIR/output"
MOCK_BIN="$TMP_DIR/mock-bin"
MOCK_COUNT="$TMP_DIR/wrangler-count"
MOCK_VERIFY_CALLS="$TMP_DIR/verify-calls"
VERSION_ID='12345678-1234-4234-8234-123456789abc'
VERSION_PREVIEW='https://12345678-allium-shadow-test.test.workers.dev'
ALIAS_PREVIEW='https://allium-test-allium-shadow-test.test.workers.dev'
mkdir -p "$OUTPUT_DIR/nested" "$MOCK_BIN"
printf '<html>root</html>\n' > "$OUTPUT_DIR/index.html"
printf '<html>nested</html>\n' > "$OUTPUT_DIR/nested/index.html"
printf '{"meta":{"version":"1.6"},"relays":[]}\n' > "$OUTPUT_DIR/search-index.json"

# The quoted lines are the literal bodies of generated test executables.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'count=$(cat "$MOCK_COUNT_FILE" 2>/dev/null || printf 0)' \
    'count=$((count + 1))' \
    'printf "%s\n" "$count" > "$MOCK_COUNT_FILE"' \
    'case "$MOCK_UPLOAD_MODE" in' \
    '  transient-once)' \
    '    if (( count == 1 )); then echo "Cloudflare API returned HTTP 522" >&2; exit 42; fi' \
    '    ;;' \
    '  permanent)' \
    '    echo "Authentication error" >&2' \
    '    exit 43' \
    '    ;;' \
    '  malformed)' \
    '    echo "Uploaded without structured response"' \
    '    exit 0' \
    '    ;;' \
    '  success) ;;' \
    '  *) exit 99 ;;' \
    'esac' \
    'printf "Worker Version ID: %s\n" "$MOCK_VERSION_ID"' \
    'printf "Version Preview URL: %s\n" "$MOCK_VERSION_PREVIEW"' \
    'printf "Version Preview Alias URL: %s\n" "$MOCK_ALIAS_PREVIEW"' \
    'printf "{\"type\":\"version-upload\",\"version\":1,\"version_id\":\"%s\",\"preview_url\":\"%s\",\"preview_alias_url\":\"%s\"}\n" \
      "$MOCK_VERSION_ID" "$MOCK_VERSION_PREVIEW" "$MOCK_ALIAS_PREVIEW" >> "$WRANGLER_OUTPUT_FILE_PATH"' \
    > "$MOCK_BIN/pnpm"
chmod 0755 "$MOCK_BIN/pnpm"

printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\t%s\n" "$1" "$2" >> "$MOCK_VERIFY_CALLS"' \
    > "$MOCK_BIN/verify"
chmod 0755 "$MOCK_BIN/verify"

# Keep the test portable on macOS, where BSD du does not implement -b.
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf "4096\t%s\n" "${@: -1}"' \
    > "$MOCK_BIN/du"
chmod 0755 "$MOCK_BIN/du"

run_upload() {
    local mode="$1"
    local case_dir="$2"
    mkdir -p "$case_dir"
    : > "$MOCK_COUNT"
    : > "$MOCK_VERIFY_CALLS"
    PATH="$MOCK_BIN:$PATH" \
    MOCK_UPLOAD_MODE="$mode" \
    MOCK_COUNT_FILE="$MOCK_COUNT" \
    MOCK_VERIFY_CALLS="$MOCK_VERIFY_CALLS" \
    MOCK_VERSION_ID="$VERSION_ID" \
    MOCK_VERSION_PREVIEW="$VERSION_PREVIEW" \
    MOCK_ALIAS_PREVIEW="$ALIAS_PREVIEW" \
    CLOUDFLARE_API_TOKEN=test-token \
    CF_ASSETS_ENABLED=true \
    CF_ASSETS_REQUIRE_FRESH_CHECKOUT=false \
    CF_ASSETS_WORKER_NAME=allium-shadow-test \
    CF_ASSETS_PREVIEW_ALIAS=allium-test \
    CF_ASSETS_CONFIG="$case_dir/wrangler.assets.toml" \
    CF_ASSETS_VERIFY_SCRIPT="$MOCK_BIN/verify" \
    CF_ASSETS_CONSECUTIVE_FILE="$case_dir/consecutive" \
    CF_ASSETS_LAST_VERSION_FILE="$case_dir/last-version" \
    CF_ASSETS_SUMMARY_FILE="$case_dir/summary.tsv" \
    CF_ASSETS_UPLOAD_MAX_ATTEMPTS=3 \
    CF_ASSETS_UPLOAD_RETRY_DELAY=0 \
    WRANGLER_LOG=error \
    WRANGLER_LOG_PATH="$case_dir/wrangler-error.log" \
    OUTPUT_DIR="$OUTPUT_DIR" \
        "$REPO_DIR/scripts/allium-deploy-cfassets.sh" --upload-only
}

run_upload success "$TMP_DIR/success" >/dev/null
[[ "$(cat "$MOCK_COUNT")" == 1 ]] || fail "successful upload was not attempted exactly once"
[[ "$(cat "$MOCK_VERIFY_CALLS")" == "$VERSION_PREVIEW"$'\t'"$OUTPUT_DIR" ]] \
    || fail "verification did not use the immutable version preview URL"
[[ "$(cat "$TMP_DIR/success/last-version")" == "$VERSION_ID" ]] \
    || fail "structured version ID was not recorded"
[[ "$(tail -n 1 "$TMP_DIR/success/summary.tsv")" == *$'\t'"$VERSION_PREVIEW"$'\t1' ]] \
    || fail "summary did not retain the immutable version preview URL"
pass "successful uploads verify structured immutable version metadata"

run_upload transient-once "$TMP_DIR/transient" >/dev/null
[[ "$(cat "$MOCK_COUNT")" == 2 ]] || fail "transient 522 was not retried exactly once"
[[ "$(wc -l < "$MOCK_VERIFY_CALLS" | tr -d ' ')" == 1 ]] \
    || fail "transient recovery did not invoke verification exactly once"
pass "transient Cloudflare upload failures retry and recover"

set +e
run_upload permanent "$TMP_DIR/permanent" >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 43 ]] || fail "permanent upload failure returned $status instead of 43"
[[ "$(cat "$MOCK_COUNT")" == 1 ]] || fail "permanent upload failure was retried"
[[ ! -s "$MOCK_VERIFY_CALLS" ]] || fail "permanent upload failure invoked verification"
[[ ! -f "$TMP_DIR/permanent/last-version" ]] || fail "permanent failure recorded a promotable version"
pass "non-transient upload failures fail closed without retry or verification"

set +e
run_upload malformed "$TMP_DIR/malformed" >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 1 ]] || fail "malformed upload metadata returned $status instead of 1"
[[ "$(cat "$MOCK_COUNT")" == 3 ]] || fail "malformed upload metadata did not exhaust the bounded retries"
[[ ! -s "$MOCK_VERIFY_CALLS" ]] || fail "malformed upload metadata invoked verification"
[[ ! -f "$TMP_DIR/malformed/last-version" ]] || fail "malformed metadata recorded a promotable version"
pass "malformed structured responses exhaust bounded retries and fail closed"
