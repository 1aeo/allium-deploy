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

SOURCE_DIR="$TMP_DIR/output"
MOCK_BIN="$TMP_DIR/mock-bin"
CURL_COUNT="$TMP_DIR/curl-count"
FINGERPRINT='DB1629B59707F744A0C7933E56B6802786FFC317'
mkdir -p "$SOURCE_DIR/nested" "$MOCK_BIN"
printf '<html>root</html>\n' > "$SOURCE_DIR/index.html"
printf '<html>nested route</html>\n' > "$SOURCE_DIR/nested/index.html"
printf 'largest representative asset body\n' > "$SOURCE_DIR/large.txt"
printf '{"meta":{"version":"1.6"},"relays":[{"f":"%s"}]}\n' "$FINGERPRINT" \
    > "$SOURCE_DIR/search-index.json"

# This curl fixture fails at the transport layer before HTTP on the first call,
# then emulates a healthy immutable preview for all representative checks.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'count=$(cat "$MOCK_CURL_COUNT" 2>/dev/null || printf 0)' \
    'count=$((count + 1))' \
    'printf "%s\n" "$count" > "$MOCK_CURL_COUNT"' \
    'if [[ "$MOCK_CURL_MODE" == always-fail || ( "$MOCK_CURL_MODE" == fail-once && "$count" == 1 ) ]]; then' \
    '  echo "curl: simulated connection reset" >&2' \
    '  exit 7' \
    'fi' \
    'output=/dev/null' \
    'headers=' \
    'url=' \
    'while (( $# )); do' \
    '  case "$1" in' \
    '    --output) output="$2"; shift 2 ;;' \
    '    --dump-header) headers="$2"; shift 2 ;;' \
    '    --max-time|--write-out) shift 2 ;;' \
    '    --silent|--show-error) shift ;;' \
    '    http*) url="$1"; shift ;;' \
    '    *) shift ;;' \
    '  esac' \
    'done' \
    'path="/${url#*://*/}"' \
    '[[ "$url" =~ ^https://[^/]+/$ ]] && path=/' \
    'status=200' \
    'case "$path" in' \
    '  /) [[ "$output" != /dev/null ]] && cp "$MOCK_SOURCE_DIR/index.html" "$output" ;;' \
    '  /search-index.json) cp "$MOCK_SOURCE_DIR/search-index.json" "$output" ;;' \
    '  /nested/) cp "$MOCK_SOURCE_DIR/nested/index.html" "$output" ;;' \
    '  /large.txt) cp "$MOCK_SOURCE_DIR/large.txt" "$output" ;;' \
    '  /nested) status=307 ;;' \
    '  /__allium_cfassets_missing_probe__) status=404; : > "$output" ;;' \
    '  /search\?q=*) status=302 ;;' \
    '  *) echo "unexpected fixture URL: $url ($path)" >&2; exit 90 ;;' \
    'esac' \
    'if [[ -n "$headers" ]]; then' \
    '  if [[ "$path" == / ]]; then' \
    '    printf "HTTP/1.1 200 OK\r\ncache-control: public, max-age=0, must-revalidate\r\nx-robots-tag: noindex, nofollow\r\n\r\n" > "$headers"' \
    '  else' \
    '    printf "HTTP/1.1 302 Found\r\nlocation: /relay/%s/\r\n\r\n" "$MOCK_FINGERPRINT" > "$headers"' \
    '  fi' \
    'fi' \
    'printf "%s" "$status"' \
    > "$MOCK_BIN/curl"
chmod 0755 "$MOCK_BIN/curl"

: > "$CURL_COUNT"
output=$(PATH="$MOCK_BIN:$PATH" \
    MOCK_CURL_MODE=fail-once \
    MOCK_CURL_COUNT="$CURL_COUNT" \
    MOCK_SOURCE_DIR="$SOURCE_DIR" \
    MOCK_FINGERPRINT="$FINGERPRINT" \
    CF_ASSETS_VERIFY_ATTEMPTS=3 \
    CF_ASSETS_VERIFY_MAX_ATTEMPTS=4 \
    CF_ASSETS_VERIFY_RETRY_DELAY=0 \
    "$REPO_DIR/scripts/allium-deploy-verify-cfassets.sh" \
        https://12345678-allium-shadow-test.test.workers.dev "$SOURCE_DIR")
[[ "$output" == *'attempt 1 did not pass'* ]] || fail "transport failure did not enter the bounded retry loop"
[[ "$output" == *'all checks passed 3 consecutive times'* ]] || fail "verifier did not recover after the transport failure"
pass "network-level curl failures are retried inside the bounded health gate"

: > "$CURL_COUNT"
set +e
PATH="$MOCK_BIN:$PATH" \
MOCK_CURL_MODE=always-fail \
MOCK_CURL_COUNT="$CURL_COUNT" \
MOCK_SOURCE_DIR="$SOURCE_DIR" \
MOCK_FINGERPRINT="$FINGERPRINT" \
CF_ASSETS_VERIFY_ATTEMPTS=2 \
CF_ASSETS_VERIFY_MAX_ATTEMPTS=3 \
CF_ASSETS_VERIFY_RETRY_DELAY=0 \
    "$REPO_DIR/scripts/allium-deploy-verify-cfassets.sh" \
        https://12345678-allium-shadow-test.test.workers.dev "$SOURCE_DIR" >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 1 ]] || fail "exhausted network retries returned $status instead of 1"
[[ "$(cat "$CURL_COUNT")" == 3 ]] || fail "verifier exceeded or did not reach its configured attempt bound"
pass "exhausted network retries fail closed before promotion"
