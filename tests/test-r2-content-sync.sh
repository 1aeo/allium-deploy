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

DEPLOY_DIR="$TMP_DIR/deploy"
OUTPUT_DIR="$TMP_DIR/output"
MOCK_BIN="$TMP_DIR/mock-bin"
RCLONE_LOG="$TMP_DIR/rclone.log"
CONTENT_MARKER="$DEPLOY_DIR/logs/last-r2-content-sync-date"
TODAY_LOCAL=$(date '+%Y-%m-%d')
TODAY_UTC=$(date -u '+%Y-%m-%d')

mkdir -p "$DEPLOY_DIR/scripts" "$DEPLOY_DIR/logs" "$OUTPUT_DIR/1aeo.com" "$MOCK_BIN"
cp "$REPO_DIR/scripts/allium-deploy-upload-r2.sh" "$DEPLOY_DIR/scripts/"
cp "$REPO_DIR/scripts/allium-deploy-upload-common.sh" "$DEPLOY_DIR/scripts/"

printf '<html>root</html>\n' > "$OUTPUT_DIR/index.html"
printf '{"meta":{"version":"1.6"}}\n' > "$OUTPUT_DIR/search-index.json"
printf '<html>1aeo</html>\n' > "$OUTPUT_DIR/1aeo.com/index.html"
SOURCE_COUNT=3
SOURCE_BYTES=$(find "$OUTPUT_DIR" -type f -exec wc -c {} + | awk 'END {print $1}')

# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'command_name="${1:-}"' \
    'shift || true' \
    'printf "%s\\t%s\\n" "$command_name" "$*" >> "$MOCK_RCLONE_LOG"' \
    'case "$command_name" in' \
    '  listremotes)' \
    '    printf "r2-metrics:\\n"' \
    '    ;;' \
    '  sync)' \
    '    exit "${MOCK_SYNC_EXIT:-0}"' \
    '    ;;' \
    '  size)' \
    '    if [[ "${1:-}" == "$MOCK_SOURCE_DIR" ]]; then' \
    '      printf "{\"count\":%s,\"bytes\":%s,\"sizeless\":0}\n" "$MOCK_SOURCE_COUNT" "$MOCK_SOURCE_BYTES"' \
    '    else' \
    '      printf "{\"count\":%s,\"bytes\":%s,\"sizeless\":0}\n" "${MOCK_REMOTE_COUNT:-$MOCK_SOURCE_COUNT}" "${MOCK_REMOTE_BYTES:-$MOCK_SOURCE_BYTES}"' \
    '    fi' \
    '    ;;' \
    '  cat)' \
    '    object_path="${1#r2-metrics:test-bucket/}"' \
    '    if [[ "${MOCK_HASH_MISMATCH_PATH:-}" == "$object_path" ]]; then' \
    '      printf "mismatch\\n"' \
    '    else' \
    '      /bin/cat "$MOCK_SOURCE_DIR/$object_path"' \
    '    fi' \
    '    ;;' \
    '  *)' \
    '    printf "unexpected rclone command: %s\\n" "$command_name" >&2' \
    '    exit 64' \
    '    ;;' \
    'esac' \
    > "$MOCK_BIN/rclone"
chmod 0755 "$MOCK_BIN/rclone"

run_r2() {
    env \
        PATH="$MOCK_BIN:$PATH" \
        OUTPUT_DIR="$OUTPUT_DIR" \
        RCLONE_PATH="$MOCK_BIN/rclone" \
        R2_BUCKET=test-bucket \
        R2_ACCESS_KEY_ID=test-key \
        R2_SECRET_ACCESS_KEY=test-secret \
        CLOUDFLARE_ACCOUNT_ID=test-account \
        DAILY_LOCAL_BACKUP=true \
        DAILY_R2_BACKUP=true \
        R2_CONTENT_SYNC_INTERVAL="${R2_CONTENT_SYNC_INTERVAL:-daily}" \
        R2_CONTENT_VERIFY_PATHS="${R2_CONTENT_VERIFY_PATHS:-index.html,search-index.json,1aeo.com/index.html}" \
        MOCK_RCLONE_LOG="$RCLONE_LOG" \
        MOCK_SOURCE_DIR="$OUTPUT_DIR" \
        MOCK_SOURCE_COUNT="$SOURCE_COUNT" \
        MOCK_SOURCE_BYTES="$SOURCE_BYTES" \
        MOCK_REMOTE_COUNT="${MOCK_REMOTE_COUNT:-$SOURCE_COUNT}" \
        MOCK_REMOTE_BYTES="${MOCK_REMOTE_BYTES:-$SOURCE_BYTES}" \
        MOCK_SYNC_EXIT="${MOCK_SYNC_EXIT:-0}" \
        MOCK_HASH_MISMATCH_PATH="${MOCK_HASH_MISMATCH_PATH:-}" \
        "$DEPLOY_DIR/scripts/allium-deploy-upload-r2.sh" "$@"
}

prime_backup_markers() {
    printf '%s\n' "$TODAY_LOCAL" > "$DEPLOY_DIR/logs/last-local-backup-date"
    printf '%s\n' "$TODAY_LOCAL" > "$DEPLOY_DIR/logs/last-r2-backup-date"
}

count_rclone_command() {
    local command_name="$1"
    awk -F '\t' -v command_name="$command_name" '$1 == command_name { count += 1 } END { print count + 0 }' "$RCLONE_LOG"
}

prime_backup_markers
: > "$RCLONE_LOG"
run_r2 >/dev/null
[[ "$(cat "$CONTENT_MARKER")" == "$TODAY_UTC" ]] || fail "successful daily sync did not write today's UTC marker"
[[ "$(count_rclone_command sync)" == "1" ]] || fail "first daily invocation did not perform exactly one live sync"
[[ "$(count_rclone_command size)" == "2" ]] || fail "daily sync did not compare source and remote sizes"
[[ "$(count_rclone_command cat)" == "3" ]] || fail "daily sync did not hash every representative object"
pass "due daily sync uploads, verifies, and records success"

: > "$RCLONE_LOG"
run_r2 >/dev/null
[[ "$(count_rclone_command sync)" == "0" ]] || fail "same-day invocation repeated the live sync"
[[ "$(count_rclone_command size)" == "0" ]] || fail "same-day skip repeated verification"
pass "same-day success marker skips later live syncs"

: > "$RCLONE_LOG"
run_r2 --force-content-sync "$OUTPUT_DIR" >/dev/null
[[ "$(count_rclone_command sync)" == "1" ]] || fail "manual force did not run the live sync"
[[ "$(count_rclone_command cat)" == "3" ]] || fail "manual force did not verify representative hashes"
pass "manual force sync bypasses today's marker and still verifies"

rm -f "$CONTENT_MARKER"
: > "$RCLONE_LOG"
set +e
MOCK_SYNC_EXIT=23 run_r2 >/dev/null 2>&1
status=$?
set -e
[[ "$status" == "23" ]] || fail "upload failure returned $status instead of 23"
[[ ! -f "$CONTENT_MARKER" ]] || fail "upload failure wrote a success marker"
pass "upload failure leaves the daily sync due for retry"

: > "$RCLONE_LOG"
set +e
MOCK_REMOTE_BYTES=$((SOURCE_BYTES + 1)) run_r2 >/dev/null 2>&1
status=$?
set -e
[[ "$status" != "0" ]] || fail "size mismatch was accepted"
[[ ! -f "$CONTENT_MARKER" ]] || fail "size mismatch wrote a success marker"
pass "count or byte mismatch leaves the daily sync due for retry"

: > "$RCLONE_LOG"
set +e
MOCK_HASH_MISMATCH_PATH=search-index.json run_r2 >/dev/null 2>&1
status=$?
set -e
[[ "$status" != "0" ]] || fail "representative hash mismatch was accepted"
[[ ! -f "$CONTENT_MARKER" ]] || fail "hash mismatch wrote a success marker"
pass "representative hash mismatch leaves the daily sync due for retry"

: > "$RCLONE_LOG"
set +e
R2_CONTENT_VERIFY_PATHS='index.html,' run_r2 >/dev/null 2>&1
status=$?
set -e
[[ "$status" != "0" ]] || fail "empty representative path was accepted"
[[ ! -f "$CONTENT_MARKER" ]] || fail "empty representative path wrote a success marker"
pass "empty representative paths fail verification"

: > "$RCLONE_LOG"
run_r2 >/dev/null
[[ "$(cat "$CONTENT_MARKER")" == "$TODAY_UTC" ]] || fail "retry did not record success"
[[ "$(count_rclone_command sync)" == "1" ]] || fail "retry did not synchronize content"
pass "a later cron-style invocation retries and recovers"

: > "$RCLONE_LOG"
R2_CONTENT_SYNC_INTERVAL=every-build run_r2 >/dev/null
R2_CONTENT_SYNC_INTERVAL=every-build run_r2 >/dev/null
[[ "$(count_rclone_command sync)" == "2" ]] || fail "safe default did not retain every-build behavior"
[[ "$(count_rclone_command size)" == "0" ]] || fail "every-build compatibility mode added daily verification work"
pass "every-build mode preserves the existing publication behavior"

: > "$RCLONE_LOG"
set +e
R2_CONTENT_SYNC_INTERVAL=weekly run_r2 >/dev/null 2>&1
status=$?
set -e
[[ "$status" == "2" ]] || fail "invalid interval returned $status instead of 2"
[[ "$(count_rclone_command sync)" == "0" ]] || fail "invalid interval invoked a sync"
pass "invalid content intervals fail closed"
