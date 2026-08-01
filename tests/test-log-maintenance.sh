#!/usr/bin/env bash

set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$REPO_DIR/logs"
TMP_DIR=$(mktemp -d "$REPO_DIR/logs/test-maintenance.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

UPDATE_LOG="$TMP_DIR/update.log"
WRANGLER_LOG="$TMP_DIR/wrangler-error.log"
printf '1234567890' > "$UPDATE_LOG"
printf 'abcdefghij' > "$WRANGLER_LOG"

ALLIUM_UPDATE_LOG_FILE="$UPDATE_LOG" \
ALLIUM_UPDATE_LOG_MAX_BYTES=10 \
ALLIUM_UPDATE_LOG_ARCHIVES=2 \
WRANGLER_LOG_PATH="$WRANGLER_LOG" \
WRANGLER_ERROR_LOG_MAX_BYTES=10 \
WRANGLER_ERROR_LOG_ARCHIVES=2 \
    "$REPO_DIR/scripts/allium-deploy-maintain-logs.sh" >/dev/null

[[ -f "$UPDATE_LOG.1" && ! -e "$UPDATE_LOG" ]] || fail "update log was not left pending for safe next-job compression"
[[ -f "$WRANGLER_LOG.1" && ! -e "$WRANGLER_LOG" ]] || fail "Wrangler log was not rotated"

# Simulate cron opening fresh active paths before the following invocation.
printf 'new' > "$UPDATE_LOG"
printf 'new' > "$WRANGLER_LOG"
ALLIUM_UPDATE_LOG_FILE="$UPDATE_LOG" \
ALLIUM_UPDATE_LOG_MAX_BYTES=10 \
ALLIUM_UPDATE_LOG_ARCHIVES=2 \
WRANGLER_LOG_PATH="$WRANGLER_LOG" \
WRANGLER_ERROR_LOG_MAX_BYTES=10 \
WRANGLER_ERROR_LOG_ARCHIVES=2 \
    "$REPO_DIR/scripts/allium-deploy-maintain-logs.sh" >/dev/null

[[ -f "$UPDATE_LOG.1.gz" && ! -e "$UPDATE_LOG.1" ]] || fail "pending update log was not compressed"
[[ -f "$WRANGLER_LOG.1.gz" && ! -e "$WRANGLER_LOG.1" ]] || fail "pending Wrangler log was not compressed"
[[ "$(gzip -cd "$UPDATE_LOG.1.gz")" == 1234567890 ]] || fail "compressed update log content changed"
pass "oversized logs rotate and compress on the next non-overlapping invocation"

printf 'abcdefghij' > "$UPDATE_LOG"
ALLIUM_UPDATE_LOG_FILE="$UPDATE_LOG" \
ALLIUM_UPDATE_LOG_MAX_BYTES=10 \
ALLIUM_UPDATE_LOG_ARCHIVES=2 \
WRANGLER_LOG_PATH="$WRANGLER_LOG" \
WRANGLER_ERROR_LOG_MAX_BYTES=10 \
WRANGLER_ERROR_LOG_ARCHIVES=2 \
    "$REPO_DIR/scripts/allium-deploy-maintain-logs.sh" >/dev/null
printf 'fresh' > "$UPDATE_LOG"
ALLIUM_UPDATE_LOG_FILE="$UPDATE_LOG" \
ALLIUM_UPDATE_LOG_MAX_BYTES=10 \
ALLIUM_UPDATE_LOG_ARCHIVES=2 \
WRANGLER_LOG_PATH="$WRANGLER_LOG" \
WRANGLER_ERROR_LOG_MAX_BYTES=10 \
WRANGLER_ERROR_LOG_ARCHIVES=2 \
    "$REPO_DIR/scripts/allium-deploy-maintain-logs.sh" >/dev/null

[[ -f "$UPDATE_LOG.2.gz" ]] || fail "older compressed update log was not retained"
[[ "$(gzip -cd "$UPDATE_LOG.2.gz")" == 1234567890 ]] || fail "older archive content changed"
[[ "$(gzip -cd "$UPDATE_LOG.1.gz")" == abcdefghij ]] || fail "newer archive content changed"
pass "archive count remains bounded while retaining recent history"
