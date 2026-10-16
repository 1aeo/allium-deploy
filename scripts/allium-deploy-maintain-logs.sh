#!/usr/bin/env bash
# Bound the two operational logs that are not already compact TSV summaries.
# Cron opens update.log before the deployment starts, so automatic rotation
# leaves the just-rotated file uncompressed until the following non-overlapping
# job. At that point no process has the old inode open and compression is safe.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

UPDATE_LOG_FILE="${ALLIUM_UPDATE_LOG_FILE:-$DEPLOY_DIR/logs/update.log}"
UPDATE_LOG_MAX_BYTES="${ALLIUM_UPDATE_LOG_MAX_BYTES:-33554432}"
UPDATE_LOG_ARCHIVES="${ALLIUM_UPDATE_LOG_ARCHIVES:-3}"
WRANGLER_ERROR_LOG_FILE="${WRANGLER_LOG_PATH:-$DEPLOY_DIR/logs/wrangler-error.log}"
WRANGLER_ERROR_LOG_MAX_BYTES="${WRANGLER_ERROR_LOG_MAX_BYTES:-8388608}"
WRANGLER_ERROR_LOG_ARCHIVES="${WRANGLER_ERROR_LOG_ARCHIVES:-2}"

validate_positive_integer() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
        printf '[Log-Maintenance] invalid %s=%s\n' "$name" "$value" >&2
        return 2
    }
}

validate_log_path() {
    local name="$1"
    local log_file="$2"
    local allowed_dir="$DEPLOY_DIR/logs"

    mkdir -p "$allowed_dir"
    [[ "$log_file" == "$allowed_dir/"* && "$log_file" != "$allowed_dir/" ]] || {
        printf '[Log-Maintenance] refusing unsafe %s=%s; expected a file below %s\n' \
            "$name" "$log_file" "$allowed_dir" >&2
        return 2
    }
}

shift_archives() {
    local log_file="$1"
    local keep="$2"
    local index

    rm -f "${log_file}.${keep}.gz"
    for ((index=keep-1; index>=1; index--)); do
        if [[ -f "${log_file}.${index}.gz" ]]; then
            mv "${log_file}.${index}.gz" "${log_file}.$((index + 1)).gz"
        fi
    done
}

rotate_if_needed() {
    local label="$1"
    local log_file="$2"
    local max_bytes="$3"
    local keep="$4"
    local size=0

    mkdir -p "$(dirname "$log_file")"

    # A pending .1 is from the previous cron invocation. The active pathname
    # existing again proves cron has opened a new inode and the old one is safe
    # to compress because the outer flock prevents overlapping deployments.
    if [[ -f "${log_file}.1" && -e "$log_file" ]]; then
        shift_archives "$log_file" "$keep"
        gzip -f "${log_file}.1"
    fi

    [[ -f "$log_file" ]] || return 0
    size=$(wc -c < "$log_file" | tr -d '[:space:]')
    (( size >= max_bytes )) || return 0

    mv "$log_file" "${log_file}.1"
    printf '[Log-Maintenance] rotated %s at %s bytes; retaining %s compressed archives\n' \
        "$label" "$size" "$keep"
}

validate_positive_integer ALLIUM_UPDATE_LOG_MAX_BYTES "$UPDATE_LOG_MAX_BYTES"
validate_positive_integer ALLIUM_UPDATE_LOG_ARCHIVES "$UPDATE_LOG_ARCHIVES"
validate_positive_integer WRANGLER_ERROR_LOG_MAX_BYTES "$WRANGLER_ERROR_LOG_MAX_BYTES"
validate_positive_integer WRANGLER_ERROR_LOG_ARCHIVES "$WRANGLER_ERROR_LOG_ARCHIVES"
validate_log_path ALLIUM_UPDATE_LOG_FILE "$UPDATE_LOG_FILE"
validate_log_path WRANGLER_LOG_PATH "$WRANGLER_ERROR_LOG_FILE"

rotate_if_needed update.log "$UPDATE_LOG_FILE" "$UPDATE_LOG_MAX_BYTES" "$UPDATE_LOG_ARCHIVES"
rotate_if_needed wrangler-error.log "$WRANGLER_ERROR_LOG_FILE" "$WRANGLER_ERROR_LOG_MAX_BYTES" "$WRANGLER_ERROR_LOG_ARCHIVES"
