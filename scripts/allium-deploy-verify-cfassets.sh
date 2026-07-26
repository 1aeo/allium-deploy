#!/usr/bin/env bash
# Verify an immutable Allium Workers Static Assets preview before promotion.

set -euo pipefail

PREVIEW_URL="${1:-}"
SOURCE_DIR="${2:-${OUTPUT_DIR:-$HOME/metrics-output}}"
ATTEMPTS="${CF_ASSETS_VERIFY_ATTEMPTS:-3}"
RETRY_DELAY="${CF_ASSETS_VERIFY_RETRY_DELAY:-1}"
CURL_TIMEOUT="${CF_ASSETS_VERIFY_CURL_TIMEOUT:-60}"

if [[ -z "$PREVIEW_URL" ]]; then
    echo "Usage: $0 <preview-url> [source-dir]" >&2
    exit 2
fi

PREVIEW_URL="${PREVIEW_URL%/}"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Source directory not found: $SOURCE_DIR" >&2
    exit 2
fi

for required in curl sha256sum find sort sed awk; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "Required command not found: $required" >&2
        exit 2
    fi
done

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

log() {
    printf '[CF-Assets-Verify] %s\n' "$1"
}

path_for_file() {
    local file="$1"
    local relative="${file#$SOURCE_DIR/}"

    if [[ "$relative" == "index.html" ]]; then
        printf '/'
    elif [[ "$relative" == */index.html ]]; then
        printf '/%s' "${relative%index.html}"
    else
        printf '/%s' "$relative"
    fi
}

fetch_and_hash() {
    local label="$1"
    local url_path="$2"
    local local_file="$3"
    local output_file="$TMP_DIR/${label}.body"
    local expected actual status

    expected=$(sha256sum "$local_file" | awk '{print $1}')
    status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --output "$output_file" --write-out '%{http_code}' \
        "$PREVIEW_URL$url_path")

    if [[ "$status" != "200" ]]; then
        log "$label failed: HTTP $status for $url_path"
        return 1
    fi

    actual=$(sha256sum "$output_file" | awk '{print $1}')
    if [[ "$actual" != "$expected" ]]; then
        log "$label failed: SHA-256 mismatch for $url_path"
        return 1
    fi

    log "$label ok: $url_path sha256=$actual"
}

verify_headers() {
    local headers="$TMP_DIR/root.headers"
    local status cache_control robots

    status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --dump-header "$headers" --output /dev/null --write-out '%{http_code}' \
        "$PREVIEW_URL/")
    cache_control=$(awk 'BEGIN{IGNORECASE=1} /^cache-control:/ {$1=""; sub(/^ /, ""); gsub(/\r/, ""); print; exit}' "$headers")
    robots=$(awk 'BEGIN{IGNORECASE=1} /^x-robots-tag:/ {$1=""; sub(/^ /, ""); gsub(/\r/, ""); print; exit}' "$headers")

    [[ "$status" == "200" ]] || { log "root headers failed: HTTP $status"; return 1; }
    [[ "$cache_control" == *"max-age=0"* && "$cache_control" == *"must-revalidate"* ]] || {
        log "root headers failed: unexpected Cache-Control '$cache_control'"
        return 1
    }
    [[ "$robots" == *"noindex"* ]] || {
        log "root headers failed: preview is missing noindex"
        return 1
    }

    log "headers ok: cache-control='$cache_control' robots='$robots'"
}

verify_directory_and_404() {
    local nested_file="$1"
    local directory_path missing_status redirect_status
    directory_path=$(path_for_file "$nested_file")

    redirect_status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --output /dev/null --write-out '%{http_code}' \
        "${PREVIEW_URL}${directory_path%/}")
    [[ "$redirect_status" == "301" || "$redirect_status" == "302" || "$redirect_status" == "307" || "$redirect_status" == "308" ]] || {
        log "directory canonicalization failed: HTTP $redirect_status for ${directory_path%/}"
        return 1
    }

    missing_status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --output "$TMP_DIR/missing.body" --write-out '%{http_code}' \
        "$PREVIEW_URL/__allium_cfassets_missing_probe__")
    [[ "$missing_status" == "404" ]] || {
        log "custom 404 failed: HTTP $missing_status"
        return 1
    }

    log "routing ok: canonical redirect=$redirect_status custom-404=$missing_status"
}

verify_search() {
    local fingerprint headers status location expected

    if ! command -v jq >/dev/null 2>&1; then
        log "search verification failed: jq is required"
        return 1
    fi

    fingerprint=$(jq -r '.relays[0].f // empty' "$SOURCE_DIR/search-index.json")
    [[ "$fingerprint" =~ ^[A-Fa-f0-9]{40}$ ]] || {
        log "search verification failed: no full fingerprint in search-index.json"
        return 1
    }

    headers="$TMP_DIR/search.headers"
    status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --dump-header "$headers" --output /dev/null --write-out '%{http_code}' \
        "$PREVIEW_URL/search?q=$fingerprint")
    location=$(awk 'BEGIN{IGNORECASE=1} /^location:/ {$1=""; sub(/^ /, ""); gsub(/\r/, ""); print; exit}' "$headers")
    expected="/relay/${fingerprint}/"

    [[ "$status" == "302" ]] || {
        log "search verification failed: HTTP $status"
        return 1
    }
    [[ "$location" == *"$expected" ]] || {
        log "search verification failed: location '$location' does not end with '$expected'"
        return 1
    }

    log "search ok: fingerprint redirected to $expected"
}

ROOT_FILE="$SOURCE_DIR/index.html"
INDEX_FILE="$SOURCE_DIR/search-index.json"

[[ -f "$ROOT_FILE" ]] || { echo "Missing $ROOT_FILE" >&2; exit 2; }
[[ -f "$INDEX_FILE" ]] || { echo "Missing $INDEX_FILE" >&2; exit 2; }

NESTED_FILE=$(find "$SOURCE_DIR" -mindepth 2 -type f -name index.html -print | sort | awk 'NR == 1 { print }')
[[ -n "$NESTED_FILE" ]] || { echo "No nested index.html found" >&2; exit 2; }

LARGEST_RECORD=$(find "$SOURCE_DIR" -type f ! -name _headers -printf '%s %p\n' | sort -nr | awk 'NR == 1 { print }')
LARGEST_FILE="${LARGEST_RECORD#* }"
[[ -f "$LARGEST_FILE" ]] || { echo "Could not select largest file" >&2; exit 2; }

NESTED_PATH=$(path_for_file "$NESTED_FILE")
LARGEST_PATH=$(path_for_file "$LARGEST_FILE")

for ((attempt=1; attempt<=ATTEMPTS; attempt++)); do
    log "verification attempt $attempt/$ATTEMPTS for $PREVIEW_URL"
    fetch_and_hash root / "$ROOT_FILE"
    fetch_and_hash search-index /search-index.json "$INDEX_FILE"
    fetch_and_hash directory "$NESTED_PATH" "$NESTED_FILE"
    fetch_and_hash largest "$LARGEST_PATH" "$LARGEST_FILE"
    verify_headers
    verify_directory_and_404 "$NESTED_FILE"
    verify_search

    if (( attempt < ATTEMPTS )); then
        sleep "$RETRY_DELAY"
    fi
done

log "all checks passed for $PREVIEW_URL"
