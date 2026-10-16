#!/usr/bin/env bash
# Verify an immutable Allium Workers Static Assets preview before promotion.
# With CHARTS_LAYOUT=charts the charts below charts/ belong to the charts
# Worker, which this preview cannot reach: they are left out of the checks,
# and an old chart URL must redirect to its /charts/ path instead.

set -euo pipefail

PREVIEW_URL="${1:-}"
SOURCE_DIR="${2:-${OUTPUT_DIR:-$HOME/metrics-output}}"
CHARTS_LAYOUT="${CHARTS_LAYOUT:-beside}"
# Allium ran with --no-charts: the tree has no chart to probe.
ALLIUM_NO_CHARTS="${ALLIUM_NO_CHARTS:-false}"
REQUIRED_PASSES="${CF_ASSETS_VERIFY_ATTEMPTS:-3}"
MAX_ATTEMPTS="${CF_ASSETS_VERIFY_MAX_ATTEMPTS:-12}"
RETRY_DELAY="${CF_ASSETS_VERIFY_RETRY_DELAY:-10}"
CURL_TIMEOUT="${CF_ASSETS_VERIFY_CURL_TIMEOUT:-60}"

if [[ -z "$PREVIEW_URL" ]]; then
    echo "Usage: $0 <preview-url> [source-dir]" >&2
    exit 2
fi

PREVIEW_URL="${PREVIEW_URL%/}"
# Paths from find are matched and stripped against "$SOURCE_DIR/", so drop
# trailing slashes from the directory (keeping "/" itself).
while [[ "$SOURCE_DIR" == */ && "$SOURCE_DIR" != / ]]; do
    SOURCE_DIR="${SOURCE_DIR%/}"
done

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Source directory not found: $SOURCE_DIR" >&2
    exit 2
fi
case "$CHARTS_LAYOUT" in
    beside|charts) ;;
    *) echo "Invalid CHARTS_LAYOUT=$CHARTS_LAYOUT; expected beside or charts" >&2; exit 2 ;;
esac

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

file_size_bytes() {
    local file="$1"
    if stat -c '%s' "$file" >/dev/null 2>&1; then
        stat -c '%s' "$file"
    else
        stat -f '%z' "$file"
    fi
}

# Print one "size<TAB>path" record per candidate file. FIND_PRINTS_SIZES is set
# once below: GNU find reports sizes itself; otherwise stat each file. Paths
# containing a newline are skipped: one would split into two records and could
# forge a size. With CHARTS_LAYOUT=charts, charts/ is not this Worker's.
file_size_records() {
    local candidate_file
    local -a skip=()
    if [[ "$CHARTS_LAYOUT" == "charts" ]]; then
        skip=(-path "$SOURCE_DIR/charts" -prune -o)
    fi
    if (( FIND_PRINTS_SIZES )); then
        find "$SOURCE_DIR" ${skip[@]+"${skip[@]}"} -type f ! -name _headers ! -path $'*\n*' -printf '%s\t%p\n'
    else
        while IFS= read -r candidate_file; do
            printf '%s\t%s\n' "$(file_size_bytes "$candidate_file")" "$candidate_file"
        done < <(find "$SOURCE_DIR" ${skip[@]+"${skip[@]}"} -type f ! -name _headers ! -path $'*\n*' -print)
    fi
}

fetch_and_hash() {
    local label="$1"
    local url_path="$2"
    local local_file="$3"
    local output_file="$TMP_DIR/${label}.body"
    local expected actual status

    expected=$(sha256sum "$local_file" | awk '{print $1}')
    if ! status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --output "$output_file" --write-out '%{http_code}' \
        "$PREVIEW_URL$url_path"); then
        log "$label failed: transient curl/network error for $url_path"
        return 1
    fi

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

    if ! status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --dump-header "$headers" --output /dev/null --write-out '%{http_code}' \
        "$PREVIEW_URL/"); then
        log "root headers failed: transient curl/network error"
        return 1
    fi
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

    if ! redirect_status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --output /dev/null --write-out '%{http_code}' \
        "${PREVIEW_URL}${directory_path%/}"); then
        log "directory canonicalization failed: transient curl/network error"
        return 1
    fi
    [[ "$redirect_status" == "301" || "$redirect_status" == "302" || "$redirect_status" == "307" || "$redirect_status" == "308" ]] || {
        log "directory canonicalization failed: HTTP $redirect_status for ${directory_path%/}"
        return 1
    }

    if ! missing_status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --output "$TMP_DIR/missing.body" --write-out '%{http_code}' \
        "$PREVIEW_URL/__allium_cfassets_missing_probe__"); then
        log "custom 404 failed: transient curl/network error"
        return 1
    fi
    [[ "$missing_status" == "404" ]] || {
        log "custom 404 failed: HTTP $missing_status"
        return 1
    }

    log "routing ok: canonical redirect=$redirect_status custom-404=$missing_status"
}

# A version that lost its chart PNGs (for example to a stale .assetsignore or
# _redirects) would pass every other check here, so fetch one chart without
# following redirects and compare it with the source file.
verify_chart() {
    local url_path="$1"
    local local_file="$2"
    local headers="$TMP_DIR/chart.headers"
    local output_file="$TMP_DIR/chart.body"
    local expected actual status content_type

    expected=$(sha256sum "$local_file" | awk '{print $1}')
    if ! status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --dump-header "$headers" --output "$output_file" --write-out '%{http_code}' \
        "$PREVIEW_URL$url_path"); then
        log "chart failed: transient curl/network error for $url_path"
        return 1
    fi
    # The value after the colon, with optional whitespace; the media type is
    # compared case-insensitively and may only be followed by parameters.
    content_type=$(awk '{ gsub(/\r/, "") } tolower($0) ~ /^content-type:/ { sub(/^[^:]*:[ \t]*/, ""); print; exit }' "$headers")

    [[ "$status" == "200" ]] || { log "chart failed: HTTP $status for $url_path"; return 1; }
    [[ "$(printf '%s' "$content_type" | tr '[:upper:]' '[:lower:]')" =~ ^image/png[[:space:]]*(\;.*)?$ ]] || {
        log "chart failed: unexpected Content-Type '$content_type' for $url_path"
        return 1
    }
    actual=$(sha256sum "$output_file" | awk '{print $1}')
    [[ "$actual" == "$expected" ]] || { log "chart failed: SHA-256 mismatch for $url_path"; return 1; }

    log "chart ok: $url_path content-type='$content_type' sha256=$actual"
}

# CHARTS_LAYOUT=charts: the main Worker's _redirects sends an old chart URL to
# its path below /charts/, which only production routes to the charts Worker.
# A version without that _redirects would leave old chart URLs broken.
verify_chart_redirect() {
    local url_path="$1"
    local expected="$2"
    local headers="$TMP_DIR/chart.headers"
    local status location

    if ! status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --dump-header "$headers" --output /dev/null --write-out '%{http_code}' \
        "$PREVIEW_URL$url_path"); then
        log "chart redirect failed: transient curl/network error for $url_path"
        return 1
    fi
    location=$(awk 'tolower($1) == "location:" {$1=""; sub(/^ /, ""); gsub(/\r/, ""); print; exit}' "$headers")

    [[ "$status" == "302" ]] || { log "chart redirect failed: HTTP $status for $url_path"; return 1; }
    [[ "$location" == "$expected" || "$location" == "$PREVIEW_URL$expected" ]] || {
        log "chart redirect failed: $url_path redirects to '$location', not $expected"
        return 1
    }

    log "chart redirect ok: $url_path -> $expected"
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
    if ! status=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" \
        --dump-header "$headers" --output /dev/null --write-out '%{http_code}' \
        "$PREVIEW_URL/search?q=$fingerprint"); then
        log "search verification failed: transient curl/network error"
        return 1
    fi
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

# GNU find prints each size itself in one process. BSD/macOS find has no
# -printf, fails this one-time probe, and falls back to a stat per file.
FIND_PRINTS_SIZES=0
if [[ "$(find "$SOURCE_DIR" -maxdepth 0 -printf '%s' 2>/dev/null)" =~ ^[0-9]+$ ]]; then
    FIND_PRINTS_SIZES=1
fi

# Process substitution keeps find's exit status out of pipefail, as before: a
# partial walk still selects a file, and an empty one fails the check below.
LARGEST_RECORD=$(
    sort -t $'\t' -k1,1nr < <(file_size_records) \
        | awk 'NR == 1 { print }'
)
LARGEST_FILE="${LARGEST_RECORD#*$'\t'}"
[[ "$LARGEST_FILE" == "$SOURCE_DIR"/* && -f "$LARGEST_FILE" ]] || { echo "Could not select largest file" >&2; exit 2; }

NESTED_PATH=$(path_for_file "$NESTED_FILE")
LARGEST_PATH=$(path_for_file "$LARGEST_FILE")

# Allium writes chart PNGs exactly two levels deep: relay/<fingerprint>/*.png
# and contact/<hash>/*.png, or with CHARTS_LAYOUT=charts the same below
# charts/. Probe the first in sort order, preferring relays: its bytes, or with
# that layout the redirect from its old URL. Only a complete beside listing
# without PNG charts (for example SVG output) skips the probe; the charts
# layout always has PNG charts unless ALLIUM_NO_CHARTS=true. Unlike the
# largest-file walk, a listing error fails closed.
CHART_PREFIX=""
if [[ "$CHARTS_LAYOUT" == "charts" ]]; then
    CHART_PREFIX="charts/"
fi
CHART_FILE=""
for chart_root in relay contact; do
    [[ -d "$SOURCE_DIR/$CHART_PREFIX$chart_root" ]] || continue
    CHART_FILE=$(
        find "$SOURCE_DIR/$CHART_PREFIX$chart_root" -mindepth 2 -maxdepth 2 -type f -name '*.png' ! -path $'*\n*' -print \
            | LC_ALL=C sort | awk 'NR == 1 { print }'
    ) || { echo "Could not list chart PNGs under $SOURCE_DIR/$CHART_PREFIX$chart_root" >&2; exit 2; }
    [[ -z "$CHART_FILE" ]] || break
done
CHART_PATH=""
if [[ -n "$CHART_FILE" ]]; then
    CHART_PATH=$(path_for_file "$CHART_FILE")
elif [[ -n "$CHART_PREFIX" && "$ALLIUM_NO_CHARTS" != "true" ]]; then
    echo "No chart PNG under $SOURCE_DIR/charts/relay or $SOURCE_DIR/charts/contact, which CHARTS_LAYOUT=charts requires" >&2
    exit 2
else
    log "no chart PNG under ${CHART_PREFIX}relay/ or ${CHART_PREFIX}contact/; chart probe skipped"
fi

run_check_set() {
    fetch_and_hash root / "$ROOT_FILE" || return 1
    fetch_and_hash search-index /search-index.json "$INDEX_FILE" || return 1
    fetch_and_hash directory "$NESTED_PATH" "$NESTED_FILE" || return 1
    fetch_and_hash largest "$LARGEST_PATH" "$LARGEST_FILE" || return 1
    if [[ -n "$CHART_PATH" && -n "$CHART_PREFIX" ]]; then
        verify_chart_redirect "/${CHART_PATH#/charts/}" "$CHART_PATH" || return 1
    elif [[ -n "$CHART_PATH" ]]; then
        verify_chart "$CHART_PATH" "$CHART_FILE" || return 1
    fi
    verify_headers || return 1
    verify_directory_and_404 "$NESTED_FILE" || return 1
    verify_search || return 1
}

[[ "$REQUIRED_PASSES" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid required pass count: $REQUIRED_PASSES" >&2; exit 2; }
[[ "$MAX_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid max attempt count: $MAX_ATTEMPTS" >&2; exit 2; }
(( MAX_ATTEMPTS >= REQUIRED_PASSES )) || { echo "Max attempts must be at least required passes" >&2; exit 2; }

consecutive=0
for ((attempt=1; attempt<=MAX_ATTEMPTS; attempt++)); do
    log "verification attempt $attempt/$MAX_ATTEMPTS; consecutive=$consecutive/$REQUIRED_PASSES for $PREVIEW_URL"
    if run_check_set; then
        consecutive=$((consecutive + 1))
        if (( consecutive >= REQUIRED_PASSES )); then
            log "all checks passed $REQUIRED_PASSES consecutive times for $PREVIEW_URL"
            exit 0
        fi
    else
        consecutive=0
        log "attempt $attempt did not pass; waiting ${RETRY_DELAY}s for a bounded transient retry"
    fi

    if (( attempt < MAX_ATTEMPTS )); then
        sleep "$RETRY_DELAY"
    fi
done

log "verification failed: $REQUIRED_PASSES consecutive passes were not reached in $MAX_ATTEMPTS attempts"
exit 1
