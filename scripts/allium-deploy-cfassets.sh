#!/usr/bin/env bash
# Upload and verify an Allium Workers Static Assets version without changing
# production traffic. Promotion is guarded and disabled throughout Stages 1–2.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

MODE="${1:---upload-only}"
case "$MODE" in
    --upload-only|--generate-only|--promote) ;;
    *) echo "Usage: $0 [--upload-only|--generate-only|--promote]" >&2; exit 2 ;;
esac

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    # shellcheck disable=SC1091
    source "$DEPLOY_DIR/config.env"
fi

CF_ASSETS_ENABLED="${CF_ASSETS_ENABLED:-false}"
CF_ASSETS_ALLOW_PROMOTION="${CF_ASSETS_ALLOW_PROMOTION:-false}"
CF_ASSETS_WORKER_NAME="${CF_ASSETS_WORKER_NAME:-allium-metrics-assets}"
CF_ASSETS_PREVIEW_ALIAS="${CF_ASSETS_PREVIEW_ALIAS:-allium-candidate}"
CF_ASSETS_COMPATIBILITY_DATE="${CF_ASSETS_COMPATIBILITY_DATE:-2026-07-26}"
CF_ASSETS_DIRECTORY="${OUTPUT_DIR:-$HOME/metrics-output}"
CF_ASSETS_TEMPLATE="${CF_ASSETS_TEMPLATE:-$DEPLOY_DIR/wrangler.assets.toml.template}"
CF_ASSETS_CONFIG="${CF_ASSETS_CONFIG:-$DEPLOY_DIR/wrangler.assets.toml}"
CF_ASSETS_HEADERS_SOURCE="${CF_ASSETS_HEADERS_SOURCE:-$DEPLOY_DIR/cloudflare-assets/_headers}"
CF_ASSETS_404_SOURCE="${CF_ASSETS_404_SOURCE:-$DEPLOY_DIR/cloudflare-assets/404.html}"
CF_ASSETS_VERIFY_SCRIPT="${CF_ASSETS_VERIFY_SCRIPT:-$SCRIPT_DIR/allium-deploy-verify-cfassets.sh}"
CF_ASSETS_CONSECUTIVE_FILE="${CF_ASSETS_CONSECUTIVE_FILE:-$DEPLOY_DIR/logs/cfassets-shadow-consecutive-successes}"
CF_ASSETS_LAST_VERSION_FILE="${CF_ASSETS_LAST_VERSION_FILE:-$DEPLOY_DIR/logs/cfassets-last-version}"
CF_ASSETS_SUMMARY_FILE="${CF_ASSETS_SUMMARY_FILE:-$DEPLOY_DIR/logs/cfassets-shadow-summary.tsv}"

log() {
    printf '[CF-Assets] %s\n' "$1"
}

assert_safe_worker_name() {
    [[ "$CF_ASSETS_WORKER_NAME" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || {
        log "invalid worker name: $CF_ASSETS_WORKER_NAME"
        return 1
    }
    [[ "$CF_ASSETS_PREVIEW_ALIAS" =~ ^[a-z][a-z0-9-]*$ ]] || {
        log "invalid preview alias: $CF_ASSETS_PREVIEW_ALIAS"
        return 1
    }
}

assert_fresh_checkout() {
    if [[ "${CF_ASSETS_REQUIRE_FRESH_CHECKOUT:-true}" != "true" ]]; then
        return 0
    fi

    local head_sha origin_sha dirty
    run_with_timeout 30 git -C "$DEPLOY_DIR" fetch --quiet origin main
    head_sha=$(git -C "$DEPLOY_DIR" rev-parse HEAD)
    origin_sha=$(git -C "$DEPLOY_DIR" rev-parse origin/main)
    dirty=$(git -C "$DEPLOY_DIR" status --porcelain --untracked-files=normal)

    [[ "$head_sha" == "$origin_sha" ]] || {
        log "refusing upload: checkout HEAD $head_sha does not match origin/main $origin_sha"
        return 1
    }
    [[ -z "$dirty" ]] || {
        log "refusing upload: checkout has tracked or unignored changes"
        printf '%s\n' "$dirty" >&2
        return 1
    }
}

escape_sed_replacement() {
    printf '%s' "$1" | sed 's/[&|]/\\&/g'
}

generate_config() {
    local worker_name compatibility_date assets_directory

    [[ -f "$CF_ASSETS_TEMPLATE" ]] || { log "missing template: $CF_ASSETS_TEMPLATE"; return 1; }
    [[ -d "$CF_ASSETS_DIRECTORY" ]] || { log "missing assets directory: $CF_ASSETS_DIRECTORY"; return 1; }
    [[ -f "$CF_ASSETS_HEADERS_SOURCE" ]] || { log "missing headers source: $CF_ASSETS_HEADERS_SOURCE"; return 1; }
    [[ -f "$CF_ASSETS_404_SOURCE" ]] || { log "missing 404 source: $CF_ASSETS_404_SOURCE"; return 1; }

    install -m 0644 "$CF_ASSETS_HEADERS_SOURCE" "$CF_ASSETS_DIRECTORY/_headers"
    install -m 0644 "$CF_ASSETS_404_SOURCE" "$CF_ASSETS_DIRECTORY/404.html"

    worker_name=$(escape_sed_replacement "$CF_ASSETS_WORKER_NAME")
    compatibility_date=$(escape_sed_replacement "$CF_ASSETS_COMPATIBILITY_DATE")
    assets_directory=$(escape_sed_replacement "$CF_ASSETS_DIRECTORY")

    sed -e "s|{{CF_ASSETS_WORKER_NAME}}|$worker_name|g" \
        -e "s|{{CF_ASSETS_COMPATIBILITY_DATE}}|$compatibility_date|g" \
        -e "s|{{CF_ASSETS_DIRECTORY}}|$assets_directory|g" \
        "$CF_ASSETS_TEMPLATE" > "$CF_ASSETS_CONFIG.tmp"
    mv "$CF_ASSETS_CONFIG.tmp" "$CF_ASSETS_CONFIG"

    if grep -Eq '(^|[[:space:]])routes?[[:space:]]*=|custom_domain[[:space:]]*=' "$CF_ASSETS_CONFIG"; then
        log "refusing shadow config containing a route or custom domain"
        return 1
    fi

    log "generated route-free config: $CF_ASSETS_CONFIG"
}

load_cloudflare_token() {
    local token_file
    for token_file in \
        "$HOME/.config/cloudflare/workers_api_token" \
        "$HOME/.config/cloudflare/api_token"; do
        if [[ -f "$token_file" ]]; then
            # shellcheck disable=SC1090
            source "$token_file"
            break
        fi
    done

    [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] || {
        log "CLOUDFLARE_API_TOKEN is not configured"
        return 1
    }
    export CLOUDFLARE_API_TOKEN
    export CLOUDFLARE_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:-}"
}

run_wrangler() {
    (
        cd "$DEPLOY_DIR"
        if command -v pnpm >/dev/null 2>&1; then
            pnpm exec wrangler "$@"
        elif command -v corepack >/dev/null 2>&1; then
            corepack pnpm exec wrangler "$@"
        else
            npx --no-install wrangler "$@"
        fi
    )
}

record_failure() {
    local status="$1"
    if [[ "$status" -ne 0 && "$MODE" == "--upload-only" ]]; then
        mkdir -p "$(dirname "$CF_ASSETS_CONSECUTIVE_FILE")"
        printf '0\n' > "$CF_ASSETS_CONSECUTIVE_FILE"
    fi
}

trap 'record_failure $?' EXIT

assert_safe_worker_name
generate_config

if [[ "$MODE" == "--generate-only" ]]; then
    log "generate-only complete; no Cloudflare API call was made"
    exit 0
fi

if [[ "$MODE" == "--promote" ]]; then
    [[ "$CF_ASSETS_ALLOW_PROMOTION" == "true" ]] || {
        log "promotion is disabled; Stage 3 requires explicit review"
        exit 3
    }
    assert_fresh_checkout
    load_cloudflare_token
    log "promotion was explicitly enabled"
    run_wrangler versions deploy --config "$CF_ASSETS_CONFIG"
    exit 0
fi

[[ "$CF_ASSETS_ENABLED" == "true" ]] || {
    log "shadow upload is disabled (CF_ASSETS_ENABLED=$CF_ASSETS_ENABLED)"
    exit 0
}

assert_fresh_checkout
load_cloudflare_token
mkdir -p "$DEPLOY_DIR/logs"

UPLOAD_OUTPUT=$(mktemp)
trap 'status=$?; rm -f "$UPLOAD_OUTPUT"; record_failure "$status"' EXIT

started=$(date +%s)
log "uploading immutable shadow version for $CF_ASSETS_WORKER_NAME"
if ! run_wrangler versions upload \
    --preview-alias "$CF_ASSETS_PREVIEW_ALIAS" \
    --config "$CF_ASSETS_CONFIG" 2>&1 | tee "$UPLOAD_OUTPUT"; then
    log "version upload failed"
    exit 1
fi

version_id=$(sed -n 's/.*Worker Version ID: //p' "$UPLOAD_OUTPUT" | tr -d '\r' | tail -1)
preview_url=$(sed -n 's/.*Version Preview Alias URL: //p' "$UPLOAD_OUTPUT" | tr -d '\r' | tail -1)

[[ -n "$version_id" ]] || { log "could not parse Worker Version ID"; exit 1; }
[[ "$preview_url" == https://*workers.dev ]] || { log "could not parse preview alias URL"; exit 1; }

"$CF_ASSETS_VERIFY_SCRIPT" "$preview_url" "$CF_ASSETS_DIRECTORY"

finished=$(date +%s)
duration=$((finished - started))
file_count=$(find "$CF_ASSETS_DIRECTORY" -type f ! -name _headers | wc -l | tr -d ' ')
byte_count=$(du -sb "$CF_ASSETS_DIRECTORY" | awk '{print $1}')
consecutive=$(cat "$CF_ASSETS_CONSECUTIVE_FILE" 2>/dev/null || printf '0')
[[ "$consecutive" =~ ^[0-9]+$ ]] || consecutive=0
consecutive=$((consecutive + 1))

printf '%s\n' "$consecutive" > "$CF_ASSETS_CONSECUTIVE_FILE"
printf '%s\n' "$version_id" > "$CF_ASSETS_LAST_VERSION_FILE"

if [[ ! -f "$CF_ASSETS_SUMMARY_FILE" ]]; then
    printf 'timestamp_utc\tversion_id\tduration_seconds\tfile_count\tbyte_count\tpreview_url\tconsecutive_successes\n' > "$CF_ASSETS_SUMMARY_FILE"
fi
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$version_id" "$duration" \
    "$file_count" "$byte_count" "$preview_url" "$consecutive" \
    >> "$CF_ASSETS_SUMMARY_FILE"

log "shadow version verified: version=$version_id duration=${duration}s consecutive=$consecutive preview=$preview_url"
