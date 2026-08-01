#!/usr/bin/env bash
# Allium Deploy - Update Metrics
# Runs allium to generate site, uploads to configured storage backends, prunes old backups
# Cron: */30 * * * * /path/to/allium-deploy-update.sh >> /path/to/logs/update.log 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
UPDATE_STARTED_EPOCH="$(date +%s)"
UPDATE_STARTED_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

if [[ "${ALLIUM_DEPLOY_TEST_MODE:-}" == "1" ]]; then
    :
elif [[ -f "$DEPLOY_DIR/config.env" ]]; then
    source "$DEPLOY_DIR/config.env"
else
    echo "Error: config.env not found"
    exit 1
fi

ALLIUM_CONFIG_DIR="${ALLIUM_REPO_DIR:-${ALLIUM_DIR:-$HOME/allium}}"
ALLIUM_CONFIG_DIR="${ALLIUM_CONFIG_DIR%/}"
if [[ -d "$ALLIUM_CONFIG_DIR/.git" ]]; then
    ALLIUM_REPO_DIR="$ALLIUM_CONFIG_DIR"
elif [[ -d "$ALLIUM_CONFIG_DIR/../.git" ]]; then
    ALLIUM_REPO_DIR="$(cd "$ALLIUM_CONFIG_DIR/.." && pwd)"
else
    ALLIUM_REPO_DIR="$ALLIUM_CONFIG_DIR"
fi
if [[ -f "$ALLIUM_CONFIG_DIR/allium.py" ]]; then
    ALLIUM_DIR="$ALLIUM_CONFIG_DIR"
else
    ALLIUM_DIR="${ALLIUM_REPO_DIR%/}/allium"
fi
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/metrics-output}"
SITE_URL="${SITE_URL:-https://metrics.example.com}"
PAGES_PURGE_URL="${PAGES_PURGE_URL:-$SITE_URL}"
CONSECUTIVE_FAILURES_FILE="/tmp/allium-deploy-failures"

# Storage configuration
STORAGE_ORDER="${STORAGE_ORDER:-r2,do,failover}"
R2_ENABLED="${R2_ENABLED:-true}"
DO_ENABLED="${DO_ENABLED:-false}"
CF_ASSETS_ENABLED="${CF_ASSETS_ENABLED:-false}"
CF_ASSETS_REQUIRED="${CF_ASSETS_REQUIRED:-false}"
CF_ASSETS_ALLOW_PROMOTION="${CF_ASSETS_ALLOW_PROMOTION:-false}"
CF_ASSETS_SCRIPT="${CF_ASSETS_SCRIPT:-$SCRIPT_DIR/allium-deploy-cfassets.sh}"
CF_ASSETS_CONSECUTIVE_FILE="${CF_ASSETS_CONSECUTIVE_FILE:-$DEPLOY_DIR/logs/cfassets-shadow-consecutive-successes}"
CF_ASSETS_JOB_SUMMARY_FILE="${CF_ASSETS_JOB_SUMMARY_FILE:-$DEPLOY_DIR/logs/cfassets-stage2-job-summary.tsv}"
CF_ASSETS_MAX_JOB_SECONDS="${CF_ASSETS_MAX_JOB_SECONDS:-1800}"

# Keep human-readable deployment output and error-only Wrangler diagnostics
# bounded. Compact job/candidate/promotion TSV summaries are retained
# separately and are not affected by this rotation.
ALLIUM_UPDATE_LOG_FILE="${ALLIUM_UPDATE_LOG_FILE:-$DEPLOY_DIR/logs/update.log}"
ALLIUM_UPDATE_LOG_MAX_BYTES="${ALLIUM_UPDATE_LOG_MAX_BYTES:-33554432}"
ALLIUM_UPDATE_LOG_ARCHIVES="${ALLIUM_UPDATE_LOG_ARCHIVES:-3}"
WRANGLER_LOG="${WRANGLER_LOG:-error}"
WRANGLER_DEFAULT_LOG_PATH="$DEPLOY_DIR/logs/wrangler-debug-sink.log"
WRANGLER_LOG_PATH="${WRANGLER_LOG_PATH:-$WRANGLER_DEFAULT_LOG_PATH}"
WRANGLER_LOG_SANITIZE="${WRANGLER_LOG_SANITIZE:-true}"
WRANGLER_ERROR_LOG_MAX_BYTES="${WRANGLER_ERROR_LOG_MAX_BYTES:-8388608}"
WRANGLER_ERROR_LOG_ARCHIVES="${WRANGLER_ERROR_LOG_ARCHIVES:-2}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

assert_boolean_setting() {
    local name="$1"
    local value="$2"

    case "$value" in
        true|false) return 0 ;;
        *)
            log "invalid $name=$value; expected true or false"
            return 2
            ;;
    esac
}

promote_verified_cfassets_if_ready() {
    local upload_exit="${1:-1}"

    if [[ ! "$upload_exit" =~ ^[0-9]+$ ]] || (( upload_exit > 255 )); then
        log "invalid Workers Assets upload status: $upload_exit"
        return 2
    fi
    if (( upload_exit != 0 )); then
        return "$upload_exit"
    fi
    if [[ "$CF_ASSETS_ALLOW_PROMOTION" != "true" ]]; then
        return 0
    fi

    "$CF_ASSETS_SCRIPT" --promote
}

require_current_deploy_checkout() {
    log "Verifying allium-deploy checkout before schema-triggered deploy..."

    cd "$DEPLOY_DIR"
    if ! run_with_timeout 30 git fetch --quiet origin main; then
        log "refusing schema-triggered deploy: could not fetch origin/main"
        return 1
    fi

    local local_head origin_head dirty
    if ! local_head="$(git rev-parse HEAD)" || ! origin_head="$(git rev-parse origin/main)"; then
        log "refusing schema-triggered deploy: could not resolve checkout or origin/main"
        return 1
    fi

    if [[ "$local_head" != "$origin_head" ]]; then
        log "refusing schema-triggered deploy: checkout HEAD $local_head is not origin/main $origin_head"
        return 1
    fi

    dirty="$(git status --porcelain --untracked-files=normal)"
    if [[ -n "$dirty" ]]; then
        log "refusing schema-triggered deploy: working tree has tracked or unignored changes"
        printf '%s\n' "$dirty" | sed 's/^/[dirty] /' >&2
        return 1
    fi

    log "allium-deploy checkout is current and clean"
    return 0
}

get_failures() {
    cat "$CONSECUTIVE_FAILURES_FILE" 2>/dev/null || echo 0
}

increment_failures() {
    echo $(($(get_failures) + 1)) > "$CONSECUTIVE_FAILURES_FILE"
}

reset_failures() {
    echo 0 > "$CONSECUTIVE_FAILURES_FILE"
}

fetch_check_runs() {
    local repo="$1"
    local sha="$2"
    local url="https://api.github.com/repos/$repo/commits/$sha/check-runs?per_page=100"
    local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
    local header_file page next_url

    while [[ -n "$url" ]]; do
        header_file=$(mktemp)
        if [[ -n "$token" ]]; then
            if ! page=$(run_with_timeout 30 curl -fsSL -D "$header_file" \
                -H "Accept: application/vnd.github+json" \
                -H "X-GitHub-Api-Version: 2022-11-28" \
                -H "Authorization: Bearer $token" \
                "$url"); then
                rm -f "$header_file"
                return 1
            fi
        else
            if ! page=$(run_with_timeout 30 curl -fsSL -D "$header_file" \
                -H "Accept: application/vnd.github+json" \
                -H "X-GitHub-Api-Version: 2022-11-28" \
                "$url"); then
                rm -f "$header_file"
                return 1
            fi
        fi

        printf '%s\n' "$page"
        next_url=$(awk -F'[<>]' 'tolower($0) ~ /^link:/ {
            for (i = 2; i <= NF; i += 2) {
                if ($(i + 1) ~ /rel="next"/) {
                    print $i
                    exit
                }
            }
        }' "$header_file")
        rm -f "$header_file"
        url="$next_url"
    done
}

check_runs_are_green() {
    local repo="$1"
    local sha="$2"
    local label="$3"
    local payload total failing summary

    if ! command -v curl &>/dev/null; then
        log "Guarded auto-pull skipped for $label: curl is not installed"
        return 1
    fi

    if ! command -v jq &>/dev/null; then
        log "Guarded auto-pull skipped for $label: jq is not installed"
        return 1
    fi

    if ! payload=$(fetch_check_runs "$repo" "$sha" 2>/dev/null); then
        log "Guarded auto-pull skipped for $label@$sha: could not read GitHub check-runs"
        return 1
    fi

    total=$(jq -s -r '[.[].check_runs[]] | length' <<< "$payload" 2>/dev/null || echo 0)
    if (( total < 1 )); then
        log "Guarded auto-pull skipped for $label@$sha: no GitHub check-runs found"
        return 1
    fi

    failing=$(jq -s -r '[.[].check_runs[] | select(.status != "completed" or (.conclusion != "success" and .conclusion != "skipped"))] | length' <<< "$payload" 2>/dev/null || echo 1)
    if (( failing == 0 )); then
        return 0
    fi

    summary=$(jq -s -r '[
        .[].check_runs[]
        | select(.status != "completed" or (.conclusion != "success" and .conclusion != "skipped"))
        | "\(.name):\(.status)/\(.conclusion // "null")"
    ] | join(";")' <<< "$payload" 2>/dev/null || true)
    log "Guarded auto-pull skipped for $label@$sha: checks not all success or skipped (${summary:-unknown})"
    return 1
}

guarded_pull_repo() {
    local label="$1"
    local repo_dir="$2"
    local github_repo="$3"
    local branch="$4"
    local rollback_var="$5"
    local current_branch pre_sha remote_sha post_sha

    if [[ ! -d "$repo_dir/.git" ]]; then
        log "Guarded auto-pull skipped for $label: $repo_dir is not a git checkout"
        return 0
    fi

    if ! git -C "$repo_dir" diff --quiet || ! git -C "$repo_dir" diff --cached --quiet; then
        log "Guarded auto-pull skipped for $label: tracked working tree changes are present"
        return 0
    fi

    pre_sha=$(git -C "$repo_dir" rev-parse HEAD)

    if ! run_with_timeout 30 git -C "$repo_dir" fetch origin "$branch" >/dev/null 2>&1; then
        log "Guarded auto-pull skipped for $label@$pre_sha: git fetch origin $branch failed"
        return 0
    fi

    remote_sha=$(git -C "$repo_dir" rev-parse "origin/$branch")
    if [[ "$pre_sha" == "$remote_sha" ]]; then
        log "Guarded auto-pull: $label already current at $pre_sha"
        return 0
    fi

    if ! check_runs_are_green "$github_repo" "$remote_sha" "$label"; then
        return 0
    fi

    current_branch=$(git -C "$repo_dir" symbolic-ref --quiet --short HEAD 2>/dev/null || true)
    if [[ "$current_branch" != "$branch" ]]; then
        log "Guarded auto-pull skipped for $label: checkout is on ${current_branch:-detached HEAD}, expected $branch"
        return 0
    fi

    if ! git -C "$repo_dir" merge --ff-only "origin/$branch" >/dev/null 2>&1; then
        log "Guarded auto-pull skipped for $label: $pre_sha cannot fast-forward to $remote_sha"
        return 0
    fi

    post_sha=$(git -C "$repo_dir" rev-parse HEAD)
    printf -v "$rollback_var" '%s' "$pre_sha"
    export "${rollback_var?}"
    log "Guarded auto-pull: $label $pre_sha -> $post_sha"
}

guarded_pull_allium() {
    guarded_pull_repo "allium" "$ALLIUM_REPO_DIR" "1aeo/allium" "master" "ALLIUM_ROLLBACK_SHA"
}

guarded_pull_allium_deploy() {
    guarded_pull_repo "allium-deploy" "$DEPLOY_DIR" "1aeo/allium-deploy" "main" "ALLIUM_DEPLOY_ROLLBACK_SHA"
}

rollback_repo_to_sha() {
    local label="$1"
    local repo_dir="$2"
    local sha="$3"

    if [[ -z "$sha" ]]; then
        return 0
    fi

    if git -C "$repo_dir" reset --hard "$sha" >/dev/null 2>&1; then
        log "Rolled back $label checkout to $sha"
    else
        log "Failed to roll back $label checkout to $sha"
        return 1
    fi
}

rollback_guarded_pulls() {
    local failed=false

    rollback_repo_to_sha "allium" "$ALLIUM_REPO_DIR" "${ALLIUM_ROLLBACK_SHA:-}" || failed=true
    rollback_repo_to_sha "allium-deploy" "$DEPLOY_DIR" "${ALLIUM_DEPLOY_ROLLBACK_SHA:-}" || failed=true

    if [[ "$failed" == "true" ]]; then
        return 1
    fi
}

# Record one bounded row per scheduled Stage 2 job. A failure anywhere in the
# generator/publisher/purge job, or a total runtime beyond the scheduler
# interval, breaks the consecutive-build streak even when the route-free
# Worker candidate itself happened to verify successfully.
record_stage2_job_result() {
    local status="$1"
    local started_epoch="$2"
    local started_utc="$3"
    local finished_epoch="${4:-$(date +%s)}"
    local finished_utc="${5:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"

    [[ "$CF_ASSETS_ENABLED" == "true" ]] || return 0

    local duration cadence_ok=true counter=0 counter_tmp
    duration=$((finished_epoch - started_epoch))
    if [[ ! "$CF_ASSETS_MAX_JOB_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
        log "⚠️ Invalid CF_ASSETS_MAX_JOB_SECONDS=$CF_ASSETS_MAX_JOB_SECONDS; using 1800"
        CF_ASSETS_MAX_JOB_SECONDS=1800
    fi

    if ((duration > CF_ASSETS_MAX_JOB_SECONDS)); then
        cadence_ok=false
    fi

    if [[ "$status" -ne 0 || "$cadence_ok" != "true" ]]; then
        mkdir -p "$(dirname "$CF_ASSETS_CONSECUTIVE_FILE")"
        counter_tmp="${CF_ASSETS_CONSECUTIVE_FILE}.tmp.$$"
        printf '0\n' > "$counter_tmp"
        mv "$counter_tmp" "$CF_ASSETS_CONSECUTIVE_FILE"
    fi

    counter=$(cat "$CF_ASSETS_CONSECUTIVE_FILE" 2>/dev/null || printf '0')
    [[ "$counter" =~ ^[0-9]+$ ]] || counter=0

    mkdir -p "$(dirname "$CF_ASSETS_JOB_SUMMARY_FILE")"
    if [[ ! -f "$CF_ASSETS_JOB_SUMMARY_FILE" ]]; then
        printf 'started_utc\tfinished_utc\texit_status\ttotal_duration_seconds\tcadence_ok\tshadow_counter\n' \
            > "$CF_ASSETS_JOB_SUMMARY_FILE"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$started_utc" "$finished_utc" "$status" "$duration" "$cadence_ok" "$counter" \
        >> "$CF_ASSETS_JOB_SUMMARY_FILE"

    log "Stage 2 job result: status=$status total=${duration}s cadence_ok=$cadence_ok shadow_counter=$counter"
}

record_update_exit() {
    local update_status="$1"

    trap - EXIT
    set +e
    record_stage2_job_result "$update_status" "$UPDATE_STARTED_EPOCH" "$UPDATE_STARTED_UTC"
    exit "$update_status"
}

# Cloudflare CDN purge (runs once after all uploads)
purge_cdn() {
    local site_url="${SITE_URL:-}"
    local pages_purge_url="${PAGES_PURGE_URL:-$site_url}"
    local purge_secret="${PURGE_SECRET:-}"
    local source_dir="$OUTPUT_DIR"
    
    if [[ -z "$purge_secret" ]] || [[ -z "$site_url" ]]; then
        log "ℹ️  Cloudflare CDN purge skipped (PURGE_SECRET or SITE_URL not configured)"
        return 0
    fi

    site_url="${site_url%/}"
    pages_purge_url="${pages_purge_url%/}"
    if [[ "$site_url" != https://* || "$pages_purge_url" != https://* ]]; then
        log "❌ Cloudflare CDN purge requires HTTPS SITE_URL and PAGES_PURGE_URL"
        return 1
    fi
    if ! command -v jq &>/dev/null; then
        log "❌ Cloudflare CDN purge requires jq for safe URL encoding"
        return 1
    fi

    local purge_endpoint="${pages_purge_url}/_purge"
    
    log "🧹 Purging Cloudflare CDN cache..."
    
    # Purge search-index.json first (must be fresh before any page loads)
    log "   Purging search-index.json..."
    local si_purge_response si_purge_http_code
    si_purge_response=$(curl -s -w "\n%{http_code}" -X POST "$purge_endpoint" \
        -H "X-Purge-Secret: ${purge_secret}" \
        -H "Content-Type: application/json" \
        -d "{\"urls\": [\"${site_url}/search-index.json\"]}" 2>&1 || true)
    si_purge_http_code=$(echo "$si_purge_response" | tail -1)
    if [[ "$si_purge_http_code" != "200" ]]; then
        log "   ⚠️  search-index.json purge returned HTTP $si_purge_http_code"
    fi
    
    # Purge Prometheus metrics (must be fresh for scraping)
    log "   Purging Prometheus metrics..."
    local pm_purge_response pm_purge_http_code
    pm_purge_response=$(curl -s -w "\n%{http_code}" -X POST "$purge_endpoint" \
        -H "X-Purge-Secret: ${purge_secret}" \
        -H "Content-Type: application/json" \
        -d "{\"urls\": [\"${site_url}/metrics\"]}" 2>&1 || true)
    pm_purge_http_code=$(echo "$pm_purge_response" | tail -1)
    if [[ "$pm_purge_http_code" != "200" ]]; then
        log "   ⚠️  Prometheus metrics purge returned HTTP $pm_purge_http_code"
    fi
    
    # Find all HTML files and convert to URL paths
    # Cache keys use directory form (foo/) not file form (foo/index.html)
    local html_files=()
    while IFS= read -r -d '' file; do
        local rel_path="${file#$source_dir/}"
        # Convert index.html paths to directory form for cache key matching
        if [[ "$rel_path" == */index.html ]]; then
            rel_path="${rel_path%index.html}"
        elif [[ "$rel_path" == "index.html" ]]; then
            rel_path=""
        fi
        html_files+=("$rel_path")
    done < <(find "$source_dir" -name "*.html" -type f -print0)
    
    local total_html=${#html_files[@]}
    log "   Found $total_html HTML files to purge"
    
    # Purge in batches of 50
    local batch_size=50
    local progress_interval=2500
    local total_purged=0
    local batch_num=0
    local last_progress=0
    
    for ((i=0; i<total_html; i+=batch_size)); do
        batch_num=$((batch_num + 1))
        local batch=("${html_files[@]:i:batch_size}")
        
        local urls_json
        urls_json=$(jq -cn --arg base "$site_url" --args \
            '$ARGS.positional | map($base + "/" + .)' "${batch[@]}")
        
        local purge_response
        purge_response=$(curl -s -X POST "$purge_endpoint" \
            -H "X-Purge-Secret: ${purge_secret}" \
            -H "Content-Type: application/json" \
            -d "{\"urls\":${urls_json}}" 2>&1)
        
        if echo "$purge_response" | grep -q '"success":true'; then
            local batch_purged
            batch_purged=$(echo "$purge_response" | grep -oE '"purged":[0-9]+' | grep -oE '[0-9]+')
            total_purged=$((total_purged + ${batch_purged:-0}))
        fi
        
        local files_processed=$((i + ${#batch[@]}))
        if (( files_processed - last_progress >= progress_interval )); then
            local percent=$((files_processed * 100 / total_html))
            log "   Progress: $files_processed/$total_html ($percent%) - purged $total_purged"
            last_progress=$files_processed
        fi
    done
    
    log "   ✅ Purged $total_purged of $total_html cached HTML pages"
}

if [[ "${ALLIUM_DEPLOY_TEST_MODE:-}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi

if [[ "$WRANGLER_LOG_PATH" == "$WRANGLER_DEFAULT_LOG_PATH" ]] &&
    ! prepare_null_log_sink "$WRANGLER_LOG_PATH"; then
    log "❌ Could not prepare the bounded Wrangler debug sink"
    exit 1
fi

if ! ALLIUM_UPDATE_LOG_FILE="$ALLIUM_UPDATE_LOG_FILE" \
    ALLIUM_UPDATE_LOG_MAX_BYTES="$ALLIUM_UPDATE_LOG_MAX_BYTES" \
    ALLIUM_UPDATE_LOG_ARCHIVES="$ALLIUM_UPDATE_LOG_ARCHIVES" \
    WRANGLER_LOG_PATH="$WRANGLER_LOG_PATH" \
    WRANGLER_ERROR_LOG_MAX_BYTES="$WRANGLER_ERROR_LOG_MAX_BYTES" \
    WRANGLER_ERROR_LOG_ARCHIVES="$WRANGLER_ERROR_LOG_ARCHIVES" \
    "$SCRIPT_DIR/allium-deploy-maintain-logs.sh"; then
    log "⚠️ Log maintenance failed; continuing the deployment"
fi

export WRANGLER_LOG WRANGLER_LOG_PATH WRANGLER_LOG_SANITIZE

assert_boolean_setting CF_ASSETS_ENABLED "$CF_ASSETS_ENABLED"
assert_boolean_setting CF_ASSETS_REQUIRED "$CF_ASSETS_REQUIRED"
assert_boolean_setting CF_ASSETS_ALLOW_PROMOTION "$CF_ASSETS_ALLOW_PROMOTION"

trap 'record_update_exit $?' EXIT

log "========================================"
log "Starting metrics update..."
log "Storage order: $STORAGE_ORDER"

if [[ ! -f "$ALLIUM_DIR/allium.py" ]]; then
    log "❌ Could not locate allium.py under $ALLIUM_CONFIG_DIR or $ALLIUM_DIR"
    exit 1
fi

# Capture current search-index.json schema version before update (for change detection)
OLD_SCHEMA_VERSION=""
if command -v jq &>/dev/null; then
    OLD_SCHEMA_VERSION=$(run_with_timeout 30 curl -sf "$SITE_URL/search-index.json" 2>/dev/null | jq -r '.meta.version // "unknown"' 2>/dev/null || echo "unknown")
    log "Current search-index schema: v$OLD_SCHEMA_VERSION"
fi

log "Checking guarded auto-pulls..."
guarded_pull_allium_deploy
guarded_pull_allium

# Start background prune (only if less than 3 consecutive failures)
failures=$(get_failures)
if [ "$failures" -lt 3 ]; then
    log "🧹 Starting background prune (parallel with allium)..."
    stdbuf -oL "$SCRIPT_DIR/allium-deploy-prune.sh" &
    PRUNE_PID=$!
else
    log "⚠️ Skipping prune - $failures consecutive failures detected"
    PRUNE_PID=""
fi

# Step 1: Run allium
log "Running allium..."
cd "$ALLIUM_DIR"
if python3 -u allium.py --out "$OUTPUT_DIR" --base-url "$SITE_URL" --progress; then
    log "✅ Allium completed"
else
    log "❌ Allium failed"
    increment_failures
    ROLLBACK_SUCCESS=true
    rollback_guarded_pulls || ROLLBACK_SUCCESS=false
    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true
    if [[ "$ROLLBACK_SUCCESS" != "true" ]]; then
        log "❌ One or more guarded-pull rollbacks failed - manual checkout repair required"
    fi
    exit 1
fi

# Check for schema version change and auto-deploy search.js if needed
if command -v jq &>/dev/null && [[ -f "$OUTPUT_DIR/search-index.json" ]]; then
    NEW_SCHEMA_VERSION=$(jq -r '.meta.version // "unknown"' "$OUTPUT_DIR/search-index.json" 2>/dev/null || echo "unknown")
    
    if [[ "$OLD_SCHEMA_VERSION" != "unknown" ]] && [[ "$NEW_SCHEMA_VERSION" != "unknown" ]] && [[ "$OLD_SCHEMA_VERSION" != "$NEW_SCHEMA_VERSION" ]]; then
        log "⚠️  SEARCH-INDEX SCHEMA CHANGED: v$OLD_SCHEMA_VERSION → v$NEW_SCHEMA_VERSION"
        log "⚠️  Auto-deploying search.js to match new search-index schema..."

        if ! require_current_deploy_checkout; then
            log "❌ search.js auto-deploy skipped - deploy checkout is not safe"
            log "❌ Update/clean $DEPLOY_DIR, then run: $DEPLOY_DIR/scripts/allium-deploy-cfpages.sh"
        elif "$DEPLOY_DIR/scripts/allium-deploy-cfpages.sh" >> "$DEPLOY_DIR/logs/cfpages-deploy.log" 2>&1; then
            log "✅ search.js auto-deployed successfully"
        else
            log "❌ search.js auto-deploy FAILED - manual deploy required!"
            log "❌ Run: $DEPLOY_DIR/scripts/allium-deploy-cfpages.sh"
        fi
    elif [[ "$NEW_SCHEMA_VERSION" != "unknown" ]]; then
        log "Search-index schema: v$NEW_SCHEMA_VERSION (unchanged)"
    fi
fi

# Step 2: Prepare the immutable output overlays before any publisher reads the
# tree, then upload to storage backends and the route-free Workers shadow in
# parallel. Repeated Workers preparation is idempotent and preserves mtimes.
R2_PID=""
DO_PID=""
CF_ASSETS_PID=""
CF_ASSETS_PREPARED=false
CF_ASSETS_PREPARE_EXIT=0

if [[ "$CF_ASSETS_ENABLED" == "true" ]]; then
    log "Preparing Cloudflare Workers Assets overlay and route-free config..."
    if "$SCRIPT_DIR/allium-deploy-cfassets.sh" --generate-only; then
        CF_ASSETS_PREPARED=true
    else
        CF_ASSETS_PREPARE_EXIT=$?
        log "⚠️ Workers Assets preparation failed (exit $CF_ASSETS_PREPARE_EXIT)"
    fi
fi

# Start uploads in parallel (line-buffered for clean interleaving)
UPLOAD_START=$(date +%s)

if [[ "$R2_ENABLED" == "true" ]]; then
    log "🚀 Starting R2 upload..."
    stdbuf -oL "$SCRIPT_DIR/allium-deploy-upload-r2.sh" "$OUTPUT_DIR" &
    R2_PID=$!
fi

if [[ "$DO_ENABLED" == "true" ]]; then
    log "🚀 Starting DO Spaces upload..."
    stdbuf -oL "$SCRIPT_DIR/allium-deploy-upload-do.sh" "$OUTPUT_DIR" &
    DO_PID=$!
fi

if [[ "$CF_ASSETS_PREPARED" == "true" ]]; then
    log "🚀 Starting Cloudflare Workers Assets shadow upload (no production route)..."
    stdbuf -oL "$SCRIPT_DIR/allium-deploy-cfassets.sh" --upload-only &
    CF_ASSETS_PID=$!
fi

# Wait for uploads to complete (capture exit codes without triggering set -e)
UPLOAD_SUCCESS=false

if [[ -n "$R2_PID" ]]; then
    R2_EXIT=0
    wait "$R2_PID" || R2_EXIT=$?
    R2_DURATION=$(($(date +%s) - UPLOAD_START))
    R2_TIME=$(printf '%dm%02ds' $((R2_DURATION/60)) $((R2_DURATION%60)))
    if [[ "$R2_EXIT" == "0" ]]; then
        log "✅ R2 upload completed ($R2_TIME)"
        UPLOAD_SUCCESS=true
    else
        log "⚠️ R2 upload failed (exit $R2_EXIT, $R2_TIME)"
    fi
fi

if [[ -n "$DO_PID" ]]; then
    DO_EXIT=0
    wait "$DO_PID" || DO_EXIT=$?
    DO_DURATION=$(($(date +%s) - UPLOAD_START))
    DO_TIME=$(printf '%dm%02ds' $((DO_DURATION/60)) $((DO_DURATION%60)))
    if [[ "$DO_EXIT" == "0" ]]; then
        log "✅ DO Spaces upload completed ($DO_TIME)"
        UPLOAD_SUCCESS=true
    else
        log "⚠️ DO Spaces upload failed (exit $DO_EXIT, $DO_TIME)"
    fi
fi

CF_ASSETS_EXIT="$CF_ASSETS_PREPARE_EXIT"
if [[ -n "$CF_ASSETS_PID" ]]; then
    wait "$CF_ASSETS_PID" || CF_ASSETS_EXIT=$?
    CF_ASSETS_DURATION=$(($(date +%s) - UPLOAD_START))
    CF_ASSETS_TIME=$(printf '%dm%02ds' $((CF_ASSETS_DURATION/60)) $((CF_ASSETS_DURATION%60)))
    if [[ "$CF_ASSETS_EXIT" == "0" ]]; then
        log "✅ Workers Assets shadow upload and verification completed ($CF_ASSETS_TIME)"
        if [[ "$CF_ASSETS_ALLOW_PROMOTION" == "true" ]]; then
            log "🚀 Promoting verified Workers Assets version to production..."
            if promote_verified_cfassets_if_ready "$CF_ASSETS_EXIT"; then
                log "✅ Workers Assets promotion completed successfully"
            else
                PROMOTE_EXIT=$?
                log "❌ Workers Assets promotion failed (exit $PROMOTE_EXIT)"
                CF_ASSETS_EXIT=$PROMOTE_EXIT
            fi
        fi
    else
        log "⚠️ Workers Assets shadow upload failed (exit $CF_ASSETS_EXIT, $CF_ASSETS_TIME)"
    fi
fi

# Check if at least one upload succeeded
if [[ "$UPLOAD_SUCCESS" == "true" ]]; then
    log "✅ Storage uploads completed"
else
    log "❌ All uploads failed"
    increment_failures
    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true
    exit 1
fi


if [[ "$CF_ASSETS_REQUIRED" == "true" && "$CF_ASSETS_EXIT" != "0" ]]; then
    log "❌ Workers Assets is required but its upload or verification failed"
    increment_failures
    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true
    exit 1
fi

reset_failures

# Step 3: Purge Cloudflare CDN cache (once, after all uploads)
purge_cdn

# Wait for prune to finish
if [[ -n "${PRUNE_PID:-}" ]]; then
    if ps -p "$PRUNE_PID" > /dev/null 2>&1; then
        log "⏳ Waiting for background prune to finish..."
        wait "$PRUNE_PID" 2>/dev/null || true
    fi
fi

log "✅ Done! Site: $SITE_URL"
log "========================================"
