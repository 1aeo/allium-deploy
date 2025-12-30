#!/usr/bin/env bash
# Allium Deploy - Update Metrics
# Runs allium to generate site, uploads to configured storage backends, prunes old backups
# Cron: */30 * * * * /path/to/allium-deploy-update.sh >> /path/to/logs/update.log 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    source "$DEPLOY_DIR/config.env"
else
    echo "Error: config.env not found"
    exit 1
fi

ALLIUM_DIR="${ALLIUM_DIR:-$HOME/allium}/allium"
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/metrics-output}"
SITE_URL="${SITE_URL:-https://metrics.example.com}"
CONSECUTIVE_FAILURES_FILE="/tmp/allium-deploy-failures"

# Storage configuration
STORAGE_ORDER="${STORAGE_ORDER:-r2,do,failover}"
R2_ENABLED="${R2_ENABLED:-true}"
DO_ENABLED="${DO_ENABLED:-false}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
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

# Cloudflare CDN purge (runs once after all uploads)
purge_cdn() {
    local site_url="${SITE_URL:-}"
    local purge_secret="${PURGE_SECRET:-}"
    local source_dir="$OUTPUT_DIR"
    
    if [[ -z "$purge_secret" ]] || [[ -z "$site_url" ]]; then
        log "ℹ️  Cloudflare CDN purge skipped (PURGE_SECRET or SITE_URL not configured)"
        return 0
    fi
    
    log "🧹 Purging Cloudflare CDN cache..."
    
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
        urls_json=$(printf '"%s",' "${batch[@]}" | sed 's/,$//')
        
        local purge_response
        purge_response=$(curl -s -X POST "${site_url}/_purge" \
            -H "X-Purge-Secret: ${purge_secret}" \
            -H "Content-Type: application/json" \
            -d "{\"urls\": [${urls_json}]}" 2>&1)
        
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

log "========================================"
log "Starting metrics update..."
log "Storage order: $STORAGE_ORDER"

# Capture current search-index.json schema version before update (for change detection)
OLD_SCHEMA_VERSION=""
if command -v jq &>/dev/null; then
    OLD_SCHEMA_VERSION=$(curl -sf "$SITE_URL/search-index.json" 2>/dev/null | jq -r '.meta.version // "unknown"' 2>/dev/null || echo "unknown")
    log "Current search-index schema: v$OLD_SCHEMA_VERSION"
fi

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
    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true
    exit 1
fi

# Check for schema version change and auto-deploy search.js if needed
if command -v jq &>/dev/null && [[ -f "$OUTPUT_DIR/search-index.json" ]]; then
    NEW_SCHEMA_VERSION=$(jq -r '.meta.version // "unknown"' "$OUTPUT_DIR/search-index.json" 2>/dev/null || echo "unknown")
    
    if [[ "$OLD_SCHEMA_VERSION" != "unknown" ]] && [[ "$NEW_SCHEMA_VERSION" != "unknown" ]] && [[ "$OLD_SCHEMA_VERSION" != "$NEW_SCHEMA_VERSION" ]]; then
        log "⚠️  SEARCH-INDEX SCHEMA CHANGED: v$OLD_SCHEMA_VERSION → v$NEW_SCHEMA_VERSION"
        log "⚠️  Auto-deploying search.js to match new search-index schema..."
        
        if "$DEPLOY_DIR/scripts/allium-deploy-cfpages.sh" >> "$DEPLOY_DIR/logs/cfpages-deploy.log" 2>&1; then
            log "✅ search.js auto-deployed successfully"
        else
            log "❌ search.js auto-deploy FAILED - manual deploy required!"
            log "❌ Run: $DEPLOY_DIR/scripts/allium-deploy-cfpages.sh"
        fi
    elif [[ "$NEW_SCHEMA_VERSION" != "unknown" ]]; then
        log "Search-index schema: v$NEW_SCHEMA_VERSION (unchanged)"
    fi
fi

# Step 2: Upload to storage backends (parallel)
R2_PID=""
DO_PID=""

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

# Check if at least one upload succeeded
if [[ "$UPLOAD_SUCCESS" == "true" ]]; then
    log "✅ Storage uploads completed"
    reset_failures
else
    log "❌ All uploads failed"
    increment_failures
    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true
    exit 1
fi

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
