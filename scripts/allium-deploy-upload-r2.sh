#!/usr/bin/env bash
# Allium Deploy - Upload to Cloudflare R2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/allium-deploy-upload-common.sh"

# Parse arguments
SOURCE_DIR_ARG=""
FORCE_BACKUP=false
FORCE_CONTENT_SYNC=false
case "${1:-}" in
    --force-backup)
        FORCE_BACKUP=true
        SOURCE_DIR_ARG="${2:-}"
        ;;
    --force-content-sync)
        FORCE_CONTENT_SYNC=true
        SOURCE_DIR_ARG="${2:-}"
        ;;
    --list-backups|--help|-h) ;;
    *) SOURCE_DIR_ARG="${1:-}" ;;
esac

setup_common_vars
STORAGE_NAME="R2"

# R2 configuration
R2_BUCKET_NAME="${R2_BUCKET:?R2_BUCKET must be set in config.env}"
BUCKET="r2-metrics:${R2_BUCKET_NAME}"

LOCAL_BACKUP_MARKER="$LOG_DIR/last-local-backup-date"
R2_BACKUP_MARKER="$LOG_DIR/last-r2-backup-date"
DAILY_R2_BACKUP="${DAILY_R2_BACKUP:-true}"
R2_CONTENT_SYNC_INTERVAL="${R2_CONTENT_SYNC_INTERVAL:-every-build}"
R2_CONTENT_SYNC_MARKER="${R2_CONTENT_SYNC_MARKER:-$LOG_DIR/last-r2-content-sync-date}"
R2_CONTENT_VERIFY_PATHS="${R2_CONTENT_VERIFY_PATHS:-index.html,search-index.json,1aeo.com/index.html}"
R2_CONTENT_SYNC_TODAY="$(date -u '+%Y-%m-%d')"

validate_content_sync_interval() {
    case "$R2_CONTENT_SYNC_INTERVAL" in
        every-build|daily) return 0 ;;
        *)
            echo "❌ Error: R2_CONTENT_SYNC_INTERVAL must be every-build or daily (got: $R2_CONTENT_SYNC_INTERVAL)" >&2
            return 2
            ;;
    esac
}

content_sync_needed() {
    [[ "$FORCE_CONTENT_SYNC" == "true" ]] && return 0
    [[ "$R2_CONTENT_SYNC_INTERVAL" == "every-build" ]] && return 0

    if [[ -f "$R2_CONTENT_SYNC_MARKER" ]] &&
        [[ "$(cat "$R2_CONTENT_SYNC_MARKER" 2>/dev/null)" == "$R2_CONTENT_SYNC_TODAY" ]]; then
        return 1
    fi
    return 0
}

parse_size_stats() {
    local payload="$1"
    local label="$2"
    local stats

    if ! stats=$(jq -er '[.count, .bytes] | @tsv' <<< "$payload"); then
        log "❌ Could not parse $label object count and byte size" >&2
        return 1
    fi
    if [[ ! "$stats" =~ ^[0-9]+$'\t'[0-9]+$ ]]; then
        log "❌ Invalid $label object count and byte size: $stats" >&2
        return 1
    fi
    printf '%s\n' "$stats"
}

verify_r2_content() {
    local source_payload remote_payload source_stats remote_stats
    local source_count source_bytes remote_count remote_bytes
    local verify_path local_hash remote_hash verified_paths=0
    local -a verify_paths
    local -a size_filters=(--exclude "_backups/**" --exclude "_headers")

    if ! command -v jq >/dev/null 2>&1; then
        log "❌ jq is required for R2 content verification"
        return 1
    fi
    if ! command -v sha256sum >/dev/null 2>&1; then
        log "❌ sha256sum is required for R2 content verification"
        return 1
    fi

    log "🔎 Verifying R2 live content..."
    if ! source_payload=$($RCLONE size "$SOURCE_DIR" "${size_filters[@]}" --json --log-level ERROR); then
        log "❌ Could not measure generated output"
        return 1
    fi
    if ! remote_payload=$($RCLONE size "$BUCKET" "${size_filters[@]}" --json --log-level ERROR); then
        log "❌ Could not measure R2 live content"
        return 1
    fi
    source_stats=$(parse_size_stats "$source_payload" "generated-output") || return 1
    remote_stats=$(parse_size_stats "$remote_payload" "R2") || return 1
    IFS=$'\t' read -r source_count source_bytes <<< "$source_stats"
    IFS=$'\t' read -r remote_count remote_bytes <<< "$remote_stats"

    if [[ "$source_count" != "$remote_count" ]] || [[ "$source_bytes" != "$remote_bytes" ]]; then
        log "❌ R2 size mismatch: source=${source_count} objects/${source_bytes} bytes, remote=${remote_count} objects/${remote_bytes} bytes"
        return 1
    fi
    log "   ✅ Object count and bytes match ($source_count objects, $source_bytes bytes)"

    if [[ -z "$R2_CONTENT_VERIFY_PATHS" ]] || [[ "$R2_CONTENT_VERIFY_PATHS" == ,* ]] ||
        [[ "$R2_CONTENT_VERIFY_PATHS" == *, ]] || [[ "$R2_CONTENT_VERIFY_PATHS" == *,,* ]]; then
        log "❌ R2 content verification paths contain an empty entry"
        return 1
    fi
    IFS=',' read -r -a verify_paths <<< "$R2_CONTENT_VERIFY_PATHS"
    for verify_path in "${verify_paths[@]}"; do
        verify_path="${verify_path#"${verify_path%%[![:space:]]*}"}"
        verify_path="${verify_path%"${verify_path##*[![:space:]]}"}"
        if [[ -z "$verify_path" ]] || [[ "$verify_path" == /* ]] ||
            [[ "$verify_path" == ".." ]] || [[ "$verify_path" == ../* ]] ||
            [[ "$verify_path" == */../* ]] || [[ "$verify_path" == */.. ]]; then
            log "❌ Invalid R2 representative path: ${verify_path:-<empty>}"
            return 1
        fi
        if [[ ! -f "$SOURCE_DIR/$verify_path" ]]; then
            log "❌ Representative source file is missing: $verify_path"
            return 1
        fi

        local_hash=$(sha256sum "$SOURCE_DIR/$verify_path" | awk '{print $1}')
        if ! remote_hash=$($RCLONE cat "$BUCKET/$verify_path" --log-level ERROR | sha256sum | awk '{print $1}'); then
            log "❌ Could not hash R2 representative object: $verify_path"
            return 1
        fi
        if [[ "$local_hash" != "$remote_hash" ]]; then
            log "❌ R2 representative hash mismatch: $verify_path"
            return 1
        fi
        log "   ✅ Representative hash matches: $verify_path"
        verified_paths=$((verified_paths + 1))
    done

    if (( verified_paths == 0 )); then
        log "❌ R2 content verification requires at least one representative path"
        return 1
    fi
    log "   ✅ R2 live content verification passed"
}

write_content_sync_marker() {
    local marker_dir marker_tmp

    marker_dir=$(dirname "$R2_CONTENT_SYNC_MARKER")
    marker_tmp="${R2_CONTENT_SYNC_MARKER}.tmp.$$"
    mkdir -p "$marker_dir"
    if ! printf '%s\n' "$R2_CONTENT_SYNC_TODAY" > "$marker_tmp" ||
        ! mv "$marker_tmp" "$R2_CONTENT_SYNC_MARKER"; then
        rm -f "$marker_tmp"
        log "❌ Could not record successful R2 content synchronization"
        return 1
    fi
}

print_r2_help() {
    cat <<EOF
Usage: $0 [source_dir]
       $0 --force-content-sync [source_dir]
       $0 --list-backups
       $0 --force-backup [source_dir]

Options:
  --force-content-sync  Synchronize and verify live R2 content even if today's
                        daily success marker already exists
  --list-backups        List available local and remote backups
  --force-backup        Force both local and remote backups even if done today

R2_CONTENT_SYNC_INTERVAL accepts every-build (the safe default) or daily.
Daily mode retries every invocation until upload and verification both pass.
EOF
}

ensure_r2_remote() {
    local r2_key="${R2_ACCESS_KEY_ID:-}"
    local r2_secret="${R2_SECRET_ACCESS_KEY:-}"
    local cf_account="${CLOUDFLARE_ACCOUNT_ID:-}"
    
    if [[ -z "$r2_key" ]] || [[ -z "$r2_secret" ]]; then
        echo "❌ Error: R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY must be set in config.env"
        exit 1
    fi
    
    if ! $RCLONE listremotes 2>/dev/null | grep -q "^r2-metrics:$"; then
        echo "📦 Configuring rclone 'r2-metrics' remote..."
        $RCLONE config create r2-metrics s3 \
            provider=Cloudflare \
            access_key_id="$r2_key" \
            secret_access_key="$r2_secret" \
            endpoint="https://${cf_account}.r2.cloudflarestorage.com" \
            acl=private \
            --non-interactive
        echo "   ✅ Remote 'r2-metrics' configured"
    fi
}

# Handle arguments
case "${1:-}" in
    --list-backups)
        ensure_r2_remote
        list_backups "$BUCKET" "$LOCAL_BACKUP_MARKER" "$R2_BACKUP_MARKER" "R2"
        exit 0
        ;;
    --force-backup|--force-content-sync) ;;
    --help|-h)
        print_r2_help
        exit 0
        ;;
esac

[[ ! -d "$SOURCE_DIR" ]] && { echo "❌ Error: Source directory not found: $SOURCE_DIR"; exit 1; }
validate_content_sync_interval

ensure_r2_remote

log "☁️  Cloudflare R2 Upload"
log "   Bucket: $R2_BUCKET_NAME"
log "   Parallel: $TRANSFERS transfers, $CHECKERS checkers"

create_local_backup "$BUCKET" "$LOCAL_BACKUP_MARKER" "$FORCE_BACKUP" "$DAILY_LOCAL_BACKUP" || true
create_remote_backup "$BUCKET" "$R2_BACKUP_MARKER" "$FORCE_BACKUP" "$DAILY_R2_BACKUP" || true

if content_sync_needed; then
    if [[ "$FORCE_CONTENT_SYNC" == "true" ]]; then
        log "🔁 Forcing R2 live content synchronization"
    else
        log "📅 R2 live content synchronization is due ($R2_CONTENT_SYNC_INTERVAL)"
    fi
    upload_content "$BUCKET"

    if [[ "$R2_CONTENT_SYNC_INTERVAL" == "daily" ]] || [[ "$FORCE_CONTENT_SYNC" == "true" ]]; then
        verify_r2_content
        write_content_sync_marker
        log "   ✅ Recorded R2 live content synchronization for $R2_CONTENT_SYNC_TODAY UTC"
    fi
else
    log "⏭️  Skipping R2 live content sync (already verified today: $(cat "$R2_CONTENT_SYNC_MARKER"))"
fi
print_sync_summary
