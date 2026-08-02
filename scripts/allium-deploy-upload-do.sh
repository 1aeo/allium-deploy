#!/usr/bin/env bash
# Allium Deploy - Upload to DigitalOcean Spaces
#
# Note: DO Spaces CDN does NOT support cache invalidation/purging.
# Set DO_SPACES_CDN=true to use CDN (faster, up to 1hr stale)
# Set DO_SPACES_CDN=false to use origin (always fresh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/allium-deploy-upload-common.sh"

# Parse arguments
SOURCE_DIR_ARG=""
FORCE_BACKUP=false
REMOTE_BACKUP_ONLY=false
case "${1:-}" in
    --list-backups|--force-backup|--remote-backup-only|--help|-h) ;;
    *) SOURCE_DIR_ARG="${1:-}" ;;
esac

setup_common_vars
STORAGE_NAME="DO-Spaces"

# Override parallelism for DO Spaces (lower to avoid 503 rate limiting)
TRANSFERS="${DO_RCLONE_TRANSFERS:-56}"
CHECKERS="${DO_RCLONE_CHECKERS:-80}"
# A full Allium build replaces roughly 29,000 small objects. Limit aggregate
# HTTP operations so the PUT/HEAD/check burst stays below DigitalOcean's
# request-rate optimization threshold while retaining enough workers to keep
# the pipeline full. This does not disable rclone's post-upload integrity HEAD.
TPS_LIMIT="${DO_RCLONE_TPS_LIMIT:-120}"
TPS_LIMIT_BURST="${DO_RCLONE_TPS_LIMIT_BURST:-1}"
# DigitalOcean recommends several small parallel connections. Avoid placing all
# 56 transfer workers behind one long-lived HTTP/2 session, whose observed
# throughput can collapse while the host itself remains idle.
S3_DISABLE_HTTP2="${DO_RCLONE_DISABLE_HTTP2:-true}"
# The retained _backups tree is much larger than the hot mirror. Disabling
# ListR lets rclone prune that excluded directory instead of recursively
# enumerating every retained backup object on each scheduled sync.
RCLONE_FAST_LIST="${DO_RCLONE_FAST_LIST:-false}"

# DO Spaces configuration
DO_REGION="${DO_SPACES_REGION:-nyc3}"
DO_BUCKET_NAME="${DO_SPACES_BUCKET:?DO_SPACES_BUCKET must be set in config.env}"
BUCKET="spaces-metrics:${DO_BUCKET_NAME}"
DO_USE_CDN="${DO_SPACES_CDN:-false}"

LOCAL_BACKUP_MARKER="${DO_LOCAL_BACKUP_MARKER:-$LOG_DIR/last-do-local-backup-date}"
DO_BACKUP_MARKER="${DO_REMOTE_BACKUP_MARKER:-$LOG_DIR/last-do-backup-date}"
DAILY_DO_BACKUP="${DAILY_DO_BACKUP:-true}"
DO_REMOTE_BACKUP_INLINE="${DO_REMOTE_BACKUP_INLINE:-true}"
DO_IO_LOCK_FILE="${DO_IO_LOCK_FILE:-/tmp/allium-do-spaces-io.lock}"
DO_IO_LOCK_WAIT_SECONDS="${DO_IO_LOCK_WAIT_SECONDS:-180}"

validate_do_coordination_settings() {
    case "$DO_REMOTE_BACKUP_INLINE" in
        true|false) ;;
        *)
            log "❌ DO_REMOTE_BACKUP_INLINE must be true or false (got: $DO_REMOTE_BACKUP_INLINE)"
            return 2
            ;;
    esac
    [[ "$DO_IO_LOCK_WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] || {
        log "❌ DO_IO_LOCK_WAIT_SECONDS must be a positive integer (got: $DO_IO_LOCK_WAIT_SECONDS)"
        return 2
    }
    [[ "$DO_IO_LOCK_FILE" == /tmp/* && "$DO_IO_LOCK_FILE" != /tmp/ ]] || {
        log "❌ DO_IO_LOCK_FILE must be one explicit file below /tmp"
        return 2
    }
    command -v flock >/dev/null 2>&1 || {
        log "❌ flock is required for DO live/backup serialization"
        return 2
    }
}

run_with_do_io_lock() {
    local status=0
    exec 8>"$DO_IO_LOCK_FILE"
    if ! flock -w "$DO_IO_LOCK_WAIT_SECONDS" 8; then
        log "❌ Timed out after ${DO_IO_LOCK_WAIT_SECONDS}s waiting for DO I/O lock"
        exec 8>&-
        return 1
    fi
    "$@" || status=$?
    flock -u 8
    exec 8>&-
    return "$status"
}

ensure_spaces_remote() {
    local do_key="${DO_SPACES_KEY:-}"
    local do_secret="${DO_SPACES_SECRET:-}"
    
    if [[ -z "$do_key" ]] || [[ -z "$do_secret" ]]; then
        echo "❌ Error: DO_SPACES_KEY and DO_SPACES_SECRET must be set in config.env"
        exit 1
    fi
    
    if ! $RCLONE listremotes 2>/dev/null | grep -q "^spaces-metrics:$"; then
        echo "📦 Configuring rclone 'spaces-metrics' remote..."
        $RCLONE config create spaces-metrics s3 \
            provider=DigitalOcean \
            access_key_id="$do_key" \
            secret_access_key="$do_secret" \
            endpoint="${DO_REGION}.digitaloceanspaces.com" \
            acl=public-read \
            no_check_bucket=true \
            --non-interactive
        echo "   ✅ Remote 'spaces-metrics' configured"
    else
        $RCLONE config update spaces-metrics no_check_bucket=true --non-interactive 2>/dev/null || true
    fi
}

# Handle arguments
case "${1:-}" in
    --list-backups)
        ensure_spaces_remote
        list_backups "$BUCKET" "$LOCAL_BACKUP_MARKER" "$DO_BACKUP_MARKER" "DO Spaces"
        exit 0
        ;;
    --force-backup)
        FORCE_BACKUP=true
        SOURCE_DIR_ARG="${2:-}"
        setup_common_vars
        ;;
    --remote-backup-only)
        REMOTE_BACKUP_ONLY=true
        ;;
    --help|-h)
        print_help "$0" "DO Spaces"
        exit 0
        ;;
esac

[[ ! -d "$SOURCE_DIR" ]] && { echo "❌ Error: Source directory not found: $SOURCE_DIR"; exit 1; }

ensure_spaces_remote
validate_do_coordination_settings

if [[ "$REMOTE_BACKUP_ONLY" == "true" ]]; then
    STORAGE_NAME="DO-Backup"
    TRANSFERS="${DO_REMOTE_BACKUP_TRANSFERS:-16}"
    CHECKERS="${DO_REMOTE_BACKUP_CHECKERS:-32}"
    TPS_LIMIT="${DO_REMOTE_BACKUP_TPS_LIMIT:-30}"
    TPS_LIMIT_BURST="${DO_REMOTE_BACKUP_TPS_LIMIT_BURST:-1}"

    log "📦 DigitalOcean remote backup"
    log "   Transaction rate: $TPS_LIMIT operations/second, burst $TPS_LIMIT_BURST"
    if backup_needed "$DO_BACKUP_MARKER" "$DAILY_DO_BACKUP" false; then
        run_with_do_io_lock create_remote_backup \
            "$BUCKET" "$DO_BACKUP_MARKER" false "$DAILY_DO_BACKUP"
    else
        log "⏭️  Remote backup already completed today: $(cat "$DO_BACKUP_MARKER")"
    fi
    print_sync_summary
    exit 0
fi

log "🌊 DigitalOcean Spaces Upload"
log "   Bucket: $DO_BUCKET_NAME ($DO_REGION)"
log "   Parallel: $TRANSFERS transfers, $CHECKERS checkers"
log "   Transaction rate: $TPS_LIMIT operations/second, burst $TPS_LIMIT_BURST"
log "   S3 HTTP/2 disabled: $S3_DISABLE_HTTP2"
if [[ "$DO_USE_CDN" == "true" ]]; then
    log "   Mode: CDN (faster, may cache up to 1hr)"
else
    log "   Mode: Origin (always fresh)"
fi

create_local_backup "$BUCKET" "$LOCAL_BACKUP_MARKER" "$FORCE_BACKUP" "$DAILY_LOCAL_BACKUP" || true
if [[ "$DO_REMOTE_BACKUP_INLINE" == "true" ]]; then
    run_with_do_io_lock create_remote_backup \
        "$BUCKET" "$DO_BACKUP_MARKER" "$FORCE_BACKUP" "$DAILY_DO_BACKUP" || true
else
    log "⏭️  DO remote backup is handled by the independent retry runner"
fi
run_with_do_io_lock upload_content "$BUCKET"
print_sync_summary
