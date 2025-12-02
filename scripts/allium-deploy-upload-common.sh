#!/usr/bin/env bash
# Allium Deploy - Common Upload Functions
# Shared functions for R2 and DO Spaces upload scripts

# --- Logging ---

STORAGE_NAME=""

log() {
    if [[ -n "$STORAGE_NAME" ]]; then
        echo "[$STORAGE_NAME] $1"
    else
        echo "$1"
    fi
}

# --- Configuration ---

setup_common_vars() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
    DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
    
    [[ -f "$DEPLOY_DIR/config.env" ]] && source "$DEPLOY_DIR/config.env"
    
    SOURCE_DIR="${SOURCE_DIR_ARG:-${OUTPUT_DIR:-$HOME/metrics-output}}"
    LOCAL_BACKUP_DIR="${BACKUP_DIR:-$HOME/metrics-backups}"
    RCLONE="${RCLONE_PATH:-$HOME/bin/rclone}"
    TIMESTAMP=$(date '+%Y-%m-%d_%H%M%S')
    TODAY=$(date '+%Y-%m-%d')
    
    LOG_DIR="$DEPLOY_DIR/logs"
    mkdir -p "$LOG_DIR"
    
    # Rclone settings (can be overridden per-backend)
    TRANSFERS="${RCLONE_TRANSFERS:-128}"
    CHECKERS="${RCLONE_CHECKERS:-256}"
    BUFFER_SIZE="${RCLONE_BUFFER_SIZE:-128M}"
    S3_CONCURRENCY="${RCLONE_S3_UPLOAD_CONCURRENCY:-32}"
    S3_CHUNK="${RCLONE_S3_CHUNK_SIZE:-16M}"
    
    DAILY_LOCAL_BACKUP="${DAILY_LOCAL_BACKUP:-true}"
}

build_rclone_opts() {
    echo "--transfers=$TRANSFERS --checkers=$CHECKERS --buffer-size=$BUFFER_SIZE --s3-upload-concurrency=$S3_CONCURRENCY --s3-chunk-size=$S3_CHUNK --fast-list --stats=10s --stats-one-line --log-level=NOTICE --stats-log-level=NOTICE --retries=5 --retries-sleep=2s --low-level-retries=10"
}

# --- Backup Functions ---

backup_needed() {
    local marker_file="$1"
    local daily_setting="$2"
    local force_flag="${3:-false}"
    
    [[ "$force_flag" == "true" ]] && return 0
    [[ "$daily_setting" != "true" ]] && return 0
    
    if [[ -f "$marker_file" ]]; then
        [[ "$(cat "$marker_file" 2>/dev/null)" == "$TODAY" ]] && return 1
    fi
    return 0
}

create_local_backup() {
    local bucket="$1"
    local marker_file="$2"
    local force_flag="${3:-false}"
    local daily_setting="${4:-true}"
    local rclone_opts
    rclone_opts=$(build_rclone_opts)
    
    if backup_needed "$marker_file" "$daily_setting" "$force_flag"; then
        log "📦 Creating local backup..."
        log "   Target: $LOCAL_BACKUP_DIR/backup-$TIMESTAMP"
        mkdir -p "$LOCAL_BACKUP_DIR/backup-$TIMESTAMP"
        $RCLONE sync "$bucket" "$LOCAL_BACKUP_DIR/backup-$TIMESTAMP" --exclude "_backups/**" $rclone_opts 2>&1 | while read -r line; do log "   $line"; done
        echo "$TODAY" > "$marker_file"
        log "   ✅ Local backup created"
        return 0
    else
        log "⏭️  Skipping local backup (already done today: $(cat "$marker_file"))"
        return 1
    fi
}

create_remote_backup() {
    local bucket="$1"
    local marker_file="$2"
    local force_flag="${3:-false}"
    local daily_setting="${4:-true}"
    local rclone_opts
    rclone_opts=$(build_rclone_opts)
    
    if backup_needed "$marker_file" "$daily_setting" "$force_flag"; then
        log "📦 Creating remote backup..."
        log "   Target: $bucket/_backups/$TIMESTAMP"
        $RCLONE sync "$bucket" "$bucket/_backups/$TIMESTAMP" --exclude "_backups/**" $rclone_opts 2>&1 | while read -r line; do log "   $line"; done
        echo "$TODAY" > "$marker_file"
        log "   ✅ Remote backup created"
        return 0
    else
        log "⏭️  Skipping remote backup (already done today: $(cat "$marker_file"))"
        return 1
    fi
}

upload_content() {
    local bucket="$1"
    local rclone_opts
    rclone_opts=$(build_rclone_opts)
    
    log "🚀 Uploading content (incremental sync)..."
    log "   Source: $SOURCE_DIR"
    log "   Target: $bucket"
    $RCLONE sync "$SOURCE_DIR" "$bucket" --exclude "_backups/**" $rclone_opts 2>&1 | while read -r line; do log "   $line"; done
    log "   ✅ Upload complete"
}

# --- Utilities ---

print_sync_summary() {
    log "✅ Sync complete!"
}

list_backups() {
    local bucket="$1"
    local local_marker="$2"
    local remote_marker="$3"
    local storage_name="$4"
    
    echo "📦 Local backups:"
    ls -1dt "$LOCAL_BACKUP_DIR"/backup-* 2>/dev/null | head -5 || echo "   (none)"
    echo ""
    echo "📦 $storage_name backups:"
    $RCLONE lsf "$bucket/_backups/" --dirs-only 2>/dev/null | sort -r | head -5 || echo "   (none)"
    echo ""
    echo "📅 Last local backup: $(cat "$local_marker" 2>/dev/null || echo "never")"
    echo "📅 Last $storage_name backup: $(cat "$remote_marker" 2>/dev/null || echo "never")"
}

print_help() {
    local script_name="$1"
    local storage_name="$2"
    
    cat <<EOF
Usage: $script_name [source_dir]
       $script_name --list-backups
       $script_name --force-backup [source_dir]

Options:
  --list-backups   List available local and remote backups
  --force-backup   Force both local and remote backups even if done today

Rollback from local backup:
  $script_name ~/metrics-backups/backup-YYYY-MM-DD_HHMMSS

Rollback from $storage_name backup:
  rclone sync remote:bucket/_backups/YYYY-MM-DD_HHMMSS ~/metrics-output
  $script_name
EOF
}
