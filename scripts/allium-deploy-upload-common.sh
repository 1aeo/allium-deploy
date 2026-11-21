#!/usr/bin/env bash
# Allium Deploy - Common Upload Functions
# Shared functions for R2 and DO Spaces upload scripts

# --- Logging ---

STORAGE_NAME=""
SKIP_LOCAL_BACKUP="${SKIP_LOCAL_BACKUP:-false}"
_LOCAL_BACKUP_STAGING=""
_LOCAL_BACKUP_LOCK_OPEN=false

log() {
    if [[ -n "$STORAGE_NAME" ]]; then
        echo "[$STORAGE_NAME] $1"
    else
        echo "$1"
    fi
}

cleanup_local_backup_staging() {
    if [[ -n "${_LOCAL_BACKUP_STAGING:-}" && -d "$_LOCAL_BACKUP_STAGING" ]]; then
        rm -rf -- "$_LOCAL_BACKUP_STAGING" 2>/dev/null || true
    fi
    _LOCAL_BACKUP_STAGING=""
    if [[ "${_LOCAL_BACKUP_LOCK_OPEN:-false}" == "true" ]]; then
        exec 7>&- 2>/dev/null || true
        _LOCAL_BACKUP_LOCK_OPEN=false
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

    LOCAL_BACKUP_LOCK_FILE="${LOCAL_BACKUP_LOCK_FILE:-$LOG_DIR/.local-backup.lock}"
    SKIP_LOCAL_BACKUP="${SKIP_LOCAL_BACKUP:-false}"
    
    # Rclone settings (can be overridden per-backend)
    TRANSFERS="${RCLONE_TRANSFERS:-128}"
    CHECKERS="${RCLONE_CHECKERS:-256}"
    BUFFER_SIZE="${RCLONE_BUFFER_SIZE:-128M}"
    S3_CONCURRENCY="${RCLONE_S3_UPLOAD_CONCURRENCY:-32}"
    S3_CHUNK="${RCLONE_S3_CHUNK_SIZE:-16M}"
    RCLONE_FAST_LIST="${RCLONE_FAST_LIST:-true}"
    RCLONE_CHECKSUM="${RCLONE_CHECKSUM:-false}"
    TPS_LIMIT="${RCLONE_TPS_LIMIT:-0}"
    TPS_LIMIT_BURST="${RCLONE_TPS_LIMIT_BURST:-1}"
    S3_DISABLE_HTTP2="${RCLONE_S3_DISABLE_HTTP2:-false}"
    # Only the DO live sync skips the post-upload HEAD (DO_RCLONE_NO_HEAD).
    S3_NO_HEAD=false
}

# build_rclone_opts [root|subtree]: options for a sync whose source is the
# output root (the default) or one of its top-level directories.
build_rclone_opts() {
    local scope="${1:-root}"
    local control_excludes="--exclude=/.assetsignore --exclude=/_redirects"
    local fast_list_opt=""
    local checksum_opt=""
    local s3_http2_opt=""
    local s3_no_head_opt=""

    case "$RCLONE_FAST_LIST" in
        true) fast_list_opt="--fast-list" ;;
        false) ;;
        *)
            echo "RCLONE_FAST_LIST must be true or false (got: $RCLONE_FAST_LIST)" >&2
            return 2
            ;;
    esac

    # --checksum compares size plus the MD5 that S3 listings already carry as
    # the ETag of single-part objects, instead of reading each object's mtime
    # metadata with a HEAD request.
    case "${RCLONE_CHECKSUM:-false}" in
        true) checksum_opt="--checksum" ;;
        false) ;;
        *)
            echo "RCLONE_CHECKSUM must be true or false (got: $RCLONE_CHECKSUM)" >&2
            return 2
            ;;
    esac

    if [[ ! "$TPS_LIMIT" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]]; then
        echo "RCLONE_TPS_LIMIT must be a non-negative number (got: $TPS_LIMIT)" >&2
        return 2
    fi
    if [[ ! "$TPS_LIMIT_BURST" =~ ^[1-9][0-9]*$ ]]; then
        echo "RCLONE_TPS_LIMIT_BURST must be a positive integer (got: $TPS_LIMIT_BURST)" >&2
        return 2
    fi
    case "$S3_DISABLE_HTTP2" in
        true) s3_http2_opt="--s3-disable-http2" ;;
        false) ;;
        *)
            echo "RCLONE_S3_DISABLE_HTTP2 must be true or false (got: $S3_DISABLE_HTTP2)" >&2
            return 2
            ;;
    esac

    # --s3-no-head skips the HEAD that reads each uploaded object's size and
    # ETag back. --checksum must stay on: the next sync's size and MD5
    # comparison is what then re-checks every uploaded object.
    case "${S3_NO_HEAD:-false}" in
        true)
            if [[ -z "$checksum_opt" ]]; then
                echo "DO_RCLONE_NO_HEAD=true requires DO_RCLONE_CHECKSUM=true (the checksum comparison re-checks each upload)" >&2
                return 2
            fi
            s3_no_head_opt="--s3-no-head"
            ;;
        false) ;;
        *)
            echo "DO_RCLONE_NO_HEAD must be true or false (got: $S3_NO_HEAD)" >&2
            return 2
            ;;
    esac

    # _headers, _redirects and .assetsignore control Workers Static Assets and
    # Wrangler and must not become objects in the DO or R2 mirrors. Wrangler
    # reads .assetsignore and _redirects only at the root of the assets
    # directory, so only those copies are excluded: anchored to the root, and
    # left out of passes whose source is a subdirectory, where a file of that
    # name is ordinary content. The R2 size check excludes the same files.
    case "$scope" in
        root) ;;
        subtree) control_excludes="" ;;
        *)
            echo "build_rclone_opts: unknown scope '$scope'" >&2
            return 2
            ;;
    esac
    echo "--transfers=$TRANSFERS --checkers=$CHECKERS --buffer-size=$BUFFER_SIZE --s3-upload-concurrency=$S3_CONCURRENCY --s3-chunk-size=$S3_CHUNK --tpslimit=$TPS_LIMIT --tpslimit-burst=$TPS_LIMIT_BURST $s3_http2_opt $fast_list_opt $checksum_opt $s3_no_head_opt --exclude=_headers $control_excludes --stats=10s --stats-one-line --log-level=NOTICE --stats-log-level=NOTICE --retries=5 --retries-sleep=2s --low-level-retries=10"
}

# --- Backup Functions ---

# Each backup runs daily (once per day, gated by its date marker), every-run
# or off. Usage: resolve_backup_frequency LOCAL_BACKUP_FREQUENCY DAILY_LOCAL_BACKUP
# sets the first variable. While it is unset the older boolean still applies:
# true means daily and false means every-run, never off. Notices go to stdout;
# an invalid value is reported on stderr and returns 2 before any rclone call.
resolve_backup_frequency() {
    local name="$1"
    local legacy_name="$2"
    local value="${!name:-}"
    local legacy="${!legacy_name:-}"
    local legacy_value=""

    case "$legacy" in
        true) legacy_value=daily ;;
        false) legacy_value=every-run ;;
    esac

    if [[ -n "$value" ]]; then
        case "$value" in
            daily|every-run|off) ;;
            *)
                log "❌ $name must be daily, every-run or off (got: $value)" >&2
                return 2
                ;;
        esac
        if [[ -n "$legacy" && -z "$legacy_value" ]]; then
            log "❌ $legacy_name must be true or false (got: $legacy); remove it now that $name is set" >&2
            return 2
        fi
        if [[ -n "$legacy" && "$legacy_value" != "$value" ]]; then
            log "⚠️  $legacy_name=$legacy is ignored; $name=$value takes precedence"
        fi
    elif [[ -n "$legacy" ]]; then
        if [[ -z "$legacy_value" ]]; then
            log "❌ $legacy_name must be true or false (got: $legacy); set $name=daily, every-run or off instead" >&2
            return 2
        fi
        value="$legacy_value"
        log "ℹ️  $legacy_name is deprecated; set $name=$value instead (same behavior)"
    else
        value=daily
    fi
    printf -v "$name" '%s' "$value"
}

backup_needed() {
    local marker_file="$1"
    local frequency="$2"
    local force_flag="${3:-false}"
    
    # An explicit --force-backup is a deliberate manual request, so it also
    # runs a backup whose frequency is off.
    [[ "$force_flag" == "true" ]] && return 0
    case "$frequency" in
        every-run) return 0 ;;
        daily) ;;
        *) return 1 ;;
    esac
    
    if [[ -f "$marker_file" ]]; then
        [[ "$(cat "$marker_file" 2>/dev/null)" == "$TODAY" ]] && return 1
    fi
    return 0
}

write_marker_atomically() {
    local marker_file="$1"
    local value="$2"
    local marker_dir tmp_file

    marker_dir=$(dirname "$marker_file")
    mkdir -p "$marker_dir"
    tmp_file="${marker_file}.tmp.$$"
    if ! printf '%s\n' "$value" > "$tmp_file" || ! mv -f -- "$tmp_file" "$marker_file"; then
        rm -f -- "$tmp_file"
        log "   ❌ Failed to write marker file: $marker_file"
        return 1
    fi
}

_release_local_backup_lock() {
    if [[ "${_LOCAL_BACKUP_LOCK_OPEN:-false}" == "true" ]]; then
        exec 7>&- 2>/dev/null || true
        _LOCAL_BACKUP_LOCK_OPEN=false
    fi
}

create_local_backup() {
    local bucket="$1"
    local marker_file="$2"
    local force_flag="${3:-false}"
    local frequency="${4:-daily}"
    local rclone_opts staging_dir final_dir
    local status=0
    rclone_opts=$(build_rclone_opts root)

    if [[ "${SKIP_LOCAL_BACKUP:-false}" == "true" && "$force_flag" != "true" ]]; then
        log "⏭️  Skipping local backup (handled by primary storage backend)"
        return 1
    fi

    if ! backup_needed "$marker_file" "$frequency" "$force_flag"; then
        if [[ "$frequency" == "off" ]]; then
            log "⏭️  Skipping local backup (frequency is off)"
        else
            log "⏭️  Skipping local backup (already done today: $(cat "$marker_file"))"
        fi
        return 1
    fi

    if command -v flock >/dev/null 2>&1; then
        mkdir -p "$(dirname "$LOCAL_BACKUP_LOCK_FILE")"
        exec 7>"$LOCAL_BACKUP_LOCK_FILE"
        _LOCAL_BACKUP_LOCK_OPEN=true
        if ! flock -n 7; then
            _release_local_backup_lock
            log "⏭️  Skipping local backup (another local backup is already in progress)"
            return 1
        fi
        # Re-check after acquiring lock in case a concurrent process just completed.
        if ! backup_needed "$marker_file" "$frequency" "$force_flag"; then
            _release_local_backup_lock
            log "⏭️  Skipping local backup (already done today: $(cat "$marker_file"))"
            return 1
        fi
    fi

    mkdir -p "$LOCAL_BACKUP_DIR"
    staging_dir="$LOCAL_BACKUP_DIR/backup-${TIMESTAMP}.tmp.$$"
    final_dir="$LOCAL_BACKUP_DIR/backup-$TIMESTAMP"
    if [[ -e "$final_dir" ]]; then
        final_dir="$LOCAL_BACKUP_DIR/backup-${TIMESTAMP}-$$"
    fi

    rm -rf -- "$staging_dir"
    mkdir -p "$staging_dir"
    _LOCAL_BACKUP_STAGING="$staging_dir"

    log "📦 Creating local backup..."
    log "   Target: $final_dir"
    run_rclone_logged sync "$bucket" "$staging_dir" --exclude "_backups/**" $rclone_opts || status=$?
    if [[ "$status" != "0" ]]; then
        rm -rf -- "$staging_dir"
        _LOCAL_BACKUP_STAGING=""
        _release_local_backup_lock
        log "   ❌ Local backup failed (rclone exit $status); today's backup is not marked done"
        return "$status"
    fi

    if ! mv -- "$staging_dir" "$final_dir"; then
        rm -rf -- "$staging_dir"
        _LOCAL_BACKUP_STAGING=""
        _release_local_backup_lock
        log "   ❌ Failed to finalize local backup directory: $final_dir"
        return 1
    fi
    _LOCAL_BACKUP_STAGING=""

    if ! write_marker_atomically "$marker_file" "$TODAY"; then
        _release_local_backup_lock
        return 1
    fi
    _release_local_backup_lock
    log "   ✅ Local backup created"
    return 0
}

create_remote_backup() {
    local bucket="$1"
    local marker_file="$2"
    local force_flag="${3:-false}"
    local frequency="${4:-daily}"
    local rclone_opts
    local status=0
    rclone_opts=$(build_rclone_opts root)
    
    if backup_needed "$marker_file" "$frequency" "$force_flag"; then
        log "📦 Creating remote backup..."
        log "   Target: $bucket/_backups/$TIMESTAMP"
        run_rclone_logged sync "$bucket" "$bucket/_backups/$TIMESTAMP" --exclude "_backups/**" $rclone_opts || status=$?
        if [[ "$status" != "0" ]]; then
            log "   ❌ Remote backup failed (rclone exit $status); today's backup is not marked done"
            return "$status"
        fi
        write_marker_atomically "$marker_file" "$TODAY" || return 1
        log "   ✅ Remote backup created"
        return 0
    elif [[ "$frequency" == "off" ]]; then
        log "⏭️  Skipping remote backup (frequency is off)"
        return 1
    else
        log "⏭️  Skipping remote backup (already done today: $(cat "$marker_file"))"
        return 1
    fi
}

# Run one rclone command with its output streamed through log(), returning
# rclone's own exit status. Callers such as run_with_do_io_lock invoke uploads
# from an `||` list, where set -e is suspended, so a failed pipeline must be
# returned explicitly rather than left to errexit. Requires pipefail, which
# every upload script sets.
run_rclone_logged() {
    local status=0
    $RCLONE "$@" 2>&1 | while read -r line; do log "   $line"; done || status=${PIPESTATUS[0]}
    return "$status"
}

upload_content() {
    local bucket="$1"
    local rclone_opts
    local status=0
    rclone_opts=$(build_rclone_opts root) || return

    log "🚀 Uploading content (incremental sync)..."
    log "   Source: $SOURCE_DIR"
    log "   Target: $bucket"
    run_rclone_logged sync "$SOURCE_DIR" "$bucket" --exclude "_backups/**" $rclone_opts || status=$?
    if [[ "$status" != "0" ]]; then
        log "   ❌ Upload failed (rclone exit $status)"
        return "$status"
    fi
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
    local -a local_list=()
    local candidate
    
    echo "📦 Local backups:"
    if [[ -d "$LOCAL_BACKUP_DIR" ]]; then
        shopt -s nullglob
        for candidate in "$LOCAL_BACKUP_DIR"/backup-*; do
            [[ "$(basename "$candidate")" == *.tmp.* ]] && continue
            local_list+=("$candidate")
        done
        shopt -u nullglob
    fi
    if (( ${#local_list[@]} > 0 )); then
        ls -1dt "${local_list[@]}" 2>/dev/null | head -5 || echo "   (none)"
    else
        echo "   (none)"
    fi
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
  --list-backups       List available local and remote backups
  --force-backup       Force both local and remote backups even if done today
                       or their frequency is off
  --skip-local-backup  Skip local backup for this run (unless --force-backup)

Rollback from local backup:
  $script_name ~/metrics-backups/backup-YYYY-MM-DD_HHMMSS

Rollback from $storage_name backup:
  rclone sync remote:bucket/_backups/YYYY-MM-DD_HHMMSS ~/metrics-output
  $script_name
EOF
}
