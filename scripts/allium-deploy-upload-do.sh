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
    --force-backup) SOURCE_DIR_ARG="${2:-}" ;;
    --list-backups|--remote-backup-only|--help|-h) ;;
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
# the pipeline full. rclone's post-upload integrity HEAD is kept unless
# DO_RCLONE_NO_HEAD=true.
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
# Without ListR, rclone lists every remote directory separately: one LIST per
# relay, contact and family page folder, about 21,300 per build. The page trees
# named here are synced one at a time with --fast-list, which lists only that
# prefix (one LIST per 1,000 objects) and never touches _backups/. A final
# directory-traversal pass covers everything else. Empty keeps one sync.
DO_FAST_LIST_SUBTREES="${DO_RCLONE_FAST_LIST_SUBTREES:-}"
DO_FAST_LIST_SUBTREE_NAMES=()
# Compare size plus the listing ETag (the MD5 of every single-part object)
# instead of reading each object's mtime with a HEAD request. Unchanged files
# then cost no request and changed same-size files skip the mtime HEAD.
RCLONE_CHECKSUM="${DO_RCLONE_CHECKSUM:-false}"
# Skip the HEAD rclone sends after each live-sync upload to read the object's
# size and ETag back, so a changed file costs one PUT instead of two requests.
# DO rejects a PUT whose Content-MD5 does not match the body, rclone compares
# the PUT response's ETag with the local MD5, and the next build's checksum
# comparison checks every object again. Requires DO_RCLONE_CHECKSUM=true.
# Backups keep the HEAD.
DO_NO_HEAD="${DO_RCLONE_NO_HEAD:-false}"

# DO Spaces configuration
DO_REGION="${DO_SPACES_REGION:-nyc3}"
DO_BUCKET_NAME="${DO_SPACES_BUCKET:?DO_SPACES_BUCKET must be set in config.env}"
BUCKET="spaces-metrics:${DO_BUCKET_NAME}"
DO_USE_CDN="${DO_SPACES_CDN:-false}"

LOCAL_BACKUP_MARKER="${DO_LOCAL_BACKUP_MARKER:-$LOG_DIR/last-do-local-backup-date}"
DO_BACKUP_MARKER="${DO_REMOTE_BACKUP_MARKER:-$LOG_DIR/last-do-backup-date}"
DO_REMOTE_BACKUP_INLINE="${DO_REMOTE_BACKUP_INLINE:-true}"
DO_IO_LOCK_FILE="${DO_IO_LOCK_FILE:-/tmp/allium-do-spaces-io.lock}"
DO_IO_LOCK_WAIT_SECONDS="${DO_IO_LOCK_WAIT_SECONDS:-180}"
DO_LIVE_SYNC_SUMMARY_FILE="${DO_LIVE_SYNC_SUMMARY_FILE:-$LOG_DIR/do-live-sync-summary.tsv}"

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

validate_do_fast_list_subtrees() {
    local subtree seen=" "
    local -a names=()

    if [[ "$DO_FAST_LIST_SUBTREES" == *$'\n'* ]]; then
        log "❌ DO_RCLONE_FAST_LIST_SUBTREES must be one comma-separated line"
        return 2
    fi
    IFS=', ' read -r -a names <<< "$DO_FAST_LIST_SUBTREES"
    for subtree in ${names[@]+"${names[@]}"}; do
        if [[ ! "$subtree" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
            log "❌ DO_RCLONE_FAST_LIST_SUBTREES entries must be top-level directory names (got: '$subtree')"
            return 2
        fi
        if [[ "$seen" == *" $subtree "* ]]; then
            log "❌ DO_RCLONE_FAST_LIST_SUBTREES lists '$subtree' twice"
            return 2
        fi
        seen+="$subtree "
        DO_FAST_LIST_SUBTREE_NAMES+=("$subtree")
    done
}

# Sync the live mirror. Each configured page tree that exists in this build is
# synced with --fast-list on its own prefix; the final pass then excludes those
# trees and syncs the root files and every other directory, including deleting
# trees the generator no longer produces. Passes run one after another so the
# shared transaction cap still bounds the aggregate request rate. A pass that
# still fails after rclone's retries stops the remaining passes: when DO is
# unreachable every later pass would spend its full retry budget too, and the
# Workers promotion waits for this job. The next build syncs everything again.
upload_do_content() {
    local bucket="$1"
    local rclone_opts subtree_opts subtree
    local status=0
    local -a subtrees=()
    local -a remainder_excludes=()
    # Only the live sync skips the post-upload HEAD. build_rclone_opts sees
    # this local, also when upload_content calls it.
    local S3_NO_HEAD="$DO_NO_HEAD"

    if [[ "$RCLONE_FAST_LIST" == "true" || ${#DO_FAST_LIST_SUBTREE_NAMES[@]} -eq 0 ]]; then
        upload_content "$bucket"
        return
    fi

    rclone_opts=$(build_rclone_opts root) || return
    subtree_opts=$(build_rclone_opts subtree) || return

    for subtree in "${DO_FAST_LIST_SUBTREE_NAMES[@]}"; do
        if [[ -d "$SOURCE_DIR/$subtree" ]]; then
            subtrees+=("$subtree")
            remainder_excludes+=(--exclude "/$subtree/**")
        else
            log "   ⏭️  $subtree/ is not in this build; the final pass covers it"
        fi
    done

    log "🚀 Uploading content (incremental sync, ${#subtrees[@]} fast-list subtrees)..."
    log "   Source: $SOURCE_DIR"
    log "   Target: $bucket"
    for subtree in ${subtrees[@]+"${subtrees[@]}"}; do
        log "   ▶ $subtree/ (fast-list)"
        run_rclone_logged sync "$SOURCE_DIR/$subtree" "$bucket/$subtree" $subtree_opts --fast-list || status=$?
        if [[ "$status" != "0" ]]; then
            log "   ❌ $subtree/ failed (rclone exit $status); skipping the remaining passes"
            return "$status"
        fi
    done

    log "   ▶ remaining files (directory traversal)"
    run_rclone_logged sync "$SOURCE_DIR" "$bucket" --exclude "_backups/**" \
        ${remainder_excludes[@]+"${remainder_excludes[@]}"} $rclone_opts || status=$?
    if [[ "$status" != "0" ]]; then
        log "   ❌ Remaining files failed (rclone exit $status)"
        return "$status"
    fi
    log "   ✅ Upload complete"
}

# Append one row per live-sync attempt, including lock timeouts, so DO duration
# and failures are visible without parsing update.log.
record_do_live_sync() {
    local status="$1"
    local started_epoch="$2"
    local started_utc="$3"
    local finished_epoch finished_utc listing

    finished_epoch=$(date +%s)
    finished_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    if [[ "$RCLONE_FAST_LIST" == "true" ]]; then
        listing="fast-list"
    elif [[ ${#DO_FAST_LIST_SUBTREE_NAMES[@]} -gt 0 ]]; then
        listing="fast-list:$(IFS=,; echo "${DO_FAST_LIST_SUBTREE_NAMES[*]}")"
    else
        listing="traversal"
    fi

    mkdir -p "$(dirname "$DO_LIVE_SYNC_SUMMARY_FILE")" || return
    if [[ ! -s "$DO_LIVE_SYNC_SUMMARY_FILE" ]]; then
        printf 'started_utc\tfinished_utc\texit_status\tduration_seconds\tchecksum\tlisting\n' \
            > "$DO_LIVE_SYNC_SUMMARY_FILE" || return
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$started_utc" "$finished_utc" "$status" "$((finished_epoch - started_epoch))" \
        "$RCLONE_CHECKSUM" "$listing" >> "$DO_LIVE_SYNC_SUMMARY_FILE"
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
        # SOURCE_DIR_ARG was parsed above. Calling setup_common_vars again here
        # would reset the DO transfer, checker and transaction-rate caps.
        FORCE_BACKUP=true
        ;;
    --remote-backup-only)
        REMOTE_BACKUP_ONLY=true
        # A manual `--remote-backup-only --force-backup` takes a DO snapshot
        # even if one exists today or DO_BACKUP_FREQUENCY=off. The hourly
        # runner never passes it.
        if [[ "${2:-}" == "--force-backup" ]]; then
            FORCE_BACKUP=true
        fi
        ;;
    --help|-h)
        print_help "$0" "DO Spaces"
        cat <<EOF

DO snapshot only (used by scripts/run-do-remote-backup.sh):
  $0 --remote-backup-only
  $0 --remote-backup-only --force-backup
                   Take a DO snapshot now, even if done today or
                   DO_BACKUP_FREQUENCY is off

With DO_REMOTE_BACKUP_INLINE=false, --force-backup [source_dir] forces only
the local backup; use --remote-backup-only --force-backup for the DO snapshot.
LOCAL_BACKUP_FREQUENCY and DO_BACKUP_FREQUENCY accept daily (the default),
every-run or off.
EOF
        exit 0
        ;;
esac

[[ ! -d "$SOURCE_DIR" ]] && { echo "❌ Error: Source directory not found: $SOURCE_DIR"; exit 1; }

if [[ "$REMOTE_BACKUP_ONLY" == "true" ]]; then
    STORAGE_NAME="DO-Backup"
    # This mode takes no local backup. An invalid value still stops it, since
    # it would also break every build, but the deprecation notice is not
    # repeated in the runner's log.
    resolve_backup_frequency LOCAL_BACKUP_FREQUENCY DAILY_LOCAL_BACKUP >/dev/null
else
    resolve_backup_frequency LOCAL_BACKUP_FREQUENCY DAILY_LOCAL_BACKUP
fi
resolve_backup_frequency DO_BACKUP_FREQUENCY DAILY_DO_BACKUP
if [[ "$REMOTE_BACKUP_ONLY" == "true" && "$DO_BACKUP_FREQUENCY" == "off" &&
    "$FORCE_BACKUP" != "true" ]]; then
    log "⏭️  DO remote backup is off (DO_BACKUP_FREQUENCY=off)"
    exit 0
fi

ensure_spaces_remote
validate_do_coordination_settings

if [[ "$REMOTE_BACKUP_ONLY" == "true" ]]; then
    TRANSFERS="${DO_REMOTE_BACKUP_TRANSFERS:-16}"
    CHECKERS="${DO_REMOTE_BACKUP_CHECKERS:-32}"
    TPS_LIMIT="${DO_REMOTE_BACKUP_TPS_LIMIT:-30}"
    TPS_LIMIT_BURST="${DO_REMOTE_BACKUP_TPS_LIMIT_BURST:-1}"

    # Validate options here: inside run_with_do_io_lock's `||` list a failed
    # option build would go unnoticed and rclone would run without its caps.
    build_rclone_opts root >/dev/null

    log "📦 DigitalOcean remote backup"
    log "   Transaction rate: $TPS_LIMIT operations/second, burst $TPS_LIMIT_BURST"
    if backup_needed "$DO_BACKUP_MARKER" "$DO_BACKUP_FREQUENCY" "$FORCE_BACKUP"; then
        run_with_do_io_lock create_remote_backup \
            "$BUCKET" "$DO_BACKUP_MARKER" "$FORCE_BACKUP" "$DO_BACKUP_FREQUENCY"
    else
        log "⏭️  Remote backup already completed today: $(cat "$DO_BACKUP_MARKER")"
    fi
    print_sync_summary
    exit 0
fi

# Validate the live-sync options, including DO_RCLONE_NO_HEAD, before the
# backups run. Only upload_do_content applies DO_RCLONE_NO_HEAD.
S3_NO_HEAD="$DO_NO_HEAD" build_rclone_opts root >/dev/null
validate_do_fast_list_subtrees

log "🌊 DigitalOcean Spaces Upload"
log "   Bucket: $DO_BUCKET_NAME ($DO_REGION)"
log "   Parallel: $TRANSFERS transfers, $CHECKERS checkers"
log "   Transaction rate: $TPS_LIMIT operations/second, burst $TPS_LIMIT_BURST"
log "   S3 HTTP/2 disabled: $S3_DISABLE_HTTP2"
log "   Checksum comparison: $RCLONE_CHECKSUM"
log "   Skip post-upload HEAD: $DO_NO_HEAD"
if [[ "$RCLONE_FAST_LIST" != "true" && ${#DO_FAST_LIST_SUBTREE_NAMES[@]} -gt 0 ]]; then
    log "   Fast-list subtrees: ${DO_FAST_LIST_SUBTREE_NAMES[*]}"
fi
if [[ "$DO_USE_CDN" == "true" ]]; then
    log "   Mode: CDN (faster, may cache up to 1hr)"
else
    log "   Mode: Origin (always fresh)"
fi

create_local_backup "$BUCKET" "$LOCAL_BACKUP_MARKER" "$FORCE_BACKUP" "$LOCAL_BACKUP_FREQUENCY" || true
# A backup that is off does not wait for the DO I/O lock unless forced.
if [[ "$DO_REMOTE_BACKUP_INLINE" == "true" &&
    ( "$DO_BACKUP_FREQUENCY" != "off" || "$FORCE_BACKUP" == "true" ) ]]; then
    run_with_do_io_lock create_remote_backup \
        "$BUCKET" "$DO_BACKUP_MARKER" "$FORCE_BACKUP" "$DO_BACKUP_FREQUENCY" || true
elif [[ "$DO_REMOTE_BACKUP_INLINE" != "true" && "$FORCE_BACKUP" == "true" ]]; then
    log "⏭️  --force-backup does not take the deferred DO snapshot; run $0 --remote-backup-only --force-backup"
elif [[ "$DO_BACKUP_FREQUENCY" == "off" ]]; then
    log "⏭️  DO remote backup is off (DO_BACKUP_FREQUENCY=off)"
else
    log "⏭️  DO remote backup is handled by the independent retry runner"
fi
live_started_epoch=$(date +%s)
live_started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
live_status=0
run_with_do_io_lock upload_do_content "$BUCKET" || live_status=$?
record_do_live_sync "$live_status" "$live_started_epoch" "$live_started_utc" ||
    log "⚠️  Could not append $DO_LIVE_SYNC_SUMMARY_FILE"
if [[ "$live_status" != "0" ]]; then
    log "❌ DO live sync failed (exit $live_status)"
    exit "$live_status"
fi
print_sync_summary
