#!/usr/bin/env bash
# Allium Deploy - Prune Old Backups
# Removes old backups from local and R2 (keeps last N)
# Runs in background during update for efficiency

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

PRUNE_ENV_OVERRIDES=(BACKUP_DIR LOG_DIR LOCAL_BACKUP_LOCK_FILE R2_BUCKET RCLONE_PATH R2_LIST_TIMEOUT KEEP_BACKUPS LOCAL_KEEP_BACKUPS)
capture_env_overrides "${PRUNE_ENV_OVERRIDES[@]}"

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    source "$DEPLOY_DIR/config.env"
fi

restore_env_overrides "${PRUNE_ENV_OVERRIDES[@]}"

LOCAL_BACKUP_DIR="${BACKUP_DIR:-$HOME/metrics-backups}"
LOG_DIR="${LOG_DIR:-$DEPLOY_DIR/logs}"
LOCAL_BACKUP_LOCK_FILE="${LOCAL_BACKUP_LOCK_FILE:-$LOG_DIR/.local-backup.lock}"
BUCKET="r2-metrics:${R2_BUCKET:?R2_BUCKET must be set in config.env}"
RCLONE="${RCLONE_PATH:-$HOME/bin/rclone}"
R2_LIST_TIMEOUT="${R2_LIST_TIMEOUT:-300}"
KEEP_BACKUPS="${KEEP_BACKUPS:-5}"
LOCAL_KEEP_BACKUPS="${LOCAL_KEEP_BACKUPS:-$KEEP_BACKUPS}"
SAFETY_BUFFER=2

log() {
    echo "[PRUNE] [$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

count_lines() { local c; c=$(grep -c . <<< "$1" 2>/dev/null) || c=0; echo "$c"; }

if [[ ! "$KEEP_BACKUPS" =~ ^[1-9][0-9]*$ ]]; then
    log "❌ Invalid KEEP_BACKUPS=$KEEP_BACKUPS (must be a positive integer)"
    exit 2
fi
if [[ ! "$LOCAL_KEEP_BACKUPS" =~ ^[1-9][0-9]*$ ]]; then
    log "❌ Invalid LOCAL_KEEP_BACKUPS=$LOCAL_KEEP_BACKUPS (must be a positive integer)"
    exit 2
fi

log "🧹 Prune starting..."

# Local prune
if [[ -d "$LOCAL_BACKUP_DIR" ]]; then
    if [[ ! -r "$LOCAL_BACKUP_DIR" ]] || [[ ! -x "$LOCAL_BACKUP_DIR" ]]; then
        log "❌ Local backup enumeration failed: cannot read $LOCAL_BACKUP_DIR"
        exit 1
    fi

    # Clean stale incomplete local backup staging dirs older than 24 hours only when
    # no local backup holds LOCAL_BACKUP_LOCK_FILE (rclone updates files inside subdirs).
    run_stale_cleanup=true
    prune_lock_open=false
    if command -v flock >/dev/null 2>&1 && [[ -f "$LOCAL_BACKUP_LOCK_FILE" ]]; then
        exec 7>"$LOCAL_BACKUP_LOCK_FILE"
        prune_lock_open=true
        if ! flock -n 7; then
            exec 7>&-
            prune_lock_open=false
            run_stale_cleanup=false
            log "⏭️ Skipping stale temp cleanup (local backup lock is held)"
        fi
    fi

    if [[ "$run_stale_cleanup" == "true" ]]; then
        while IFS= read -r -d '' stale_tmp; do
            log "   Removing stale incomplete backup: $(basename "$stale_tmp")"
            if ! rm -rf -- "$stale_tmp"; then
                if [[ "$prune_lock_open" == "true" ]]; then
                    exec 7>&-
                fi
                log "❌ Failed to remove stale temp backup: $stale_tmp"
                exit 1
            fi
        done < <(find "$LOCAL_BACKUP_DIR" -maxdepth 1 -type d -name 'backup-*.tmp.*' -mmin +1440 -print0 2>/dev/null)
    fi

    if [[ "$prune_lock_open" == "true" ]]; then
        exec 7>&-
    fi

    shopt -s nullglob
    local_backups=()
    for candidate in "$LOCAL_BACKUP_DIR"/backup-*; do
        [[ "$(basename "$candidate")" == *.tmp.* ]] && continue
        local_backups+=("$candidate")
    done
    shopt -u nullglob
    local_all=""
    if (( ${#local_backups[@]} > 0 )); then
        if ! local_all=$(ls -1dt "${local_backups[@]}" 2>&1); then
            log "❌ Local backup enumeration failed: $local_all"
            exit 1
        fi
    fi
    local_count=$(count_lines "$local_all")
    if [[ "$local_count" -gt "$((LOCAL_KEEP_BACKUPS + SAFETY_BUFFER))" ]]; then
        log "🧹 Pruning local backups ($local_count found, keeping $LOCAL_KEEP_BACKUPS)..."
        local_to_delete=$(printf '%s\n' "$local_all" | tail -n +$((LOCAL_KEEP_BACKUPS + 1)))
        while IFS= read -r backup_path; do
            [[ -z "$backup_path" ]] && continue
            if ! rm -rf -- "$backup_path"; then
                log "❌ Failed to remove local backup: $backup_path"
                exit 1
            fi
        done <<< "$local_to_delete"
        log "✅ Local prune done"
    else
        log "⏭️ Local prune skipped ($local_count backups, need $((LOCAL_KEEP_BACKUPS + SAFETY_BUFFER + 1))+ to prune)"
    fi
fi

# R2 prune
r2_error_file=$(mktemp)
if r2_all=$(run_with_timeout "$R2_LIST_TIMEOUT" "$RCLONE" lsf "$BUCKET/_backups/" --dirs-only 2>"$r2_error_file"); then
    rm -f "$r2_error_file"
else
    r2_status=$?
    r2_error=$(cat "$r2_error_file" 2>/dev/null || true)
    rm -f "$r2_error_file"
    if [[ "$r2_status" -eq 124 ]]; then
        log "❌ R2 backup enumeration failed: timed out after ${R2_LIST_TIMEOUT}s"
    elif [[ -n "$r2_error" ]]; then
        log "❌ R2 backup enumeration failed: $r2_error"
    else
        log "❌ R2 backup enumeration failed: exit status $r2_status"
    fi
    exit 1
fi
r2_count=$(count_lines "$r2_all")
if [[ "$r2_count" -gt "$((KEEP_BACKUPS + SAFETY_BUFFER))" ]]; then
    r2_purge_failed=false
    log "🧹 Pruning R2 backups ($r2_count found, keeping $KEEP_BACKUPS)..."
    r2_to_delete=$(printf '%s\n' "$r2_all" | sort -r | tail -n +$((KEEP_BACKUPS + 1)))
    while IFS= read -r backup; do
        [[ -z "$backup" ]] && continue
        log "   Removing $BUCKET/_backups/$backup"
        if ! purge_output=$("$RCLONE" purge "$BUCKET/_backups/$backup" 2>&1); then
            log "⚠️ Failed to remove R2 backup $BUCKET/_backups/$backup: ${purge_output:-unknown error}"
            r2_purge_failed=true
        fi
    done <<< "$r2_to_delete"
    if [[ "$r2_purge_failed" == "true" ]]; then
        log "❌ R2 prune completed with one or more purge failures"
        exit 1
    fi
    log "✅ R2 prune done"
else
    log "⏭️ R2 prune skipped ($r2_count backups, need $((KEEP_BACKUPS + SAFETY_BUFFER + 1))+ to prune)"
fi

log "🧹 Prune finished"
