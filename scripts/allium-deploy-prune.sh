#!/usr/bin/env bash
# Allium Deploy - Prune Old Backups
# Removes old backups from local and R2 (keeps last N)
# Runs in background during update for efficiency

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

ENV_BACKUP_DIR_SET="${BACKUP_DIR+x}"
ENV_BACKUP_DIR_VALUE="${BACKUP_DIR-}"
ENV_R2_BUCKET_SET="${R2_BUCKET+x}"
ENV_R2_BUCKET_VALUE="${R2_BUCKET-}"
ENV_RCLONE_PATH_SET="${RCLONE_PATH+x}"
ENV_RCLONE_PATH_VALUE="${RCLONE_PATH-}"
ENV_R2_LIST_TIMEOUT_SET="${R2_LIST_TIMEOUT+x}"
ENV_R2_LIST_TIMEOUT_VALUE="${R2_LIST_TIMEOUT-}"
ENV_KEEP_BACKUPS_SET="${KEEP_BACKUPS+x}"
ENV_KEEP_BACKUPS_VALUE="${KEEP_BACKUPS-}"

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    source "$DEPLOY_DIR/config.env"
fi

if [[ -n "$ENV_BACKUP_DIR_SET" ]]; then BACKUP_DIR="$ENV_BACKUP_DIR_VALUE"; fi
if [[ -n "$ENV_R2_BUCKET_SET" ]]; then R2_BUCKET="$ENV_R2_BUCKET_VALUE"; fi
if [[ -n "$ENV_RCLONE_PATH_SET" ]]; then RCLONE_PATH="$ENV_RCLONE_PATH_VALUE"; fi
if [[ -n "$ENV_R2_LIST_TIMEOUT_SET" ]]; then R2_LIST_TIMEOUT="$ENV_R2_LIST_TIMEOUT_VALUE"; fi
if [[ -n "$ENV_KEEP_BACKUPS_SET" ]]; then KEEP_BACKUPS="$ENV_KEEP_BACKUPS_VALUE"; fi

LOCAL_BACKUP_DIR="${BACKUP_DIR:-$HOME/metrics-backups}"
BUCKET="r2-metrics:${R2_BUCKET:?R2_BUCKET must be set in config.env}"
RCLONE="${RCLONE_PATH:-$HOME/bin/rclone}"
R2_LIST_TIMEOUT="${R2_LIST_TIMEOUT:-300}"
KEEP_BACKUPS="${KEEP_BACKUPS:-5}"
SAFETY_BUFFER=2

log() {
    echo "[PRUNE] [$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

count_lines() { local c; c=$(grep -c . <<< "$1" 2>/dev/null) || c=0; echo "$c"; }

log "🧹 Prune starting..."

# Local prune
if [[ -d "$LOCAL_BACKUP_DIR" ]]; then
    if [[ ! -r "$LOCAL_BACKUP_DIR" ]] || [[ ! -x "$LOCAL_BACKUP_DIR" ]]; then
        log "❌ Local backup enumeration failed: cannot read $LOCAL_BACKUP_DIR"
        exit 1
    fi

    shopt -s nullglob
    local_backups=("$LOCAL_BACKUP_DIR"/backup-*)
    shopt -u nullglob
    local_all=""
    if (( ${#local_backups[@]} > 0 )); then
        if ! local_all=$(ls -1dt "${local_backups[@]}" 2>&1); then
            log "❌ Local backup enumeration failed: $local_all"
            exit 1
        fi
    fi
    local_count=$(count_lines "$local_all")
    if [[ "$local_count" -gt "$((KEEP_BACKUPS + SAFETY_BUFFER))" ]]; then
        log "🧹 Pruning local backups ($local_count found, keeping $KEEP_BACKUPS)..."
        local_to_delete=$(printf '%s\n' "$local_all" | tail -n +$((KEEP_BACKUPS + 1)))
        while IFS= read -r backup_path; do
            [[ -z "$backup_path" ]] && continue
            if ! rm -rf -- "$backup_path"; then
                log "❌ Failed to remove local backup: $backup_path"
                exit 1
            fi
        done <<< "$local_to_delete"
        log "✅ Local prune done"
    else
        log "⏭️ Local prune skipped ($local_count backups, need $((KEEP_BACKUPS + SAFETY_BUFFER + 1))+ to prune)"
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
