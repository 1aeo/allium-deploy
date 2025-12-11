#!/usr/bin/env bash
# Allium Deploy - Prune Old Backups
# Removes old backups from local and R2 (keeps last N)
# Runs in background during update for efficiency

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    source "$DEPLOY_DIR/config.env"
fi

LOCAL_BACKUP_DIR="${BACKUP_DIR:-$HOME/metrics-backups}"
BUCKET="r2-metrics:${R2_BUCKET:?R2_BUCKET must be set in config.env}"
RCLONE="${RCLONE_PATH:-$HOME/bin/rclone}"
KEEP_BACKUPS="${KEEP_BACKUPS:-5}"
SAFETY_BUFFER=2  # Only prune if we have KEEP + BUFFER backups

log() {
    echo "[PRUNE] [$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "🧹 Prune starting..."

# Local prune
if [[ -d "$LOCAL_BACKUP_DIR" ]]; then
    local_count=$(ls -1d "$LOCAL_BACKUP_DIR"/backup-* 2>/dev/null | wc -l)
    if [ "$local_count" -gt "$((KEEP_BACKUPS + SAFETY_BUFFER))" ]; then
        log "🧹 Pruning local backups ($local_count found, keeping $KEEP_BACKUPS)..."
        ls -1dt "$LOCAL_BACKUP_DIR"/backup-* | tail -n +$((KEEP_BACKUPS + 1)) | xargs rm -rf
        log "✅ Local prune done"
    else
        log "⏭️ Local prune skipped ($local_count backups, need $((KEEP_BACKUPS + SAFETY_BUFFER + 1))+ to prune)"
    fi
fi

# R2 prune
r2_count=$($RCLONE lsf "$BUCKET/_backups/" --dirs-only 2>/dev/null | wc -l)
if [ "$r2_count" -gt "$((KEEP_BACKUPS + SAFETY_BUFFER))" ]; then
    log "🧹 Pruning R2 backups ($r2_count found, keeping $KEEP_BACKUPS)..."
    r2_to_delete=$($RCLONE lsf "$BUCKET/_backups/" --dirs-only 2>/dev/null | sort -r | tail -n +$((KEEP_BACKUPS + 1)))
    for backup in $r2_to_delete; do
        log "   Removing $BUCKET/_backups/$backup"
        $RCLONE purge "$BUCKET/_backups/$backup" 2>/dev/null || true
    done
    log "✅ R2 prune done"
else
    log "⏭️ R2 prune skipped ($r2_count backups, need $((KEEP_BACKUPS + SAFETY_BUFFER + 1))+ to prune)"
fi

log "🧹 Prune finished"

