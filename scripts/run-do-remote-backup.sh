#!/usr/bin/env bash
# Retry the retained daily DO remote backup outside the publication critical
# path. This wrapper is intentionally quiet after today's marker exists.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    # shellcheck disable=SC1091
    source "$DEPLOY_DIR/config.env"
fi

MARKER_FILE="${DO_REMOTE_BACKUP_MARKER:-$DEPLOY_DIR/logs/last-do-backup-date}"
LOG_FILE="${DO_REMOTE_BACKUP_LOG_FILE:-$DEPLOY_DIR/logs/do-remote-backup.log}"
SUMMARY_FILE="${DO_REMOTE_BACKUP_SUMMARY_FILE:-$DEPLOY_DIR/logs/do-remote-backup-summary.tsv}"
RUN_LOCK="${DO_REMOTE_BACKUP_RUN_LOCK:-/tmp/allium-do-remote-backup-run.lock}"
LOG_MAX_BYTES="${DO_REMOTE_BACKUP_LOG_MAX_BYTES:-8388608}"
LOG_ARCHIVES="${DO_REMOTE_BACKUP_LOG_ARCHIVES:-2}"
TODAY="$(date '+%Y-%m-%d')"

[[ "$RUN_LOCK" == /tmp/* && "$RUN_LOCK" != /tmp/ ]] || {
    printf '[DO-Backup] refusing unsafe run lock: %s\n' "$RUN_LOCK" >&2
    exit 2
}

exec 9>"$RUN_LOCK"
flock -n 9 || exit 0

if [[ -f "$MARKER_FILE" ]] && [[ "$(cat "$MARKER_FILE" 2>/dev/null)" == "$TODAY" ]]; then
    exit 0
fi

ALLIUM_UPDATE_LOG_FILE="$LOG_FILE" \
ALLIUM_UPDATE_LOG_MAX_BYTES="$LOG_MAX_BYTES" \
ALLIUM_UPDATE_LOG_ARCHIVES="$LOG_ARCHIVES" \
WRANGLER_LOG_PATH="$DEPLOY_DIR/logs/wrangler-debug-sink.log" \
    "$SCRIPT_DIR/allium-deploy-maintain-logs.sh" >/dev/null

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$SUMMARY_FILE")"
exec >>"$LOG_FILE" 2>&1

started_epoch=$(date +%s)
started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
status=0
printf '[DO-Backup] started_utc=%s\n' "$started_utc"
"$SCRIPT_DIR/allium-deploy-upload-do.sh" --remote-backup-only || status=$?
finished_epoch=$(date +%s)
finished_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
duration=$((finished_epoch - started_epoch))
marker_value=$(cat "$MARKER_FILE" 2>/dev/null || true)

if [[ ! -f "$SUMMARY_FILE" ]]; then
    printf 'started_utc\tfinished_utc\texit_status\tduration_seconds\tmarker\n' > "$SUMMARY_FILE"
fi
printf '%s\t%s\t%s\t%s\t%s\n' \
    "$started_utc" "$finished_utc" "$status" "$duration" "$marker_value" \
    >> "$SUMMARY_FILE"
printf '[DO-Backup] finished_utc=%s status=%s duration=%ss marker=%s\n' \
    "$finished_utc" "$status" "$duration" "${marker_value:-missing}"
exit "$status"
