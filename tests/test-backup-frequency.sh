#!/usr/bin/env bash
# LOCAL_BACKUP_FREQUENCY, R2_BACKUP_FREQUENCY and DO_BACKUP_FREQUENCY: daily,
# every-run and off, the older DAILY_*_BACKUP names, invalid values,
# --force-backup (including a deferred DO snapshot), and the hourly DO runner.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d /tmp/allium-backup-frequency-test.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT
# Run copies of the scripts so a deployed config.env in this checkout can never
# replace the mocks and point a test backup at a real bucket.
DEPLOY_COPY="$TMP_DIR/deploy"
mkdir -p "$DEPLOY_COPY/scripts" "$DEPLOY_COPY/logs"
cp "$ROOT_DIR/scripts/allium-deploy-upload-r2.sh" \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" \
    "$ROOT_DIR/scripts/allium-deploy-upload-common.sh" \
    "$ROOT_DIR/scripts/run-do-remote-backup.sh" \
    "$ROOT_DIR/scripts/allium-deploy-maintain-logs.sh" \
    "$DEPLOY_COPY/scripts/"
# Settings in the caller's environment must not leak into any run.
unset LOCAL_BACKUP_FREQUENCY R2_BACKUP_FREQUENCY DO_BACKUP_FREQUENCY \
    DAILY_LOCAL_BACKUP DAILY_R2_BACKUP DAILY_DO_BACKUP

fail() {
    echo "not ok - $1" >&2
    if [[ -f "$RUN_LOG" ]]; then
        sed 's/^/#   /' "$RUN_LOG" >&2
    fi
    exit 1
}

pass() {
    echo "ok - $1"
}

MOCK_BIN="$TMP_DIR/mock-bin"
MOCK_CALLS="$TMP_DIR/rclone-calls"
MOCK_FLOCK_CALLS="$TMP_DIR/flock-calls"
RUN_LOG="$TMP_DIR/run.log"
mkdir -p "$MOCK_BIN"
# Records every rclone invocation, so a run that must stop before rclone can
# be checked for an empty call log.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\n" "$*" >> "$MOCK_RCLONE_CALLS"' \
    'if [[ -n "${MOCK_FAIL_BACKUPS:-}" && "${1:-}" == sync && ( "${3:-}" == */backups/backup-* || "${3:-}" == *:test-bucket/_backups/* ) ]]; then echo "mock backup failure" >&2; exit 7; fi' \
    'case "${1:-}" in' \
    '  listremotes) printf "r2-metrics:\nspaces-metrics:\n" ;;' \
    'esac' \
    > "$MOCK_BIN/rclone"
chmod 0755 "$MOCK_BIN/rclone"
# The production host provides util-linux flock; this stub keeps the test
# portable and records each lock request.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf "%s\n" "$*" >> "$MOCK_FLOCK_CALLS"' \
    > "$MOCK_BIN/flock"
chmod 0755 "$MOCK_BIN/flock"

OUT="$TMP_DIR/output"
mkdir -p "$OUT" "$TMP_DIR/backups"
printf '<html>test</html>\n' > "$OUT/index.html"
TODAY=$(date '+%Y-%m-%d')
R2_LOCAL_MARKER="$DEPLOY_COPY/logs/last-local-backup-date"
R2_MARKER="$DEPLOY_COPY/logs/last-r2-backup-date"
DO_LOCAL_MARKER="$TMP_DIR/do-local-marker"
DO_MARKER="$TMP_DIR/do-marker"
RUNNER_LOG="$DEPLOY_COPY/logs/do-remote-backup.log"
RUNNER_SUMMARY="$TMP_DIR/do-remote-backup-summary.tsv"

common_env=(
    PATH="$MOCK_BIN:$PATH"
    MOCK_RCLONE_CALLS="$MOCK_CALLS"
    MOCK_FLOCK_CALLS="$MOCK_FLOCK_CALLS"
    RCLONE_PATH="$MOCK_BIN/rclone"
    OUTPUT_DIR="$OUT"
    BACKUP_DIR="$TMP_DIR/backups"
    R2_BUCKET=test-bucket
    R2_ACCESS_KEY_ID=test-key
    R2_SECRET_ACCESS_KEY=test-secret
    CLOUDFLARE_ACCOUNT_ID=test-account
    R2_CONTENT_SYNC_INTERVAL=every-build
    DO_SPACES_BUCKET=test-bucket
    DO_SPACES_KEY=test-key
    DO_SPACES_SECRET=test-secret
    DO_LOCAL_BACKUP_MARKER="$DO_LOCAL_MARKER"
    DO_REMOTE_BACKUP_MARKER="$DO_MARKER"
    DO_IO_LOCK_FILE="$TMP_DIR/do-io.lock"
    DO_IO_LOCK_WAIT_SECONDS=3
    DO_LIVE_SYNC_SUMMARY_FILE="$TMP_DIR/do-live-sync-summary.tsv"
    DO_REMOTE_BACKUP_LOG_FILE="$RUNNER_LOG"
    DO_REMOTE_BACKUP_SUMMARY_FILE="$RUNNER_SUMMARY"
    DO_REMOTE_BACKUP_RUN_LOCK="$TMP_DIR/runner.lock"
)

# run SCRIPT [NAME=value ...] [-- ARG ...] runs a copied script with the mocks
# and leaves its exit status in RUN_STATUS and its output in RUN_LOG.
run() {
    local script="$DEPLOY_COPY/scripts/$1"
    local -a settings=()
    shift
    while [[ $# -gt 0 && "$1" != "--" ]]; do
        settings+=("$1")
        shift
    done
    if [[ $# -gt 0 ]]; then
        shift
    fi
    : > "$MOCK_CALLS"
    : > "$MOCK_FLOCK_CALLS"
    RUN_STATUS=0
    env "${common_env[@]}" ${settings[@]+"${settings[@]}"} "$script" "$@" \
        > "$RUN_LOG" 2>&1 || RUN_STATUS=$?
}

count_calls() {
    grep -cF -- "$1" "$MOCK_CALLS" || true
}

# expect_backups LOCAL REMOTE LABEL checks the backup syncs of the last run.
expect_backups() {
    local local_count remote_count
    local_count=$(count_calls " $TMP_DIR/backups/backup-")
    remote_count=$(count_calls ':test-bucket/_backups/')
    [[ "$RUN_STATUS" == 0 ]] || fail "$3: exited $RUN_STATUS"
    [[ "$local_count" == "$1" && "$remote_count" == "$2" ]] ||
        fail "$3: expected $1 local and $2 remote backups, got $local_count and $remote_count"
    [[ "$(count_calls "sync $OUT ")" == 1 ]] || fail "$3: live content was not synced once"
}

expect_log() {
    grep -Fq -- "$1" "$RUN_LOG" || fail "$2"
}

expect_no_log() {
    if grep -Fq -- "$1" "$RUN_LOG"; then
        fail "$2"
    fi
}

expect_no_rclone() {
    [[ ! -s "$MOCK_CALLS" ]] || fail "$1: rclone ran: $(head -1 "$MOCK_CALLS")"
}

mark_today() {
    printf '%s\n' "$TODAY" | tee "$R2_LOCAL_MARKER" "$R2_MARKER" \
        "$DO_LOCAL_MARKER" "$DO_MARKER" >/dev/null
}

clear_markers() {
    rm -f "$R2_LOCAL_MARKER" "$R2_MARKER" "$DO_LOCAL_MARKER" "$DO_MARKER"
}

# --- R2 upload: local and R2 backups ---

mark_today
run allium-deploy-upload-r2.sh
expect_backups 0 0 "R2 default"
expect_no_log 'deprecated' "unset settings logged a deprecation notice"
clear_markers
run allium-deploy-upload-r2.sh
expect_backups 1 1 "R2 default with no markers"
[[ "$(cat "$R2_MARKER")" == "$TODAY" ]] || fail "daily R2 backup did not write its marker"
pass "unset settings mean daily: one backup per day, no notice"

mark_today
run allium-deploy-upload-r2.sh LOCAL_BACKUP_FREQUENCY=daily R2_BACKUP_FREQUENCY=daily
expect_backups 0 0 "R2 daily"
run allium-deploy-upload-r2.sh LOCAL_BACKUP_FREQUENCY=every-run R2_BACKUP_FREQUENCY=every-run
expect_backups 1 1 "R2 every-run"
pass "daily skips after today's marker; every-run ignores it"

clear_markers
run allium-deploy-upload-r2.sh LOCAL_BACKUP_FREQUENCY=off R2_BACKUP_FREQUENCY=off
expect_backups 0 0 "R2 off"
[[ ! -e "$R2_LOCAL_MARKER" && ! -e "$R2_MARKER" ]] || fail "off wrote a backup marker"
expect_log 'Skipping local backup (frequency is off)' "off local backup was not logged"
expect_log 'Skipping remote backup (frequency is off)' "off R2 backup was not logged"
run allium-deploy-upload-r2.sh LOCAL_BACKUP_FREQUENCY=off R2_BACKUP_FREQUENCY=daily
expect_backups 0 1 "R2 local off only"
pass "off skips the R2 run's backups but not live content"

mark_today
run allium-deploy-upload-r2.sh LOCAL_BACKUP_FREQUENCY=off R2_BACKUP_FREQUENCY=off \
    -- --force-backup "$OUT"
expect_backups 1 1 "R2 off with --force-backup"
pass "an explicit --force-backup still takes R2 backups that are off"

mark_today
run allium-deploy-upload-r2.sh DAILY_LOCAL_BACKUP=true DAILY_R2_BACKUP=true
expect_backups 0 0 "legacy true"
expect_log 'DAILY_LOCAL_BACKUP is deprecated; set LOCAL_BACKUP_FREQUENCY=daily instead' \
    "legacy local true did not name LOCAL_BACKUP_FREQUENCY=daily"
expect_log 'DAILY_R2_BACKUP is deprecated; set R2_BACKUP_FREQUENCY=daily instead' \
    "legacy R2 true did not name R2_BACKUP_FREQUENCY=daily"
run allium-deploy-upload-r2.sh DAILY_LOCAL_BACKUP=false DAILY_R2_BACKUP=false
expect_backups 1 1 "legacy false"
expect_log 'DAILY_R2_BACKUP is deprecated; set R2_BACKUP_FREQUENCY=every-run instead' \
    "legacy R2 false did not name R2_BACKUP_FREQUENCY=every-run"
pass "older names still work: true is daily, false is every-run, with a notice"

clear_markers
run allium-deploy-upload-r2.sh R2_BACKUP_FREQUENCY=off DAILY_R2_BACKUP=false
expect_backups 1 0 "new off over legacy false"
expect_log 'DAILY_R2_BACKUP=false is ignored; R2_BACKUP_FREQUENCY=off takes precedence' \
    "conflicting settings did not warn"
mark_today
run allium-deploy-upload-r2.sh R2_BACKUP_FREQUENCY=every-run DAILY_R2_BACKUP=true
expect_backups 0 1 "new every-run over legacy true"
run allium-deploy-upload-r2.sh R2_BACKUP_FREQUENCY=daily DAILY_R2_BACKUP=true
expect_backups 0 0 "agreeing settings"
expect_no_log 'ignored' "agreeing settings warned"
expect_no_log 'deprecated' "a set new name still logged a deprecation notice"
pass "the new setting wins over a disagreeing older one, with a warning"

for setting in R2_BACKUP_FREQUENCY=weekly LOCAL_BACKUP_FREQUENCY=false \
    R2_BACKUP_FREQUENCY=Daily DAILY_R2_BACKUP=off DAILY_LOCAL_BACKUP=no; do
    clear_markers
    run allium-deploy-upload-r2.sh "$setting"
    [[ "$RUN_STATUS" == 2 ]] || fail "R2 $setting exited $RUN_STATUS instead of 2"
    expect_no_rclone "R2 $setting"
    expect_log "${setting%%=*} must be" "R2 $setting did not name the bad setting"
done
pass "invalid R2 run values fail closed before any rclone call"

clear_markers
run allium-deploy-upload-r2.sh R2_BACKUP_FREQUENCY=daily DAILY_R2_BACKUP=off
[[ "$RUN_STATUS" == 2 ]] || fail "an invalid older value beside a valid new one exited $RUN_STATUS instead of 2"
expect_no_rclone "R2 R2_BACKUP_FREQUENCY=daily DAILY_R2_BACKUP=off"
expect_log 'DAILY_R2_BACKUP must be true or false' \
    "an invalid older value beside a valid new one was not named"
pass "an invalid older value fails closed even when the new setting is set"

# --- DO upload: local and DO backups ---

clear_markers
run allium-deploy-upload-do.sh LOCAL_BACKUP_FREQUENCY=off DO_BACKUP_FREQUENCY=off
expect_backups 0 0 "DO inline off"
[[ ! -e "$DO_LOCAL_MARKER" && ! -e "$DO_MARKER" ]] || fail "DO off wrote a backup marker"
[[ $(grep -c -- '^-w ' "$MOCK_FLOCK_CALLS") == 1 ]] ||
    fail "an off DO backup still waited for the DO I/O lock"
pass "off skips the inline DO backups without taking the DO I/O lock"

mark_today
run allium-deploy-upload-do.sh LOCAL_BACKUP_FREQUENCY=every-run DO_BACKUP_FREQUENCY=every-run
expect_backups 1 1 "DO every-run"
run allium-deploy-upload-do.sh DAILY_LOCAL_BACKUP=false DAILY_DO_BACKUP=false
expect_backups 1 1 "DO legacy false"
expect_log 'DAILY_DO_BACKUP is deprecated; set DO_BACKUP_FREQUENCY=every-run instead' \
    "legacy DO false did not name DO_BACKUP_FREQUENCY=every-run"
run allium-deploy-upload-do.sh DAILY_DO_BACKUP=true
expect_backups 0 0 "DO legacy true"
pass "DO inline backups follow every-run and the older DAILY_DO_BACKUP"

run allium-deploy-upload-do.sh LOCAL_BACKUP_FREQUENCY=off DO_BACKUP_FREQUENCY=off \
    -- --force-backup "$OUT"
expect_backups 1 1 "DO off with --force-backup"
pass "an explicit --force-backup still takes DO backups that are off"

clear_markers
run allium-deploy-upload-do.sh DO_REMOTE_BACKUP_INLINE=false DO_BACKUP_FREQUENCY=off
expect_backups 1 0 "DO deferred off"
expect_log 'DO remote backup is off (DO_BACKUP_FREQUENCY=off)' \
    "publication did not log that the deferred DO backup is off"
pass "publication logs an off DO backup instead of deferring it to the runner"

# Production defers the DO snapshot, so the upload's --force-backup cannot take
# it and must say which command does.
for frequency in off daily; do
    mark_today
    run allium-deploy-upload-do.sh DO_REMOTE_BACKUP_INLINE=false \
        LOCAL_BACKUP_FREQUENCY=off DO_BACKUP_FREQUENCY="$frequency" \
        -- --force-backup "$OUT"
    expect_backups 1 0 "DO deferred $frequency with --force-backup"
    expect_log '--force-backup does not take the deferred DO snapshot; run' \
        "deferred $frequency --force-backup did not explain the skipped DO snapshot"
    expect_log '--remote-backup-only --force-backup' \
        "deferred $frequency --force-backup did not name the forcing command"
done
pass "a deferred --force-backup takes only the local backup and names the DO command"

printf 'yesterday\n' > "$DO_MARKER"
run allium-deploy-upload-do.sh DO_BACKUP_FREQUENCY=off -- --remote-backup-only
[[ "$RUN_STATUS" == 0 ]] || fail "remote-backup-only with off exited $RUN_STATUS"
expect_no_rclone "remote-backup-only with off"
[[ "$(cat "$DO_MARKER")" == yesterday ]] || fail "remote-backup-only with off wrote a marker"
expect_log '[DO-Backup]' "remote-backup-only with off did not log the skip"
mark_today
run allium-deploy-upload-do.sh DO_BACKUP_FREQUENCY=every-run -- --remote-backup-only
[[ "$RUN_STATUS" == 0 ]] || fail "remote-backup-only with every-run exited $RUN_STATUS"
[[ "$(count_calls ':test-bucket/_backups/')" == 1 ]] ||
    fail "remote-backup-only with every-run skipped after today's marker"
pass "remote-backup-only exits before rclone when off and repeats for every-run"

printf 'yesterday\n' > "$DO_MARKER"
run allium-deploy-upload-do.sh DO_REMOTE_BACKUP_INLINE=false DO_BACKUP_FREQUENCY=off \
    -- --remote-backup-only --force-backup
[[ "$RUN_STATUS" == 0 ]] || fail "forced remote-backup-only with off exited $RUN_STATUS"
[[ "$(count_calls ':test-bucket/_backups/')" == 1 ]] ||
    fail "forced remote-backup-only with off took no DO snapshot"
[[ "$(count_calls 'sync ')" == 1 ]] || fail "forced remote-backup-only synced more than the snapshot"
grep -F ':test-bucket/_backups/' "$MOCK_CALLS" | grep -Fq -- '--tpslimit=30 ' ||
    fail "forced remote-backup-only did not use the remote-backup transaction rate"
[[ $(grep -c -- '^-w ' "$MOCK_FLOCK_CALLS") == 1 ]] ||
    fail "forced remote-backup-only did not take the DO I/O lock"
[[ "$(cat "$DO_MARKER")" == "$TODAY" ]] || fail "forced remote-backup-only did not write the marker"
mark_today
run allium-deploy-upload-do.sh DO_BACKUP_FREQUENCY=daily -- --remote-backup-only --force-backup
[[ "$RUN_STATUS" == 0 ]] || fail "forced remote-backup-only after today's backup exited $RUN_STATUS"
[[ "$(count_calls ':test-bucket/_backups/')" == 1 ]] ||
    fail "forced remote-backup-only skipped after today's marker"
pass "remote-backup-only --force-backup takes a DO snapshot even when off or done today"

run allium-deploy-upload-do.sh -- --help
expect_log '--remote-backup-only --force-backup' "DO help does not name the forced DO snapshot"
expect_log 'forces only' "DO help does not explain --force-backup with a deferred snapshot"
pass "DO help documents the forced DO snapshot"

for setting in DO_BACKUP_FREQUENCY=sometimes DAILY_DO_BACKUP=0 LOCAL_BACKUP_FREQUENCY=never; do
    clear_markers
    run allium-deploy-upload-do.sh "$setting"
    [[ "$RUN_STATUS" == 2 ]] || fail "DO $setting exited $RUN_STATUS instead of 2"
    expect_no_rclone "DO $setting"
    run allium-deploy-upload-do.sh "$setting" -- --remote-backup-only
    [[ "$RUN_STATUS" == 2 ]] || fail "remote-backup-only $setting exited $RUN_STATUS instead of 2"
    expect_no_rclone "remote-backup-only $setting"
    expect_log "${setting%%=*} must be" "remote-backup-only $setting did not name the bad setting"
done
pass "invalid DO run values fail closed before any rclone call"

# --- Hourly DO runner ---

printf 'yesterday\n' > "$DO_MARKER"
run run-do-remote-backup.sh DO_BACKUP_FREQUENCY=off
[[ "$RUN_STATUS" == 0 ]] || fail "runner with off exited $RUN_STATUS"
expect_no_rclone "runner with off"
[[ ! -s "$RUN_LOG" ]] || fail "runner with off wrote cron output"
[[ ! -e "$RUNNER_SUMMARY" && ! -e "$RUNNER_LOG" ]] ||
    fail "runner with off wrote a summary row or log"
[[ "$(cat "$DO_MARKER")" == yesterday ]] || fail "runner with off wrote a marker"
pass "hourly runner exits quietly without a backup or summary row when off"

run run-do-remote-backup.sh DAILY_DO_BACKUP=false DAILY_LOCAL_BACKUP=true
[[ "$RUN_STATUS" == 0 ]] || fail "runner with legacy false exited $RUN_STATUS"
[[ "$(count_calls ':test-bucket/_backups/')" == 1 ]] || fail "runner did not take the due backup"
[[ ! -s "$RUN_LOG" ]] || fail "runner wrote the deprecation notice to cron output"
grep -Fq '[DO-Backup] ℹ️  DAILY_DO_BACKUP is deprecated' "$RUNNER_LOG" ||
    fail "runner log is missing the [DO-Backup] deprecation notice"
if grep -Fq 'DAILY_LOCAL_BACKUP' "$RUNNER_LOG"; then
    fail "runner log has a notice about local backups, which the runner never takes"
fi
summary_size=$(wc -c < "$RUNNER_SUMMARY" | tr -d ' ')
run run-do-remote-backup.sh DO_BACKUP_FREQUENCY=every-run
expect_no_rclone "runner after today's backup with every-run"
[[ $(wc -c < "$RUNNER_SUMMARY" | tr -d ' ') == "$summary_size" ]] ||
    fail "runner with every-run appended a second row today"
pass "hourly runner keeps one snapshot per day for every-run"

printf 'yesterday\n' > "$DO_MARKER"
rm -f "$RUNNER_SUMMARY"
run run-do-remote-backup.sh DO_BACKUP_FREQUENCY=hourly
[[ "$RUN_STATUS" == 2 ]] || fail "runner with an invalid value exited $RUN_STATUS instead of 2"
expect_no_rclone "runner with an invalid value"
expect_log 'DO_BACKUP_FREQUENCY must be daily, every-run or off' \
    "runner did not report the invalid value"
[[ ! -e "$RUNNER_SUMMARY" ]] || fail "runner with an invalid value wrote a summary row"
pass "hourly runner fails closed on an invalid value"

# A backup whose sync fails is not marked done, so a later run retries it
# instead of skipping today's backup.
rm -f "$R2_LOCAL_MARKER" "$R2_MARKER"
run allium-deploy-upload-r2.sh MOCK_FAIL_BACKUPS=1 LOCAL_BACKUP_FREQUENCY=daily R2_BACKUP_FREQUENCY=daily
[[ "$RUN_STATUS" == 0 ]] || fail "R2 run with failing backups exited $RUN_STATUS"
[[ ! -e "$R2_LOCAL_MARKER" && ! -e "$R2_MARKER" ]] || fail "a failed backup sync wrote its marker"
expect_log "Local backup failed (rclone exit 7); today's backup is not marked done" "failed local backup was not reported"
expect_log "Remote backup failed (rclone exit 7); today's backup is not marked done" "failed remote backup was not reported"
expect_no_log 'Remote backup created' "a failed remote backup was reported as created"
pass "a backup whose sync fails writes no marker and the live sync still runs"

printf 'yesterday\n' > "$DO_MARKER"
run allium-deploy-upload-do.sh MOCK_FAIL_BACKUPS=1 DO_BACKUP_FREQUENCY=daily -- --remote-backup-only
[[ "$RUN_STATUS" == 7 ]] || fail "failed remote-backup-only exited $RUN_STATUS instead of rclone's 7"
[[ "$(cat "$DO_MARKER")" == yesterday ]] || fail "failed remote-backup-only marked today's backup done"
pass "a failed DO snapshot exits with rclone's status and leaves the marker for the hourly retry"

