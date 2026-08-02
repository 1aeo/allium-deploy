#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d /tmp/allium-do-backup-test.XXXXXX)"
REPO_TMP_DIR="$(mktemp -d "$ROOT_DIR/logs/test-do-backup-runner.XXXXXX")"
trap 'rm -rf "$TMP_DIR" "$REPO_TMP_DIR"' EXIT

fail() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

MOCK_RCLONE="$TMP_DIR/rclone"
MOCK_CALLS="$TMP_DIR/calls"
MOCK_BIN="$TMP_DIR/mock-bin"
MOCK_FLOCK_CALLS="$TMP_DIR/flock-calls"
mkdir -p "$MOCK_BIN"
# The quoted lines are the literal body of the generated mock executable.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'case "${1:-}" in' \
    '  listremotes) printf "spaces-metrics:\n" ;;' \
    '  sync) printf "%s\n" "$*" >> "$MOCK_RCLONE_CALLS" ;;' \
    '  *) ;;' \
    'esac' \
    > "$MOCK_RCLONE"
chmod 0755 "$MOCK_RCLONE"
# The production host provides util-linux flock. This test stub records the
# exact bounded lock contract without requiring that non-Linux workstations
# install flock.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\n" "$*" >> "$MOCK_FLOCK_CALLS"' \
    'exit "${MOCK_FLOCK_EXIT:-0}"' \
    > "$MOCK_BIN/flock"
chmod 0755 "$MOCK_BIN/flock"

mkdir -p "$TMP_DIR/output" "$TMP_DIR/backups"
printf '<html>test</html>\n' > "$TMP_DIR/output/index.html"
TODAY=$(date '+%Y-%m-%d')
printf '%s\n' "$TODAY" > "$TMP_DIR/local-marker"

common_env=(
    PATH="$MOCK_BIN:$PATH"
    MOCK_RCLONE_CALLS="$MOCK_CALLS"
    MOCK_FLOCK_CALLS="$MOCK_FLOCK_CALLS"
    RCLONE_PATH="$MOCK_RCLONE"
    OUTPUT_DIR="$TMP_DIR/output"
    BACKUP_DIR="$TMP_DIR/backups"
    DO_SPACES_BUCKET=test-bucket
    DO_SPACES_KEY=test-key
    DO_SPACES_SECRET=test-secret
    DO_LOCAL_BACKUP_MARKER="$TMP_DIR/local-marker"
    DO_REMOTE_BACKUP_MARKER="$TMP_DIR/remote-marker"
    DO_IO_LOCK_FILE="$TMP_DIR/do-io.lock"
    DO_IO_LOCK_WAIT_SECONDS=3
)

env "${common_env[@]}" DO_REMOTE_BACKUP_INLINE=false \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" "$TMP_DIR/output" >/dev/null
[[ $(wc -l < "$MOCK_CALLS" | tr -d ' ') == 1 ]] || \
    fail "normal publication invoked more than one rclone sync"
grep -Fq "$TMP_DIR/output spaces-metrics:test-bucket" "$MOCK_CALLS" || \
    fail "normal publication did not update the live bucket"
if grep -Fq 'spaces-metrics:test-bucket/_backups/' "$MOCK_CALLS"; then
    fail "normal publication created an inline remote backup"
fi
grep -Fq -- '-w 3 8' "$MOCK_FLOCK_CALLS" || \
    fail "normal publication did not acquire the bounded DO I/O lock"
pass "normal DO publication skips only the deferred remote backup"

: > "$MOCK_CALLS"
env "${common_env[@]}" \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" --remote-backup-only >/dev/null
[[ $(wc -l < "$MOCK_CALLS" | tr -d ' ') == 1 ]] || \
    fail "remote-backup-only invoked an unexpected number of syncs"
grep -Fq 'spaces-metrics:test-bucket spaces-metrics:test-bucket/_backups/' "$MOCK_CALLS" || \
    fail "remote-backup-only did not copy the live bucket to a snapshot"
grep -Fq -- '--tpslimit=30' "$MOCK_CALLS" || \
    fail "remote-backup-only did not use its bounded transaction rate"
[[ "$(cat "$TMP_DIR/remote-marker")" == "$TODAY" ]] || \
    fail "remote-backup-only did not write the daily marker"
pass "independent DO remote backup preserves the daily snapshot marker"

: > "$MOCK_CALLS"
env "${common_env[@]}" \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" --remote-backup-only >/dev/null
[[ ! -s "$MOCK_CALLS" ]] || fail "completed remote backup ran twice in one day"
pass "independent DO remote backup skips after today's success"

printf 'yesterday\n' > "$TMP_DIR/remote-marker"
: > "$MOCK_CALLS"
if env "${common_env[@]}" MOCK_FLOCK_EXIT=1 \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" --remote-backup-only \
    >/dev/null 2>&1; then
    fail "remote backup ignored an I/O lock timeout"
fi
[[ ! -s "$MOCK_CALLS" ]] || fail "timed-out remote backup invoked rclone"
pass "live and backup mutation use a bounded fail-closed serialization lock"

printf 'yesterday\n' > "$TMP_DIR/remote-marker"
: > "$MOCK_CALLS"
env "${common_env[@]}" \
    DO_REMOTE_BACKUP_LOG_FILE="$REPO_TMP_DIR/runner.log" \
    DO_REMOTE_BACKUP_SUMMARY_FILE="$REPO_TMP_DIR/runner-summary.tsv" \
    DO_REMOTE_BACKUP_RUN_LOCK="$TMP_DIR/runner.lock" \
    "$ROOT_DIR/scripts/run-do-remote-backup.sh"
grep -Fq $'exit_status\tduration_seconds\tmarker' \
    "$REPO_TMP_DIR/runner-summary.tsv" || fail "runner summary header is missing"
grep -Fq $'\t0\t' "$REPO_TMP_DIR/runner-summary.tsv" || \
    fail "runner did not record a successful bounded row"
[[ "$(cat "$TMP_DIR/remote-marker")" == "$TODAY" ]] || \
    fail "runner did not complete today's remote backup"
summary_size=$(wc -c < "$REPO_TMP_DIR/runner-summary.tsv" | tr -d ' ')
env "${common_env[@]}" \
    DO_REMOTE_BACKUP_LOG_FILE="$REPO_TMP_DIR/runner.log" \
    DO_REMOTE_BACKUP_SUMMARY_FILE="$REPO_TMP_DIR/runner-summary.tsv" \
    DO_REMOTE_BACKUP_RUN_LOCK="$TMP_DIR/runner.lock" \
    "$ROOT_DIR/scripts/run-do-remote-backup.sh"
[[ $(wc -c < "$REPO_TMP_DIR/runner-summary.tsv" | tr -d ' ') == "$summary_size" ]] || \
    fail "runner appended noise after today's success marker"
pass "hourly backup runner records one bounded row and becomes quiet"
