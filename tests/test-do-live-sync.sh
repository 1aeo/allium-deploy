#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d /tmp/allium-do-live-sync-test.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT
# Run copies of the scripts so a deployed config.env in this checkout can never
# replace the mocks and point a test sync at a real bucket.
DEPLOY_COPY="$TMP_DIR/deploy"
mkdir -p "$DEPLOY_COPY/scripts"
cp "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" \
    "$ROOT_DIR/scripts/allium-deploy-upload-common.sh" \
    "$DEPLOY_COPY/scripts/"
UPLOAD_DO="$DEPLOY_COPY/scripts/allium-deploy-upload-do.sh"

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
SUMMARY="$TMP_DIR/do-live-sync-summary.tsv"
RUN_LOG="$TMP_DIR/run.log"
mkdir -p "$MOCK_BIN"
# Records each sync on one line and fails syncs whose arguments contain
# MOCK_FAIL_MATCH with MOCK_FAIL_EXIT, after printing like a real run would.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'case "${1:-}" in' \
    '  listremotes) printf "spaces-metrics:\n" ;;' \
    '  sync)' \
    '    printf "%s\n" "$*" >> "$MOCK_RCLONE_CALLS"' \
    '    printf "NOTICE: mock transfer stats\n"' \
    '    if [[ -n "${MOCK_FAIL_MATCH:-}" && "$*" == *"$MOCK_FAIL_MATCH"* ]]; then' \
    '      printf "ERROR: mock failure\n" >&2' \
    '      exit "${MOCK_FAIL_EXIT:-7}"' \
    '    fi' \
    '    ;;' \
    '  *) ;;' \
    'esac' \
    > "$MOCK_RCLONE"
chmod 0755 "$MOCK_RCLONE"
# The production host provides util-linux flock; this stub keeps the test
# portable and lets it simulate a lock timeout.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\n" "$*" >> "$MOCK_FLOCK_CALLS"' \
    'exit "${MOCK_FLOCK_EXIT:-0}"' \
    > "$MOCK_BIN/flock"
chmod 0755 "$MOCK_BIN/flock"

OUT="$TMP_DIR/output"
mkdir -p "$OUT/relay/AAAA" "$OUT/family/BBBB" "$OUT/misc" "$TMP_DIR/backups"
printf '<html>root</html>\n' > "$OUT/index.html"
printf '<html>relay</html>\n' > "$OUT/relay/AAAA/index.html"
printf '<html>family</html>\n' > "$OUT/family/BBBB/index.html"
printf '<html>misc</html>\n' > "$OUT/misc/all.html"
TODAY=$(date '+%Y-%m-%d')
printf '%s\n' "$TODAY" > "$TMP_DIR/local-marker"

common_env=(
    PATH="$MOCK_BIN:$PATH"
    MOCK_RCLONE_CALLS="$MOCK_CALLS"
    MOCK_FLOCK_CALLS="$MOCK_FLOCK_CALLS"
    RCLONE_PATH="$MOCK_RCLONE"
    OUTPUT_DIR="$OUT"
    BACKUP_DIR="$TMP_DIR/backups"
    DO_SPACES_BUCKET=test-bucket
    DO_SPACES_KEY=test-key
    DO_SPACES_SECRET=test-secret
    DO_LOCAL_BACKUP_MARKER="$TMP_DIR/local-marker"
    DO_REMOTE_BACKUP_MARKER="$TMP_DIR/remote-marker"
    DO_REMOTE_BACKUP_INLINE=false
    DO_IO_LOCK_FILE="$TMP_DIR/do-io.lock"
    DO_IO_LOCK_WAIT_SECONDS=3
    DO_LIVE_SYNC_SUMMARY_FILE="$SUMMARY"
)

run_do() {
    : > "$MOCK_CALLS"
    rm -f "$SUMMARY"
    local status=0
    env "${common_env[@]}" "$@" "$UPLOAD_DO" "$OUT" > "$RUN_LOG" 2>&1 || status=$?
    return "$status"
}

sync_count() {
    wc -l < "$MOCK_CALLS" | tr -d ' '
}

summary_field() {
    awk -F '\t' -v field="$1" 'NR == 2 { print $field }' "$SUMMARY"
}

# Default configuration keeps today's single directory-traversal sync.
run_do || fail "default live sync failed"
[[ "$(sync_count)" == 1 ]] || fail "default live sync did not run exactly one rclone sync"
grep -Fq "sync $OUT spaces-metrics:test-bucket --exclude _backups/**" "$MOCK_CALLS" || \
    fail "default live sync did not sync the whole tree"
if grep -Eq -- '--fast-list|--checksum|--s3-no-head' "$MOCK_CALLS"; then
    fail "default live sync enabled fast-list, checksum or no-head"
fi
default_call="sync $OUT spaces-metrics:test-bucket --exclude _backups/** --transfers=56 --checkers=80"
default_call+=" --buffer-size=128M --s3-upload-concurrency=32 --s3-chunk-size=16M --tpslimit=120"
default_call+=" --tpslimit-burst=1 --s3-disable-http2 --exclude=_headers --exclude=/.assetsignore --exclude=/_redirects"
default_call+=" --stats=10s --stats-one-line"
default_call+=" --log-level=NOTICE --stats-log-level=NOTICE --retries=5 --retries-sleep=2s --low-level-retries=10"
[[ "$(cat "$MOCK_CALLS")" == "$default_call" ]] || \
    fail "default live sync command changed: $(cat "$MOCK_CALLS")"
grep -Fq $'started_utc\tfinished_utc\texit_status\tduration_seconds\tchecksum\tlisting' "$SUMMARY" || \
    fail "summary header is missing"
[[ "$(summary_field 3)" == 0 && "$(summary_field 5)" == false && "$(summary_field 6)" == traversal ]] || \
    fail "default summary row is wrong: $(sed -n 2p "$SUMMARY")"
grep -Fq '✅ Upload complete' "$RUN_LOG" || fail "successful sync did not report completion"
pass "default DO live sync is one traversal sync with a summary row"

# A failed rclone sync must fail the uploader instead of reporting success.
if run_do MOCK_FAIL_MATCH="spaces-metrics:test-bucket" MOCK_FAIL_EXIT=5; then
    fail "failed rclone sync was reported as success"
fi
status=0
run_do MOCK_FAIL_MATCH="spaces-metrics:test-bucket" MOCK_FAIL_EXIT=5 || status=$?
[[ "$status" == 5 ]] || fail "uploader exit $status did not carry rclone's exit 5"
if grep -Fq '✅ Upload complete' "$RUN_LOG"; then
    fail "failed rclone sync logged completion"
fi
[[ "$(summary_field 3)" == 5 ]] || fail "summary did not record rclone's exit status"
pass "rclone failure inside the DO lock propagates exit status and summary"

# Checksum comparison is opt-in.
run_do DO_RCLONE_CHECKSUM=true || fail "checksum live sync failed"
grep -Fq -- '--checksum' "$MOCK_CALLS" || fail "DO_RCLONE_CHECKSUM=true did not pass --checksum"
[[ "$(summary_field 5)" == true ]] || fail "summary did not record checksum mode"
pass "DO_RCLONE_CHECKSUM=true compares listing checksums"

# Skipping the post-upload HEAD is opt-in, reaches every live-sync pass, and
# adds only --s3-no-head to the production-shaped command lines.
run_do DO_RCLONE_CHECKSUM=true DO_RCLONE_FAST_LIST_SUBTREES="relay family" || \
    fail "checksum subtree live sync failed"
cp "$MOCK_CALLS" "$TMP_DIR/checksum-calls"
if grep -Fq -- '--s3-no-head' "$TMP_DIR/checksum-calls"; then
    fail "--s3-no-head was passed without DO_RCLONE_NO_HEAD=true"
fi
grep -Fq 'Skip post-upload HEAD: false' "$RUN_LOG" || fail "header did not log the default HEAD setting"
run_do DO_RCLONE_CHECKSUM=true DO_RCLONE_FAST_LIST_SUBTREES="relay family" DO_RCLONE_NO_HEAD=true || \
    fail "no-head subtree live sync failed"
[[ "$(sync_count)" == 3 && "$(grep -c -- ' --checksum --s3-no-head ' "$MOCK_CALLS")" == 3 ]] || \
    fail "not every live-sync pass skipped the HEAD: $(cat "$MOCK_CALLS")"
[[ "$(sed 's/ --s3-no-head / /' "$MOCK_CALLS")" == "$(cat "$TMP_DIR/checksum-calls")" ]] || \
    fail "DO_RCLONE_NO_HEAD=true changed more than --s3-no-head"
grep -Fq 'Skip post-upload HEAD: true' "$RUN_LOG" || fail "header did not log the skipped HEAD"
run_do DO_RCLONE_CHECKSUM=true DO_RCLONE_NO_HEAD=true || fail "no-head single live sync failed"
{ [[ "$(sync_count)" == 1 ]] && grep -Fq -- ' --checksum --s3-no-head ' "$MOCK_CALLS"; } || \
    fail "single-pass live sync did not skip the HEAD"
pass "DO_RCLONE_NO_HEAD=true adds --s3-no-head to every live-sync pass"

# Backups keep the HEAD: inline backups on --force-backup and the independent
# remote-backup runner.
: > "$MOCK_CALLS"
env "${common_env[@]}" DO_RCLONE_CHECKSUM=true DO_RCLONE_NO_HEAD=true DO_REMOTE_BACKUP_INLINE=true \
    "$UPLOAD_DO" --force-backup "$OUT" > "$RUN_LOG" 2>&1 || fail "no-head forced backup run failed"
[[ "$(sync_count)" == 3 ]] || fail "expected local backup, remote backup and live sync, got $(sync_count)"
[[ "$(grep -c -- '--s3-no-head' "$MOCK_CALLS")" == 1 && "$(tail -n 1 "$MOCK_CALLS")" == *" --s3-no-head "* ]] || \
    fail "--s3-no-head reached a backup: $(cat "$MOCK_CALLS")"
: > "$MOCK_CALLS"
env "${common_env[@]}" DO_RCLONE_CHECKSUM=true DO_RCLONE_NO_HEAD=true \
    DO_REMOTE_BACKUP_MARKER="$TMP_DIR/remote-only-marker" \
    "$UPLOAD_DO" --remote-backup-only > "$RUN_LOG" 2>&1 || fail "no-head remote backup run failed"
[[ "$(sync_count)" == 1 ]] || fail "remote backup runner did not run one sync"
if grep -Fq -- '--s3-no-head' "$MOCK_CALLS"; then
    fail "--s3-no-head reached the independent remote backup"
fi
pass "DO_RCLONE_NO_HEAD leaves the local and remote backups unchanged"

# Per-subtree fast-list: each present subtree on its own prefix, then the rest.
run_do DO_RCLONE_FAST_LIST_SUBTREES="relay, family gone" || fail "subtree live sync failed"
[[ "$(sync_count)" == 3 ]] || fail "expected 2 subtree passes and 1 final pass, got $(sync_count)"
sed -n 1p "$MOCK_CALLS" | grep -Fq "sync $OUT/relay spaces-metrics:test-bucket/relay " || \
    fail "first pass was not the relay subtree"
sed -n 2p "$MOCK_CALLS" | grep -Fq "sync $OUT/family spaces-metrics:test-bucket/family " || \
    fail "second pass was not the family subtree"
for line in 1 2; do
    sed -n "${line}p" "$MOCK_CALLS" | grep -Fq -- '--fast-list' || \
        fail "subtree pass $line did not use --fast-list"
done
final_pass=$(sed -n 3p "$MOCK_CALLS")
[[ "$final_pass" == "sync $OUT spaces-metrics:test-bucket "* ]] || \
    fail "final pass did not sync the whole tree"
[[ "$final_pass" == *"--exclude _backups/** --exclude /relay/** --exclude /family/**"* ]] || \
    fail "final pass did not exclude _backups and the synced subtrees: $final_pass"
[[ "$final_pass" != *"--fast-list"* ]] || fail "final pass used --fast-list over the root"
[[ "$final_pass" != *"/gone/"* ]] || fail "absent subtree was excluded from the final pass"
[[ "$(summary_field 6)" == "fast-list:relay,family,gone" ]] || \
    fail "summary did not record the subtree listing mode"
# The root's Workers control files are excluded, anchored, only from the pass
# over the output root; subtree passes keep files of those names, which are
# ordinary content below the root.
[[ "$(grep -Fc -- ' --exclude=_headers --exclude=/.assetsignore --exclude=/_redirects ' "$MOCK_CALLS")" == 1 ]] || \
    fail "the root pass did not exclude the root control files: $(cat "$MOCK_CALLS")"
[[ "$(sed -n 3p "$MOCK_CALLS")" == *' --exclude=_headers --exclude=/.assetsignore --exclude=/_redirects '* ]] || \
    fail "the final root pass did not carry the anchored excludes: $(sed -n 3p "$MOCK_CALLS")"
for line in 1 2; do
    sed -n "${line}p" "$MOCK_CALLS" | grep -Eq -- '--exclude=/?(\.assetsignore|_redirects)' && \
        fail "subtree pass $line excluded control-file names: $(sed -n "${line}p" "$MOCK_CALLS")"
done
pass "per-subtree fast-list syncs each tree on its own prefix and the rest by traversal"

# A failed subtree pass fails the upload and skips the remaining passes, so a
# DO outage costs one pass's retries instead of every pass's.
status=0
run_do DO_RCLONE_FAST_LIST_SUBTREES="relay family" \
    MOCK_FAIL_MATCH="spaces-metrics:test-bucket/relay" MOCK_FAIL_EXIT=7 || status=$?
[[ "$status" == 7 ]] || fail "failed subtree pass returned $status instead of 7"
[[ "$(sync_count)" == 1 ]] || fail "passes after a failed subtree pass still ran"
if grep -Fq '✅ Upload complete' "$RUN_LOG"; then
    fail "failed subtree pass logged completion"
fi
[[ "$(summary_field 3)" == 7 ]] || fail "summary did not record the failed subtree exit"
pass "a failed subtree pass fails the upload and skips the remaining passes"

# A failure in the final pass is reported after every subtree pass ran.
status=0
run_do DO_RCLONE_FAST_LIST_SUBTREES="relay family" \
    MOCK_FAIL_MATCH="--exclude /relay/**" MOCK_FAIL_EXIT=5 || status=$?
[[ "$status" == 5 ]] || fail "failed final pass returned $status instead of 5"
[[ "$(sync_count)" == 3 ]] || fail "final-pass failure test did not run every pass"
[[ "$(summary_field 3)" == 5 ]] || fail "summary did not record the failed final pass"
pass "a failed final pass fails the upload"

# Root fast-list keeps its single-pass behavior.
run_do DO_RCLONE_FAST_LIST=true DO_RCLONE_FAST_LIST_SUBTREES="relay family" || \
    fail "root fast-list live sync failed"
[[ "$(sync_count)" == 1 ]] || fail "root fast-list ran subtree passes"
grep -Fq -- '--fast-list' "$MOCK_CALLS" || fail "root fast-list did not pass --fast-list"
[[ "$(summary_field 6)" == "fast-list" ]] || fail "summary did not record root fast-list"
pass "DO_RCLONE_FAST_LIST=true keeps one root fast-list sync"

# Invalid subtree names and checksum values fail closed before any sync.
for bad in "../etc" "_backups" "relay/AAAA" "*" "relay,,family" "relay relay" $'relay\nfamily'; do
    if run_do DO_RCLONE_FAST_LIST_SUBTREES="$bad"; then
        fail "invalid subtree list '$bad' was accepted"
    fi
    [[ ! -s "$MOCK_CALLS" ]] || fail "invalid subtree list '$bad' still ran rclone sync"
done
if run_do DO_RCLONE_CHECKSUM=maybe; then
    fail "invalid DO_RCLONE_CHECKSUM was accepted"
fi
[[ ! -s "$MOCK_CALLS" ]] || fail "invalid DO_RCLONE_CHECKSUM still ran rclone sync"
pass "invalid subtree and checksum settings fail closed"

# An invalid DO_RCLONE_NO_HEAD, or one without checksum comparison, fails
# before the due local backup or any sync runs.
expect_no_head_failure() {
    local message="$1"
    local status=0
    shift
    run_do "$@" DO_LOCAL_BACKUP_MARKER="$TMP_DIR/due-local-marker" || status=$?
    [[ "$status" == 2 ]] || fail "$* returned $status instead of 2"
    [[ ! -s "$MOCK_CALLS" ]] || fail "$* still ran rclone sync"
    grep -Fq "$message" "$RUN_LOG" || fail "$* did not report: $message"
}
expect_no_head_failure 'DO_RCLONE_NO_HEAD must be true or false (got: yes)' \
    DO_RCLONE_NO_HEAD=yes DO_RCLONE_CHECKSUM=true
expect_no_head_failure 'DO_RCLONE_NO_HEAD=true requires DO_RCLONE_CHECKSUM=true' \
    DO_RCLONE_NO_HEAD=true
expect_no_head_failure 'DO_RCLONE_NO_HEAD=true requires DO_RCLONE_CHECKSUM=true' \
    DO_RCLONE_NO_HEAD=true DO_RCLONE_CHECKSUM=false
pass "invalid or checksum-less DO_RCLONE_NO_HEAD fails closed before backups and sync"

# A DO I/O lock timeout is recorded as a failed attempt.
status=0
run_do MOCK_FLOCK_EXIT=1 || status=$?
[[ "$status" == 1 ]] || fail "lock timeout returned $status instead of 1"
[[ ! -s "$MOCK_CALLS" ]] || fail "lock timeout still ran rclone sync"
[[ "$(summary_field 3)" == 1 ]] || fail "summary did not record the lock timeout"
pass "DO I/O lock timeout is recorded in the live-sync summary"

# --force-backup keeps the DO transfer and transaction-rate caps.
: > "$MOCK_CALLS"
env "${common_env[@]}" "$UPLOAD_DO" --force-backup "$OUT" > "$RUN_LOG" 2>&1 || \
    fail "forced backup run failed"
[[ "$(sync_count)" == 2 ]] || fail "forced backup did not run the local backup and live sync"
while IFS= read -r call; do
    [[ "$call" == *"--transfers=56 "* && "$call" == *"--tpslimit=120 "* ]] || \
        fail "--force-backup dropped the DO caps: $call"
done < "$MOCK_CALLS"
pass "--force-backup keeps the DO transfer and transaction-rate caps"
