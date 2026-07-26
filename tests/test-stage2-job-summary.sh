#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "not ok - $1"
    exit 1
}

pass() {
    echo "ok - $1"
}

export ALLIUM_DEPLOY_TEST_MODE=1
export CF_ASSETS_ENABLED=true
export CF_ASSETS_CONSECUTIVE_FILE="$TMP_DIR/consecutive"
export CF_ASSETS_JOB_SUMMARY_FILE="$TMP_DIR/jobs.tsv"
export CF_ASSETS_MAX_JOB_SECONDS=1800

# shellcheck source=../scripts/allium-deploy-update.sh
source "$ROOT_DIR/scripts/allium-deploy-update.sh"

assert_latest_row() {
    local expected="$1"
    local actual
    actual=$(tail -n 1 "$CF_ASSETS_JOB_SUMMARY_FILE")
    [[ "$actual" == "$expected" ]] || fail "unexpected job row: $actual"
}

printf '7\n' > "$CF_ASSETS_CONSECUTIVE_FILE"
record_stage2_job_result 0 100 '2026-07-26T20:00:00Z' 200 '2026-07-26T20:01:40Z'
[[ "$(cat "$CF_ASSETS_CONSECUTIVE_FILE")" == "7" ]] || fail "successful job reset counter"
assert_latest_row $'2026-07-26T20:00:00Z\t2026-07-26T20:01:40Z\t0\t100\ttrue\t7'
pass "successful scheduled job preserves the streak"

printf '8\n' > "$CF_ASSETS_CONSECUTIVE_FILE"
record_stage2_job_result 1 200 '2026-07-26T20:02:00Z' 210 '2026-07-26T20:02:10Z'
[[ "$(cat "$CF_ASSETS_CONSECUTIVE_FILE")" == "0" ]] || fail "failed job did not reset counter"
assert_latest_row $'2026-07-26T20:02:00Z\t2026-07-26T20:02:10Z\t1\t10\ttrue\t0'
pass "failure outside the Worker child resets the streak"

printf '9\n' > "$CF_ASSETS_CONSECUTIVE_FILE"
record_stage2_job_result 0 300 '2026-07-26T20:03:00Z' 2101 '2026-07-26T20:33:01Z'
[[ "$(cat "$CF_ASSETS_CONSECUTIVE_FILE")" == "0" ]] || fail "over-cadence job did not reset counter"
assert_latest_row $'2026-07-26T20:03:00Z\t2026-07-26T20:33:01Z\t0\t1801\tfalse\t0'
pass "runtime beyond the scheduler interval resets the streak"

printf '10\n' > "$CF_ASSETS_CONSECUTIVE_FILE"
record_stage2_job_result 0 400 '2026-07-26T20:04:00Z' 2200 '2026-07-26T20:34:00Z'
[[ "$(cat "$CF_ASSETS_CONSECUTIVE_FILE")" == "10" ]] || fail "exact interval unexpectedly reset counter"
assert_latest_row $'2026-07-26T20:04:00Z\t2026-07-26T20:34:00Z\t0\t1800\ttrue\t10'
pass "exact scheduler interval is not classified as exceeding it"

[[ "$(head -n 1 "$CF_ASSETS_JOB_SUMMARY_FILE")" == $'started_utc\tfinished_utc\texit_status\ttotal_duration_seconds\tcadence_ok\tshadow_counter' ]] \
    || fail "job summary header is incorrect"
[[ "$(wc -l < "$CF_ASSETS_JOB_SUMMARY_FILE" | tr -d ' ')" == "5" ]] \
    || fail "job summary should contain one header and four bounded rows"
pass "job summary remains one bounded row per invocation"
