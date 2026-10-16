#!/usr/bin/env bash
# Behaviour of publish_in_restore_order in allium-deploy-update.sh: the Workers
# version is promoted as soon as it verifies, then DO Spaces and R2 are waited
# for in that order, each publisher's duration is its own, and every outcome the
# job's exit decision depends on is unchanged. With CHARTS_LAYOUT=charts the
# charts Worker is promoted and its production route checked before the main
# Worker is promoted, and a charts failure withholds that promotion and leaves
# no promotable main version, except an inconclusive route check or
# CF_CHARTS_ALLOW_STALE=true in a build that keeps the promoted layout. Also:
# the layout marker, the failure classes, the charts timing row and the
# heartbeat's warning pings.
# Publishers are stubs that record start/end events and sleep for a set time.
# The function runs with errexit on, as in production.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
REAL_MKTEMP="$(command -v mktemp)"
PUBLISHING=""

cleanup() {
    local status=$?
    if [[ -n "$PUBLISHING" ]]; then
        echo "not ok - publish_in_restore_order aborted under errexit (exit $status) in case: $PUBLISHING" >&2
    fi
    # shellcheck disable=SC2046 # one PID per word
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

STUB_DIR="$TMP_DIR/scripts"
STUB_BIN="$TMP_DIR/bin"
STATE_TMP="$TMP_DIR/state-tmp"
EVENTS="$TMP_DIR/events"
mkdir -p "$STUB_DIR" "$STUB_BIN" "$STATE_TMP" "$TMP_DIR/out"

# A storage publisher stub. <exit variable>=kill makes it kill itself with SIGKILL.
write_publisher() {
    local file="$1" name="$2" sleep_var="$3" exit_var="$4"
    cat > "$STUB_DIR/$file" <<STUB
#!/usr/bin/env bash
printf '%s start\\n' "$name" >> "\$TEST_EVENTS"
sleep "\${$sleep_var:-0}"
printf '%s end\\n' "$name" >> "\$TEST_EVENTS"
[[ "\${$exit_var:-0}" != kill ]] || kill -KILL \$\$
exit "\${$exit_var:-0}"
STUB
    chmod +x "$STUB_DIR/$file"
}
write_publisher allium-deploy-upload-do.sh "do" DO_SLEEP DO_STUB_EXIT
write_publisher allium-deploy-upload-r2.sh r2 R2_SLEEP R2_STUB_EXIT

# The Workers stub serves both --upload-only and the promoter's --promote.
cat > "$STUB_DIR/allium-deploy-cfassets.sh" <<'STUB'
#!/usr/bin/env bash
case "$1" in
    --upload-only)
        printf 'cfassets start\n' >> "$TEST_EVENTS"
        sleep "${CF_SLEEP:-0}"
        printf 'cfassets end\n' >> "$TEST_EVENTS"
        exit "${CF_STUB_EXIT:-0}"
        ;;
    --promote)
        printf 'promote\n' >> "$TEST_EVENTS"
        exit "${PROMOTE_STUB_EXIT:-0}"
        ;;
esac
exit 64
STUB
chmod +x "$STUB_DIR/allium-deploy-cfassets.sh"

# The charts Worker stub serves the upload, its promotion and the two
# production checks.
cat > "$STUB_DIR/allium-deploy-cfcharts.sh" <<'STUB'
#!/usr/bin/env bash
case "$1" in
    --upload-only)
        printf 'cfcharts start\n' >> "$TEST_EVENTS"
        sleep "${CHARTS_SLEEP:-0}"
        printf 'cfcharts end\n' >> "$TEST_EVENTS"
        exit "${CHARTS_STUB_EXIT:-0}"
        ;;
    --promote)
        printf 'cfcharts promote\n' >> "$TEST_EVENTS"
        exit "${CHARTS_PROMOTE_STUB_EXIT:-0}"
        ;;
    --check-route)
        printf 'cfcharts check-route\n' >> "$TEST_EVENTS"
        exit "${ROUTE_STUB_EXIT:-0}"
        ;;
    --check-redirects)
        printf 'cfcharts check-redirects\n' >> "$TEST_EVENTS"
        exit "${REDIRECTS_STUB_EXIT:-0}"
        ;;
esac
exit 64
STUB
chmod +x "$STUB_DIR/allium-deploy-cfcharts.sh"

# stdbuf is GNU-only; production has it. The stub drops its option.
printf '#!/usr/bin/env bash\nshift\nexec "$@"\n' > "$STUB_BIN/stdbuf"
# mktemp stub: MKTEMP_MODE=fail fails; MKTEMP_MODE=unwritable returns the path
# of a regular file, so writing "<dir>/<name>" fails even for root; otherwise
# the real mktemp.
cat > "$STUB_BIN/mktemp" <<STUB
#!/usr/bin/env bash
case "\${MKTEMP_MODE:-}" in
    fail) echo "mktemp: No space left on device" >&2; exit 1 ;;
    unwritable) "$REAL_MKTEMP" ;;
    *) exec "$REAL_MKTEMP" "\$@" ;;
esac
STUB
# curl stub for the heartbeat: records the URL it reads from its config on
# standard input and the body.
cat > "$STUB_BIN/curl" <<'STUB'
#!/usr/bin/env bash
url=$(sed -n 's/^url = "\(.*\)"$/\1/p')
data=""
while (( $# )); do
    [[ "$1" != --data-raw ]] || data="$2"
    shift
done
printf 'ping %s %s\n' "$url" "$data" >> "$TEST_EVENTS"
STUB
chmod +x "$STUB_BIN/stdbuf" "$STUB_BIN/mktemp" "$STUB_BIN/curl"
export PATH="$STUB_BIN:$PATH" TEST_EVENTS="$EVENTS" TMPDIR="$STATE_TMP"

export ALLIUM_DEPLOY_TEST_MODE=1
# shellcheck source=../scripts/allium-deploy-update.sh
source "$ROOT_DIR/scripts/allium-deploy-update.sh"
set +e
SCRIPT_DIR="$STUB_DIR"
CF_ASSETS_SCRIPT="$STUB_DIR/allium-deploy-cfassets.sh"
CF_CHARTS_SCRIPT="$STUB_DIR/allium-deploy-cfcharts.sh"
CF_ASSETS_LAST_VERSION_FILE="$TMP_DIR/cfassets-last-version"
CF_ASSETS_PROMOTION_SUMMARY_FILE="$TMP_DIR/cfassets-promotion-summary.tsv"
CHARTS_LAYOUT_MARKER_FILE="$TMP_DIR/charts-layout-promoted"
CF_CHARTS_TIMING_FILE="$TMP_DIR/cfcharts-job-timing.tsv"
CF_CHARTS_LIVE_LIST="$TMP_DIR/cfcharts-live-charts"
OUTPUT_DIR="$TMP_DIR/out"
PUBLISH_LOG="$TMP_DIR/publish.log"
VERSION='0123abcd-1234-4234-8234-123456789abc'

# run_publish <cf_sleep> <do_sleep> <r2_sleep> [NAME=value ...]
# CHARTS=on models a CHARTS_LAYOUT=charts job whose charts Worker prepared.
# The build keeps the promoted layout unless CHARTS_TRANSITION=true.
run_publish() {
    local assignment
    export CF_SLEEP="$1" DO_SLEEP="$2" R2_SLEEP="$3"
    shift 3
    export CF_STUB_EXIT=0 DO_STUB_EXIT=0 R2_STUB_EXIT=0 PROMOTE_STUB_EXIT=0 MKTEMP_MODE=""
    export CHARTS_SLEEP=0 CHARTS_STUB_EXIT=0 CHARTS_PROMOTE_STUB_EXIT=0 ROUTE_STUB_EXIT=0 REDIRECTS_STUB_EXIT=0
    R2_ENABLED=true
    DO_ENABLED=true
    CF_ASSETS_ALLOW_PROMOTION=true
    CF_ASSETS_PREPARED=true
    CF_ASSETS_PREPARE_EXIT=0
    CHARTS_LAYOUT=beside
    CF_CHARTS_PREPARED=false
    CF_CHARTS_PREPARE_EXIT=0
    CHARTS_TRANSITION=false
    CF_CHARTS_ALLOW_STALE=false
    ALLIUM_NO_CHARTS=false
    CHARTS_STAGE_BUILD_SECONDS=""
    JOB_WARN_CLASS=""
    HEALTHCHECK_URL=""
    rm -f "$CF_ASSETS_PROMOTION_SUMMARY_FILE" "$CHARTS_LAYOUT_MARKER_FILE" "$CF_CHARTS_TIMING_FILE"
    printf '%s\n' "$VERSION" > "$CF_ASSETS_LAST_VERSION_FILE"
    for assignment in "$@"; do
        if [[ "$assignment" == CHARTS=on ]]; then
            CHARTS_LAYOUT=charts
            CF_CHARTS_PREPARED=true
            continue
        fi
        # shellcheck disable=SC2163 # export the NAME=value pair as given
        export "$assignment"
        printf -v "${assignment%%=*}" '%s' "${assignment#*=}"
    done
    PROMOTED_LAYOUT="$CHARTS_LAYOUT"
    if [[ "$CHARTS_TRANSITION" == true ]]; then
        PROMOTED_LAYOUT=other
    fi
    : > "$EVENTS"
    PUBLISHING="$CF_SLEEP $DO_SLEEP $R2_SLEEP ${*:-defaults}"
    set -e
    publish_in_restore_order > "$PUBLISH_LOG" 2>&1
    set +e
    PUBLISHING=""
    [[ -z "$(ls -A "$STATE_TMP")" ]] || fail "publisher state was left behind in case: $CF_SLEEP $DO_SLEEP $R2_SLEEP $*"
    [[ -z "$PUBLISH_STATE_DIR" ]] || fail "PUBLISH_STATE_DIR was not cleared"
}

# position <file> <fixed string>: line number of the first match, or 0.
position() {
    local line
    line=$(grep -nF -- "$2" "$1" | head -n 1 | cut -d: -f1)
    printf '%s\n' "${line:-0}"
}

assert_before() {
    local file="$1" first="$2" second="$3" label="$4" a b
    a=$(position "$file" "$first")
    b=$(position "$file" "$second")
    (( a > 0 && b > 0 && a < b )) || fail "$label: '$first' (line $a) is not before '$second' (line $b) in $(tr '\n' '|' < "$file")"
}

# assert_event_before <first event> <second event> <label>: whole event lines.
assert_event_before() {
    local a b
    a=$(grep -nxF -- "$1" "$EVENTS" | head -n 1 | cut -d: -f1)
    b=$(grep -nxF -- "$2" "$EVENTS" | head -n 1 | cut -d: -f1)
    (( ${a:-0} > 0 && ${b:-0} > 0 && a < b )) || fail "$3: '$1' (line ${a:-0}) is not before '$2' (line ${b:-0}) in $(tr '\n' '|' < "$EVENTS")"
}

assert_no_event() {
    ! grep -qxF -- "$1" "$EVENTS" || fail "$2: '$1' happened: $(tr '\n' '|' < "$EVENTS")"
}

assert_logged() {
    grep -qF -- "$1" "$PUBLISH_LOG" || fail "$2: '$1' was not logged: $(tr '\n' '|' < "$PUBLISH_LOG")"
}

assert_not_logged() {
    ! grep -qF -- "$1" "$PUBLISH_LOG" || fail "$2: '$1' was logged"
}

logged_seconds() {
    local label="$1" value
    value=$(grep -F "$label" "$PUBLISH_LOG" | grep -oE '\(([0-9]+)m([0-9]{2})s' | head -n 1 | tr -d '(s')
    [[ -n "$value" ]] || fail "no duration logged for '$label': $(cat "$PUBLISH_LOG")"
    echo $(( 10#${value%m*} * 60 + 10#${value#*m} ))
}

# assert_shorter <log label A> <log label B>: A's own duration is below B's.
assert_shorter() {
    local a b
    a=$(logged_seconds "$1")
    b=$(logged_seconds "$2")
    (( a < b )) || fail "'$1' logged ${a}s, not less than '$2' (${b}s): durations are not per publisher"
}

test_worker_promoted_before_storage_finishes() {
    run_publish 1 6 4
    # All three run at once: every publisher starts before any finishes.
    assert_before "$EVENTS" "r2 start" "cfassets end" "parallel start"
    assert_before "$EVENTS" "do start" "cfassets end" "parallel start"
    assert_before "$EVENTS" "cfassets end" "promote" "worker first"
    assert_before "$EVENTS" "promote" "r2 end" "promotion waits for R2"
    assert_before "$EVENTS" "promote" "do end" "promotion waits for DO"
    assert_before "$PUBLISH_LOG" "Workers Assets promotion completed" "DO Spaces upload completed" "log order"
    assert_before "$PUBLISH_LOG" "DO Spaces upload completed" "R2 upload completed" "DO before R2"
    assert_before "$PUBLISH_LOG" "Starting Cloudflare Workers Assets" "Starting DO Spaces upload" "start order"
    assert_before "$PUBLISH_LOG" "Starting DO Spaces upload" "Starting R2 upload" "start order"
    [[ "$CF_ASSETS_EXIT" == "0" && "$UPLOAD_SUCCESS" == "true" ]] || fail "successful run reported CF_ASSETS_EXIT=$CF_ASSETS_EXIT UPLOAD_SUCCESS=$UPLOAD_SUCCESS"
    # R2 finished before DO but is waited for after it: its duration is its own.
    assert_shorter "R2 upload completed" "DO Spaces upload completed"
    assert_shorter "Workers Assets shadow upload and verification completed" "R2 upload completed"
    pass "the verified Worker is promoted before DO and R2 finish; DO then R2 are waited for, each with its own duration"
}

test_slow_worker_unchanged() {
    run_publish 3 1 1
    assert_before "$EVENTS" "do end" "promote" "slow worker"
    assert_before "$EVENTS" "cfassets end" "promote" "slow worker"
    assert_shorter "DO Spaces upload completed" "Workers Assets shadow upload and verification completed"
    [[ "$(grep -c '^promote$' "$EVENTS")" == "1" ]] || fail "promotion did not run exactly once"
    pass "a Worker that finishes last is promoted once, as before"
}

test_failures_keep_exit_inputs() {
    run_publish 0 2 2 CF_STUB_EXIT=7
    [[ "$CF_ASSETS_EXIT" == "7" ]] || fail "failed Worker upload gave CF_ASSETS_EXIT=$CF_ASSETS_EXIT"
    ! grep -q '^promote$' "$EVENTS" || fail "a failed Worker upload was promoted"
    assert_logged "DO Spaces upload completed" "storage after a Worker failure"
    assert_logged "R2 upload completed" "storage after a Worker failure"
    [[ "$UPLOAD_SUCCESS" == "true" ]] || fail "storage success was lost after a Worker failure"

    run_publish 0 1 1 PROMOTE_STUB_EXIT=42
    [[ "$CF_ASSETS_EXIT" == "42" ]] || fail "failed promotion gave CF_ASSETS_EXIT=$CF_ASSETS_EXIT"
    assert_logged "DO Spaces upload completed" "storage after a failed promotion"
    assert_logged "R2 upload completed" "storage after a failed promotion"

    run_publish 0 1 1 DO_STUB_EXIT=3 R2_STUB_EXIT=4
    [[ "$UPLOAD_SUCCESS" == "false" ]] || fail "all storage failures still reported success"
    grep -q '^promote$' "$EVENTS" || fail "promotion became gated on storage uploads"
    assert_logged "DO Spaces upload failed (exit 3" "DO failure"
    assert_logged "R2 upload failed (exit 4" "R2 failure"

    run_publish 0 1 1 DO_STUB_EXIT=3
    [[ "$UPLOAD_SUCCESS" == "true" ]] || fail "R2 success alone was not enough"
    run_publish 0 1 1 R2_STUB_EXIT=4
    [[ "$UPLOAD_SUCCESS" == "true" ]] || fail "DO success alone was not enough"

    run_publish 0 1 1 R2_ENABLED=false
    [[ "$UPLOAD_SUCCESS" == "true" ]] || fail "DO-only success was not enough"
    ! grep -q '^r2 start$' "$EVENTS" || fail "disabled R2 was uploaded"
    assert_not_logged "R2 upload" "R2 disabled"
    run_publish 0 1 1 DO_ENABLED=false
    [[ "$UPLOAD_SUCCESS" == "true" ]] || fail "R2-only success was not enough"
    ! grep -q '^do start$' "$EVENTS" || fail "disabled DO was uploaded"
    assert_not_logged "DO Spaces upload" "DO disabled"

    run_publish 0 1 1 DO_STUB_EXIT=kill
    assert_logged "DO Spaces upload failed (exit 137" "DO killed by SIGKILL"
    [[ "$UPLOAD_SUCCESS" == "true" && "$CF_ASSETS_EXIT" == "0" ]] || fail "a killed DO upload changed other outcomes"

    run_publish 0 1 1 CF_ASSETS_PREPARED=false CF_ASSETS_PREPARE_EXIT=5
    [[ "$CF_ASSETS_EXIT" == "5" ]] || fail "preparation failure gave CF_ASSETS_EXIT=$CF_ASSETS_EXIT"
    ! grep -q '^cfassets start$' "$EVENTS" || fail "an unprepared Worker version was uploaded"
    run_publish 0 1 1 CF_ASSETS_PREPARED=false
    [[ "$CF_ASSETS_EXIT" == "0" && "$UPLOAD_SUCCESS" == "true" ]] || fail "Workers disabled reported CF_ASSETS_EXIT=$CF_ASSETS_EXIT"
    assert_not_logged "Workers Assets" "Workers disabled"

    run_publish 0 0 0 DO_ENABLED=false R2_ENABLED=false
    [[ "$CF_ASSETS_EXIT" == "0" && "$UPLOAD_SUCCESS" == "false" ]] || fail "Worker-only run reported CF_ASSETS_EXIT=$CF_ASSETS_EXIT UPLOAD_SUCCESS=$UPLOAD_SUCCESS"

    run_publish 0 1 1 CF_ASSETS_ALLOW_PROMOTION=false DO_STUB_EXIT=3 R2_STUB_EXIT=4
    ! grep -q '^promote$' "$EVENTS" || fail "disabled promotion still promoted"
    assert_not_logged "Promoting verified Workers Assets" "promotion disabled"
    [[ "$CF_ASSETS_EXIT" == "0" && "$UPLOAD_SUCCESS" == "false" ]] || fail "promotion disabled with storage failing reported CF_ASSETS_EXIT=$CF_ASSETS_EXIT UPLOAD_SUCCESS=$UPLOAD_SUCCESS"
    pass "Worker, promotion, storage, signal and preparation outcomes produce the same exit inputs as before"
}

test_timing_bookkeeping_is_best_effort() {
    local mode
    for mode in fail unwritable; do
        run_publish 0 1 1 MKTEMP_MODE="$mode"
        [[ "$CF_ASSETS_EXIT" == "0" && "$UPLOAD_SUCCESS" == "true" ]] \
            || fail "mktemp $mode changed outcomes: CF_ASSETS_EXIT=$CF_ASSETS_EXIT UPLOAD_SUCCESS=$UPLOAD_SUCCESS"
        grep -q '^promote$' "$EVENTS" || fail "mktemp $mode blocked promotion"
        assert_logged "DO Spaces upload completed" "mktemp $mode"
        assert_logged "R2 upload completed" "mktemp $mode"
    done
    pass "a failed or unwritable timing directory never changes a publisher's result"
}

test_charts_worker_promoted_and_routed_first() {
    # Each comparison keeps two seconds of margin, as whole-second durations
    # and event orders need.
    run_publish 1 5 7 CHARTS=on CHARTS_SLEEP=3
    # The charts upload runs alongside the others.
    assert_event_before "cfcharts start" "cfassets end" "charts parallel start"
    assert_event_before "do start" "cfcharts end" "charts parallel start"
    assert_event_before "r2 start" "cfcharts end" "charts parallel start"
    # Charts promote < route check < main promote < DO end < R2 end, and the
    # old-URL check follows the main promotion.
    assert_event_before "cfcharts end" "cfcharts promote" "charts verified first"
    assert_event_before "cfcharts promote" "cfcharts check-route" "charts promoted before the route check"
    assert_event_before "cfcharts check-route" "promote" "route checked before the main promotion"
    assert_event_before "promote" "cfcharts check-redirects" "redirects checked after the main promotion"
    assert_event_before "promote" "do end" "main promotion before DO"
    assert_event_before "do end" "r2 end" "DO before R2"
    assert_before "$PUBLISH_LOG" "Charts Worker promotion completed" "The /charts/ route serves the promoted charts" "log order"
    assert_before "$PUBLISH_LOG" "The /charts/ route serves the promoted charts" "Workers Assets promotion completed" "log order"
    assert_before "$PUBLISH_LOG" "Workers Assets promotion completed" "DO Spaces upload completed" "log order"
    [[ "$CF_CHARTS_EXIT" == "0" && "$CF_ASSETS_EXIT" == "0" && "$UPLOAD_SUCCESS" == "true" ]] \
        || fail "charts run reported CF_CHARTS_EXIT=$CF_CHARTS_EXIT CF_ASSETS_EXIT=$CF_ASSETS_EXIT UPLOAD_SUCCESS=$UPLOAD_SUCCESS"
    assert_shorter "Workers Assets shadow upload and verification completed" "Charts Worker upload and verification completed"
    [[ ! -e "$CF_ASSETS_PROMOTION_SUMMARY_FILE" ]] || fail "a successful job recorded a withheld promotion"
    [[ "$(cat "$CF_ASSETS_LAST_VERSION_FILE")" == "$VERSION" ]] || fail "a successful job removed the verified version"

    # A charts Worker that finishes last still goes first.
    run_publish 1 1 1 CHARTS=on CHARTS_SLEEP=3
    assert_event_before "cfassets end" "cfcharts end" "slow charts Worker"
    assert_event_before "cfcharts check-route" "promote" "slow charts Worker"
    [[ "$(grep -cx 'promote' "$EVENTS")" == "1" && "$(grep -cx 'cfcharts promote' "$EVENTS")" == "1" ]] \
        || fail "each Worker was not promoted exactly once: $(tr '\n' '|' < "$EVENTS")"

    # A failed old-URL check after the main promotion only warns.
    run_publish 0 1 1 CHARTS=on REDIRECTS_STUB_EXIT=1
    [[ "$CF_ASSETS_EXIT" == "0" && "$CF_CHARTS_EXIT" == "0" ]] || fail "a failed redirect check changed the exits"
    assert_logged "Old chart URLs on" "failed redirect check"

    # With the beside layout nothing about charts runs.
    run_publish 0 1 1
    for event in "cfcharts start" "cfcharts promote" "cfcharts check-route" "cfcharts check-redirects"; do
        assert_no_event "$event" "beside layout"
    done
    assert_not_logged "harts Worker" "beside layout"
    pass "with CHARTS_LAYOUT=charts the charts Worker is promoted and its route checked before the main Worker, then DO and R2"
}

test_charts_failure_withholds_main_promotion() {
    local case name expected
    for case in \
        "CHARTS_STUB_EXIT=7|7|cfcharts promote" \
        "CHARTS_PROMOTE_STUB_EXIT=9|9|cfcharts check-route" \
        "ROUTE_STUB_EXIT=6|6|" \
        "CF_CHARTS_PREPARED=false CF_CHARTS_PREPARE_EXIT=5|5|cfcharts start"; do
        IFS='|' read -r name expected absent <<< "$case"
        # shellcheck disable=SC2086 # one NAME=value per word
        run_publish 0 1 1 CHARTS=on $name
        assert_no_event "promote" "$name"
        assert_no_event "cfcharts check-redirects" "$name"
        [[ -z "$absent" ]] || assert_no_event "$absent" "$name"
        [[ "$CF_CHARTS_EXIT" == "$expected" && "$CF_ASSETS_EXIT" == "$expected" && "$UPLOAD_SUCCESS" == "true" ]] \
            || fail "$name gave CF_CHARTS_EXIT=$CF_CHARTS_EXIT CF_ASSETS_EXIT=$CF_ASSETS_EXIT UPLOAD_SUCCESS=$UPLOAD_SUCCESS"
        assert_logged "Workers Assets promotion withheld: the charts Worker failed (exit $expected)" "$name"
        assert_logged "R2 upload completed" "$name"
        [[ "$(cat "$CF_ASSETS_PROMOTION_SUMMARY_FILE")" == $'timestamp_utc\tversion_id\texit_status\n'*$'\t'"$VERSION"$'\t'"$expected" ]] \
            || fail "$name: the withheld promotion was not recorded: $(cat "$CF_ASSETS_PROMOTION_SUMMARY_FILE" 2>/dev/null)"
        if [[ "$name" == ROUTE_* ]]; then
            assert_logged "the <host>/charts/* route is missing or reaches another Worker" "$name"
        fi
        [[ ! -e "$CF_ASSETS_LAST_VERSION_FILE" ]] || fail "$name: the withheld version stayed promotable"
    done

    # Without promotion neither Worker is promoted, nothing is withheld, and a
    # charts failure is still the Workers result.
    run_publish 0 1 1 CHARTS=on CF_ASSETS_ALLOW_PROMOTION=false CHARTS_STUB_EXIT=7
    assert_no_event "promote" "promotion disabled"
    assert_no_event "cfcharts promote" "promotion disabled"
    assert_no_event "cfcharts check-route" "promotion disabled"
    [[ "$CF_ASSETS_EXIT" == "7" && ! -e "$CF_ASSETS_PROMOTION_SUMMARY_FILE" ]] \
        || fail "promotion disabled gave CF_ASSETS_EXIT=$CF_ASSETS_EXIT or recorded a promotion"
    assert_logged "The charts Worker failed (exit 7)" "promotion disabled"
    [[ ! -e "$CF_ASSETS_LAST_VERSION_FILE" ]] || fail "promotion disabled: a version whose charts failed stayed promotable"
    run_publish 0 1 1 CHARTS=on CF_ASSETS_ALLOW_PROMOTION=false
    assert_no_event "promote" "promotion disabled, healthy"
    assert_no_event "cfcharts promote" "promotion disabled, healthy"
    assert_no_event "cfcharts check-route" "promotion disabled, healthy"
    [[ "$CF_ASSETS_EXIT" == "0" && "$(cat "$CF_ASSETS_LAST_VERSION_FILE")" == "$VERSION" ]] || fail "a healthy shadow run failed"

    # A failed main upload keeps its own exit status.
    run_publish 0 1 1 CHARTS=on CF_STUB_EXIT=3 CHARTS_STUB_EXIT=7
    [[ "$CF_ASSETS_EXIT" == "3" && ! -e "$CF_ASSETS_PROMOTION_SUMMARY_FILE" ]] || fail "a failed main upload gave CF_ASSETS_EXIT=$CF_ASSETS_EXIT"
    pass "any charts Worker failure, including the route check, withholds the main promotion, records it and leaves no promotable version; storage still runs"
}

# A charts failure in a build that keeps the promoted layout: an inconclusive
# route check promotes, a definitive one withholds, CF_CHARTS_ALLOW_STALE=true
# promotes anyway; the job is then marked to exit non-zero. A transition
# build withholds in every case.
test_charts_failure_by_build_kind() {
    run_publish 0 1 1 CHARTS=on ROUTE_STUB_EXIT=75
    assert_event_before "cfcharts check-route" "promote" "inconclusive route, kept layout"
    [[ "$CF_ASSETS_EXIT" == 0 && "$JOB_WARN_CLASS" == route_inconclusive && -z "$WORKERS_FAILURE_CLASS" ]] \
        || fail "an inconclusive route check in a kept layout gave CF_ASSETS_EXIT=$CF_ASSETS_EXIT JOB_WARN_CLASS=$JOB_WARN_CLASS"
    assert_logged "The /charts/ route check was inconclusive: promoting the main Worker" "inconclusive route, kept layout"
    assert_logged "Could not check that" "inconclusive route, kept layout"
    [[ "$(cat "$CF_ASSETS_LAST_VERSION_FILE")" == "$VERSION" && ! -e "$CF_ASSETS_PROMOTION_SUMMARY_FILE" ]] \
        || fail "an inconclusive route check in a kept layout recorded a withheld promotion"

    run_publish 0 1 1 CHARTS=on ROUTE_STUB_EXIT=6
    assert_no_event "promote" "definitive route, kept layout"
    [[ "$CF_ASSETS_EXIT" == 6 && "$WORKERS_FAILURE_CLASS" == route_definitive && -z "$JOB_WARN_CLASS" ]] \
        || fail "a definitive route failure gave CF_ASSETS_EXIT=$CF_ASSETS_EXIT class=$WORKERS_FAILURE_CLASS warn=$JOB_WARN_CLASS"

    run_publish 0 1 1 CHARTS=on CHARTS_TRANSITION=true ROUTE_STUB_EXIT=75
    assert_no_event "promote" "inconclusive route, transition"
    [[ "$CF_ASSETS_EXIT" == 75 && "$WORKERS_FAILURE_CLASS" == route_inconclusive && -z "$JOB_WARN_CLASS" ]] \
        || fail "an inconclusive route check in a transition build gave CF_ASSETS_EXIT=$CF_ASSETS_EXIT warn=$JOB_WARN_CLASS"
    [[ ! -e "$CF_ASSETS_LAST_VERSION_FILE" ]] || fail "a transition build left the withheld version promotable"

    for failure in CHARTS_STUB_EXIT=7 CHARTS_PROMOTE_STUB_EXIT=9 ROUTE_STUB_EXIT=6 "CF_CHARTS_PREPARED=false CF_CHARTS_PREPARE_EXIT=5"; do
        # shellcheck disable=SC2086 # one NAME=value per word
        run_publish 0 1 1 CHARTS=on CF_CHARTS_ALLOW_STALE=true $failure
        assert_event_before "do start" "promote" "$failure with CF_CHARTS_ALLOW_STALE"
        [[ "$CF_ASSETS_EXIT" == 0 && "$JOB_WARN_CLASS" == charts_stale ]] \
            || fail "$failure with CF_CHARTS_ALLOW_STALE=true gave CF_ASSETS_EXIT=$CF_ASSETS_EXIT warn=$JOB_WARN_CLASS"
        assert_logged "CF_CHARTS_ALLOW_STALE=true: promoting the main Worker although the charts Worker failed" "$failure"
        [[ "$(cat "$CHARTS_LAYOUT_MARKER_FILE")" == charts ]] || fail "$failure with CF_CHARTS_ALLOW_STALE: the layout was not recorded"

        # shellcheck disable=SC2086 # one NAME=value per word
        run_publish 0 1 1 CHARTS=on CHARTS_TRANSITION=true CF_CHARTS_ALLOW_STALE=true $failure
        assert_no_event "promote" "$failure, transition, CF_CHARTS_ALLOW_STALE"
        [[ "$CF_ASSETS_EXIT" != 0 && -z "$JOB_WARN_CLASS" && ! -e "$CHARTS_LAYOUT_MARKER_FILE" ]] \
            || fail "$failure in a transition build with CF_CHARTS_ALLOW_STALE=true was promoted or marked"
        assert_logged "CF_CHARTS_ALLOW_STALE=true does not apply to a chart layout transition build" "$failure"
    done

    run_publish 0 1 1 CHARTS=on CF_CHARTS_ALLOW_STALE=true CF_ASSETS_ALLOW_PROMOTION=false CHARTS_STUB_EXIT=7
    assert_no_event "promote" "CF_CHARTS_ALLOW_STALE without promotion"
    [[ "$CF_ASSETS_EXIT" == 7 && -z "$JOB_WARN_CLASS" ]] || fail "CF_CHARTS_ALLOW_STALE without promotion gave CF_ASSETS_EXIT=$CF_ASSETS_EXIT"
    pass "in a build keeping the promoted layout, an inconclusive route check or CF_CHARTS_ALLOW_STALE=true promotes the main Worker and marks the job; a transition build always withholds"
}

test_layout_marker_and_classes() {
    local case name expected
    run_publish 0 1 1
    [[ "$(cat "$CHARTS_LAYOUT_MARKER_FILE")" == beside ]] || fail "a beside promotion did not record its layout"
    run_publish 0 1 1 CHARTS=on CHARTS_TRANSITION=true
    [[ "$(cat "$CHARTS_LAYOUT_MARKER_FILE")" == charts ]] || fail "a charts promotion did not record its layout"
    assert_logged "The promoted main Worker version now has the chart layout charts (was other)" "transition promotion"
    for case in \
        "PROMOTE_STUB_EXIT=42|main_promote" \
        "CF_STUB_EXIT=3|main_upload" \
        "CF_STUB_EXIT=4|cap" \
        "CF_ASSETS_PREPARED=false CF_ASSETS_PREPARE_EXIT=5|main_prepare" \
        "CF_ASSETS_PREPARED=false CF_ASSETS_PREPARE_EXIT=4|cap" \
        "CHARTS_STUB_EXIT=4|cap" \
        "CF_CHARTS_PREPARED=false CF_CHARTS_PREPARE_EXIT=4|cap" \
        "CHARTS_STUB_EXIT=1|charts_upload" \
        "CHARTS_PROMOTE_STUB_EXIT=9|charts_promote" \
        "CF_CHARTS_PREPARED=false CF_CHARTS_PREPARE_EXIT=5|charts_prepare" \
        "ALLIUM_NO_CHARTS=true|"; do
        IFS='|' read -r name expected <<< "$case"
        # shellcheck disable=SC2086 # one NAME=value per word
        run_publish 0 1 1 CHARTS=on $name
        [[ "$WORKERS_FAILURE_CLASS" == "$expected" ]] || fail "$name gave the class '$WORKERS_FAILURE_CLASS', not '$expected'"
        if [[ -n "$expected" ]]; then
            [[ ! -e "$CHARTS_LAYOUT_MARKER_FILE" ]] || fail "$name recorded a promoted layout"
        fi
        if [[ "$name" == ALLIUM_NO_CHARTS=true ]]; then
            # A version without charts says nothing about the layout.
            [[ ! -e "$CHARTS_LAYOUT_MARKER_FILE" ]] || fail "a promotion with ALLIUM_NO_CHARTS=true recorded a layout"
        fi
    done
    pass "a main promotion records its layout (not without charts), and each Workers failure has its class"
}

test_live_charts_list() {
    mkdir -p "$OUTPUT_DIR/charts/relay/FP" "$OUTPUT_DIR/charts/contact/c1"
    printf 'png\n' > "$OUTPUT_DIR/charts/relay/FP/bandwidth-1m.png"
    printf 'png\n' > "$OUTPUT_DIR/charts/contact/c1/bandwidth-6m.png"
    printf 'html\n' > "$OUTPUT_DIR/charts/404.html"
    rm -f "$CF_CHARTS_LIVE_LIST"
    run_publish 0 1 1 CHARTS=on
    [[ "$(cat "$CF_CHARTS_LIVE_LIST" 2>/dev/null)" == $'charts/contact/c1/bandwidth-6m.png\ncharts/relay/FP/bandwidth-1m.png' ]] \
        || fail "a charts promotion did not record its pages' charts: $(cat "$CF_CHARTS_LIVE_LIST" 2>/dev/null)"
    # A withheld or failed main promotion keeps the previous list.
    printf 'png\n' > "$OUTPUT_DIR/charts/relay/FP/uptime-1y.png"
    run_publish 0 1 1 CHARTS=on CHARTS_STUB_EXIT=1
    [[ "$(wc -l < "$CF_CHARTS_LIVE_LIST" | tr -d ' ')" == 2 ]] || fail "a withheld main promotion replaced the live list"
    run_publish 0 1 1 CHARTS=on PROMOTE_STUB_EXIT=42
    [[ "$(wc -l < "$CF_CHARTS_LIVE_LIST" | tr -d ' ')" == 2 ]] || fail "a failed main promotion replaced the live list"
    # A version without charts leaves it; a beside version links none.
    run_publish 0 1 1 CHARTS=on ALLIUM_NO_CHARTS=true
    [[ "$(wc -l < "$CF_CHARTS_LIVE_LIST" | tr -d ' ')" == 2 ]] || fail "a promotion without charts changed the live list"
    run_publish 0 1 1
    [[ ! -e "$CF_CHARTS_LIVE_LIST" ]] || fail "a beside promotion kept the live list"
    rm -rf "$OUTPUT_DIR/charts"
    pass "each main promotion in the charts layout records the charts its pages link; a withheld, failed or chartless promotion keeps the list and a beside one removes it"
}

test_charts_timing_and_warning_pings() {
    local row timing_row
    run_publish 0 1 1 CHARTS=on CHARTS_SLEEP=2 CHARTS_STAGE_BUILD_SECONDS=3
    row=$(tail -n 1 "$CF_CHARTS_TIMING_FILE")
    [[ "$(head -n 1 "$CF_CHARTS_TIMING_FILE")" == $'timestamp_utc\tstage_build_seconds\tcharts_promoted_utc\tmain_wait_for_charts_seconds' ]] \
        || fail "unexpected charts timing header"
    timing_row=$'^[0-9T:-]+Z\t3\t[0-9T:-]+Z\t([0-9]+)$'
    [[ "$row" =~ $timing_row ]] && (( BASH_REMATCH[1] >= 1 )) \
        || fail "unexpected charts timing row (the main Worker waited about 2s): $row"
    run_publish 0 1 1 CHARTS=on CHARTS_PROMOTE_STUB_EXIT=9
    [[ "$(tail -n 1 "$CF_CHARTS_TIMING_FILE" | cut -f2-3)" == $'-\t-' ]] || fail "a failed charts promotion has a promotion time"
    run_publish 0 1 1
    [[ ! -e "$CF_CHARTS_TIMING_FILE" ]] || fail "a beside build wrote a charts timing row"

    run_publish 0 1 1 CHARTS=on DO_STUB_EXIT=3 REDIRECTS_STUB_EXIT=1
    ! grep -q '^ping ' "$EVENTS" || fail "a warning was pinged without HEALTHCHECK_URL"
    run_publish 0 1 1 CHARTS=on DO_STUB_EXIT=3 REDIRECTS_STUB_EXIT=1 HEALTHCHECK_URL=https://hc.example/check
    grep -qxF 'ping https://hc.example/check/log warn=redirects' "$EVENTS" || fail "the redirect warning was not pinged: $(cat "$EVENTS")"
    grep -qxF 'ping https://hc.example/check/log warn=do_upload exit=3' "$EVENTS" || fail "the DO warning was not pinged: $(cat "$EVENTS")"
    ! grep -qF 'hc.example' "$PUBLISH_LOG" || fail "the heartbeat URL was logged"
    pass "a charts build records its timing row, and warnings ping the heartbeat's log"
}

test_call_placement() {
    local script
    script="$(<"$ROOT_DIR/scripts/allium-deploy-update.sh")"
    [[ "$script" == *$'\npublish_in_restore_order\n\n# Check if at least one upload succeeded\n'* ]] \
        || fail "publish_in_restore_order is not called right before the upload checks"
    [[ "$script" != *'R2_PID'* && "$script" != *'CF_ASSETS_PID'* ]] || fail "an inline upload block is still present"
    pass "the job publishes through publish_in_restore_order before deciding its exit"
}

test_worker_promoted_before_storage_finishes
test_slow_worker_unchanged
test_failures_keep_exit_inputs
test_timing_bookkeeping_is_best_effort
test_charts_worker_promoted_and_routed_first
test_charts_failure_withholds_main_promotion
test_charts_failure_by_build_kind
test_layout_marker_and_classes
test_live_charts_list
test_charts_timing_and_warning_pings
test_call_placement
