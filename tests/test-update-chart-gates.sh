#!/usr/bin/env bash
# allium-deploy-update.sh around the chart layout: the defaults of its
# settings, the promoted-layout marker and transition builds, the local checks
# of the output tree that hold every publisher, the heartbeat (off unless
# HEALTHCHECK_URL is set, never logging the URL, bounded in time) with its
# failure classes, the DO subtree order warning, and where the job runs these. Functions run from the sourced script with fixture trees
# and a curl stub.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

STUB_BIN="$TMP_DIR/bin"
PINGS="$TMP_DIR/pings"
mkdir -p "$STUB_BIN"
# curl stub: records the URL from its config on standard input, the body and
# whether the URL was on its command line, and its arguments.
cat > "$STUB_BIN/curl" <<'STUB'
#!/usr/bin/env bash
url=$(sed -n 's/^url = "\(.*\)"$/\1/p')
data=""
argv="$*"
printf '%s\n' "$argv" >> "$PINGS.argv"
while (( $# )); do
    [[ "$1" != --data-raw ]] || data="$2"
    shift
done
[[ "$argv" != *hc.example* ]] || data="$data URL-ON-COMMAND-LINE"
printf '%s %s\n' "$url" "$data" >> "$PINGS"
exit "${CURL_STUB_EXIT:-0}"
STUB
chmod +x "$STUB_BIN/curl"
export PATH="$STUB_BIN:$PATH" PINGS

export ALLIUM_DEPLOY_TEST_MODE=1
# shellcheck source=../scripts/allium-deploy-update.sh
source "$ROOT_DIR/scripts/allium-deploy-update.sh"
set +e
UPDATE_SCRIPT=$(<"$ROOT_DIR/scripts/allium-deploy-update.sh")
CHARTS_LAYOUT_MARKER_FILE="$TMP_DIR/logs/charts-layout-promoted"
LOG="$TMP_DIR/log"

# The chart layout knobs that are not safety gates are off unless set, and
# the job rejects invalid values of the new switches before it starts.
test_defaults() {
    local defaults
    # shellcheck disable=SC2016 # expanded by the inner shell
    defaults=$(env -u CHARTS_LAYOUT -u CF_CHARTS_ALLOW_STALE -u ALLIUM_NO_CHARTS -u HEALTHCHECK_URL ALLIUM_DEPLOY_TEST_MODE=1 \
        bash -c 'source "$1"; printf "%s|%s|%s|%s\n" "$CHARTS_LAYOUT" "$CF_CHARTS_ALLOW_STALE" "$ALLIUM_NO_CHARTS" "$HEALTHCHECK_URL"' \
        _ "$ROOT_DIR/scripts/allium-deploy-update.sh")
    [[ "$defaults" == 'beside|false|false|' ]] || fail "unexpected defaults (CHARTS_LAYOUT|CF_CHARTS_ALLOW_STALE|ALLIUM_NO_CHARTS|HEALTHCHECK_URL): $defaults"
    [[ "$UPDATE_SCRIPT" == *$'\nassert_boolean_setting CF_CHARTS_ALLOW_STALE "$CF_CHARTS_ALLOW_STALE"\nassert_boolean_setting ALLIUM_NO_CHARTS "$ALLIUM_NO_CHARTS"\nassert_charts_layout\n'* ]] \
        || fail "the job does not reject invalid CF_CHARTS_ALLOW_STALE, ALLIUM_NO_CHARTS and CHARTS_LAYOUT values before it starts"
    pass "CHARTS_LAYOUT is beside, CF_CHARTS_ALLOW_STALE and ALLIUM_NO_CHARTS are false and the heartbeat is off unless set, and invalid values stop the job"
}

# transition_for <layout> [marker content | missing]: prints CHARTS_TRANSITION
# and PROMOTED_LAYOUT, then the log.
transition_for() {
    (
        CHARTS_LAYOUT="$1"
        rm -f "$CHARTS_LAYOUT_MARKER_FILE"
        if [[ "${2:-missing}" != missing ]]; then
            mkdir -p "$(dirname "$CHARTS_LAYOUT_MARKER_FILE")"
            printf '%s\n' "$2" > "$CHARTS_LAYOUT_MARKER_FILE"
        fi
        read_promoted_layout > "$LOG"
        printf '%s %s\n' "$CHARTS_TRANSITION" "$PROMOTED_LAYOUT"
        cat "$LOG"
    )
}

test_promoted_layout_marker() {
    local result
    [[ "$(transition_for beside)" == 'false beside' ]] || fail "beside without a marker is a transition: $(transition_for beside)"
    result=$(transition_for charts)
    [[ "$result" == 'true beside'*'Chart layout transition build: CHARTS_LAYOUT=charts, promoted main Worker layout beside'* ]] \
        || fail "charts without a marker is not a transition: $result"
    [[ "$(transition_for charts charts)" == 'false charts' ]] || fail "charts after a charts promotion is a transition"
    [[ "$(transition_for beside charts)" == 'true charts'* ]] || fail "beside after a charts promotion is not a transition"
    for layout in beside charts; do
        result=$(transition_for "$layout" garbage)
        [[ "$result" == 'true unknown'*'holds no layout; treating this build as a layout transition'* ]] \
            || fail "a malformed marker did not make a $layout build a transition: $result"
    done
    # record_promoted_layout writes the job's layout, but not for a version
    # without charts.
    (
        rm -f "$CHARTS_LAYOUT_MARKER_FILE"
        CHARTS_LAYOUT=charts PROMOTED_LAYOUT=beside ALLIUM_NO_CHARTS=true
        record_promoted_layout > /dev/null
        [[ ! -e "$CHARTS_LAYOUT_MARKER_FILE" ]] || fail "a version without charts recorded a layout"
        ALLIUM_NO_CHARTS=false
        record_promoted_layout > /dev/null
        [[ "$(cat "$CHARTS_LAYOUT_MARKER_FILE")" == charts ]] || fail "the promoted layout was not recorded"
        [[ -z "$(find "$(dirname "$CHARTS_LAYOUT_MARKER_FILE")" -name '*.tmp.*')" ]] || fail "a temporary marker was left behind"
    ) || exit 1
    pass "the promoted-layout marker (missing = beside) defines transition builds, a malformed one makes every build a transition, and a version without charts leaves it"
}

# A fixture output tree: a relay page, a contact page, a vanity-domain page,
# with the links of the given layout.
make_tree() {
    local dir="$1" layout="$2" charts=""
    rm -rf "$dir"
    mkdir -p "$dir/relay/FP" "$dir/contact/c1" "$dir/vanity.example" "$dir/static/images"
    [[ "$layout" == beside ]] || charts="charts/"
    {
        printf '<img src="../../static/images/flags/de.png">\n'
        printf '<a href="../../%srelay/FP/bandwidth-1m.png"><img src="../../%srelay/FP/bandwidth-1m.png"></a>\n' "$charts" "$charts"
    } > "$dir/relay/FP/index.html"
    printf '<img src="../../%scontact/c1/bandwidth-6m.png">\n' "$charts" > "$dir/contact/c1/index.html"
    printf '<img src="../%scontact/c1/bandwidth-6m.png">\n' "$charts" > "$dir/vanity.example/index.html"
    if [[ "$layout" == beside ]]; then
        printf 'png\n' > "$dir/relay/FP/bandwidth-1m.png"
        printf 'png\n' > "$dir/contact/c1/bandwidth-6m.png"
    else
        mkdir -p "$dir/charts/relay/FP" "$dir/charts/contact/c1"
        printf 'png\n' > "$dir/charts/relay/FP/bandwidth-1m.png"
        printf 'png\n' > "$dir/charts/contact/c1/bandwidth-6m.png"
    fi
}

# gates <layout> <transition> [NAME=value...]: run run_local_gates on
# $OUTPUT_DIR; prints its status, then its log.
gates() (
    CHARTS_LAYOUT="$1"
    CHARTS_TRANSITION="$2"
    CF_ASSETS_PREPARE_EXIT=0
    CF_CHARTS_PREPARE_EXIT=0
    shift 2
    for assignment in "$@"; do
        printf -v "${assignment%%=*}" '%s' "${assignment#*=}"
    done
    status=0
    run_local_gates > "$LOG" 2>&1 || status=$?
    printf '%s\n' "$status"
    cat "$LOG"
)

test_local_gates() {
    local result layout transition
    OUTPUT_DIR="$TMP_DIR/output"
    for layout in beside charts; do
        make_tree "$OUTPUT_DIR" "$layout"
        for transition in true false; do
            result=$(gates "$layout" "$transition")
            [[ "$result" == 0 ]] || fail "a clean $layout tree (transition=$transition) failed: $result"
        done
    done

    # Charts layout: a chart beside its page fails every build.
    make_tree "$OUTPUT_DIR" charts
    printf 'png\n' > "$OUTPUT_DIR/relay/FP/uptime-6m.png"
    for transition in true false; do
        result=$(gates charts "$transition")
        [[ "$result" == 1*'chart beside its page: relay/FP/uptime-6m.png'*'Local checks failed: mirrors held, no publisher started'* ]] \
            || fail "a chart beside its page passed (transition=$transition): $result"
    done
    # PNGs at other depths are not charts.
    rm "$OUTPUT_DIR/relay/FP/uptime-6m.png"
    printf 'png\n' > "$OUTPUT_DIR/relay/top.png"
    [[ "$(gates charts true)" == 0 ]] || fail "a PNG that is not a chart failed the charts layout"

    # Links that do not fit the layout: fatal in a transition build, a
    # warning otherwise. static/ links always fit.
    make_tree "$OUTPUT_DIR" charts
    printf '<img src="bandwidth-1m.png"><img src="../../static/images/x.png">\n' >> "$OUTPUT_DIR/relay/FP/index.html"
    result=$(gates charts true)
    [[ "$result" == 1*'❌ 1 PNG links on the pages do not fit CHARTS_LAYOUT=charts, e.g. relay/FP/index.html:src="bandwidth-1m.png"'*'mirrors held'* ]] \
        || fail "an old chart link passed a transition build: $result"
    result=$(gates charts false)
    [[ "$result" == 0*'⚠️ 1 PNG links on the pages do not fit CHARTS_LAYOUT=charts'* && "$result" != *'mirrors held'* ]] \
        || fail "an old chart link failed a build that keeps the layout: $result"
    make_tree "$OUTPUT_DIR" beside
    printf '<img src="../../charts/relay/FP/uptime-6m.png">\n' >> "$OUTPUT_DIR/relay/FP/index.html"
    printf '<a href="../charts/contact/c1/bandwidth-1y.png">x</a>\n' >> "$OUTPUT_DIR/vanity.example/index.html"
    result=$(gates beside true)
    [[ "$result" == 1*'❌ 2 PNG links on the pages do not fit CHARTS_LAYOUT=beside'* ]] || fail "charts/ links passed a beside transition build: $result"
    [[ "$(gates beside false)" == 0*'⚠️ 2 PNG links'* ]] || fail "charts/ links failed a beside build that keeps the layout"
    # Links with a query string or fragment are checked by their path.
    make_tree "$OUTPUT_DIR" beside
    printf '<img src="../../charts/relay/FP/uptime-6m.png?v=1"><a href="../../charts/relay/FP/uptime-1y.png#zoom">x</a>\n' >> "$OUTPUT_DIR/relay/FP/index.html"
    printf '<img src="bandwidth-1m.png?v=2">\n' >> "$OUTPUT_DIR/relay/FP/index.html"
    result=$(gates beside true)
    [[ "$result" == 1*'❌ 2 PNG links on the pages do not fit CHARTS_LAYOUT=beside'* ]] \
        || fail "charts/ links with a query string or fragment passed a beside transition build: $result"
    # A page that cannot be read is a problem too.
    make_tree "$OUTPUT_DIR" charts
    if [[ "$(id -u)" != 0 ]]; then
        chmod 000 "$OUTPUT_DIR/contact/c1/index.html"
        [[ "$(gates charts true)" == 1*'Could not read the PNG links of the pages'* ]] || fail "an unreadable page passed a transition build"
        [[ "$(gates charts false)" == 0*'⚠️ Could not read the PNG links of the pages'* ]] || fail "an unreadable page failed a build that keeps the layout"
        chmod 644 "$OUTPUT_DIR/contact/c1/index.html"
    fi

    # In a transition build a failed Workers preparation holds the mirrors too.
    # A preparation over the file limit (exit status 4) is one of them.
    for prepared in CF_ASSETS_PREPARE_EXIT=1 CF_CHARTS_PREPARE_EXIT=2 CF_ASSETS_PREPARE_EXIT=4 CF_CHARTS_PREPARE_EXIT=4; do
        [[ "$(gates charts true "$prepared")" == 1*'Workers preparation failed in a chart layout transition build'* ]] \
            || fail "$prepared did not hold the mirrors in a transition build"
        [[ "$(gates charts false "$prepared")" == 0 ]] || fail "$prepared held the mirrors in a build that keeps the layout"
    done

    [[ "$UPDATE_SCRIPT" == *$'\nif ! run_local_gates; then\n    JOB_FAILURE_CLASS=local\n    increment_failures\n    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true\n    exit 1\nfi\n\npublish_in_restore_order\n'* ]] \
        || fail "the local checks do not run right before the publishers, or do not stop the job"
    pass "before any publisher: a chart beside its page always fails, links that do not fit the layout and a failed preparation fail a transition build and otherwise warn"
}

test_heartbeat() {
    local log
    : > "$PINGS"
    (
        HEALTHCHECK_URL=""
        heartbeat /start
        heartbeat "" ok
    )
    [[ ! -s "$PINGS" ]] || fail "a heartbeat was sent without HEALTHCHECK_URL: $(cat "$PINGS")"

    log=$(
        HEALTHCHECK_URL=https://hc.example/check-id
        check_heartbeat_url
        heartbeat /start
        heartbeat /log "warn=x"
        CURL_STUB_EXIT=7 heartbeat ""
    )
    [[ "$(cat "$PINGS")" == $'https://hc.example/check-id/start \nhttps://hc.example/check-id/log warn=x\nhttps://hc.example/check-id ' ]] \
        || fail "unexpected pings: $(cat "$PINGS")"
    # An endpoint that does not answer delays the job by about ten seconds
    # per ping at most.
    [[ "$(sed -n 1p "$PINGS.argv")" == *'--connect-timeout 5 --max-time 5 --retry 1 --retry-max-time 10 '* ]] \
        || fail "the heartbeat's time is not bounded: $(sed -n 1p "$PINGS.argv")"
    [[ "$log" == *'Heartbeat ping (success) failed'* && "$log" != *hc.example* ]] || fail "a failed ping was not logged, or the URL was: $log"

    for url in http://hc.example/x 'https://hc.example/a b' 'https://hc.example/"x'; do
        : > "$PINGS"
        log=$(HEALTHCHECK_URL="$url"; check_heartbeat_url; heartbeat /start)
        [[ ! -s "$PINGS" && "$log" == *'HEALTHCHECK_URL is not an https:// URL; the heartbeat is off'* && "$log" != *hc.example* ]] \
            || fail "the heartbeat URL '$url' was used or logged: $log $(cat "$PINGS")"
    done

    # record_update_exit pings success or the failure class. A Workers failure
    # fails the heartbeat also when the job exits 0 (CF_ASSETS_REQUIRED=false),
    # for example a withheld main Worker promotion.
    : > "$PINGS"
    for case in '0|||https://hc.example/check-id ok' '1|cap||https://hc.example/check-id/fail class=cap exit=1' \
        '3|||https://hc.example/check-id/fail class=other exit=3' \
        '0||route_definitive|https://hc.example/check-id/fail class=route_definitive exit=0' \
        '0||cap|https://hc.example/check-id/fail class=cap exit=0' \
        '1|route_inconclusive|route_inconclusive|https://hc.example/check-id/fail class=route_inconclusive exit=1' \
        '1|storage|main_upload|https://hc.example/check-id/fail class=storage exit=1'; do
        IFS='|' read -r status class workers_class expected <<< "$case"
        : > "$PINGS"
        log=$(
            HEALTHCHECK_URL=https://hc.example/check-id
            CF_ASSETS_ENABLED=false
            JOB_FAILURE_CLASS="$class"
            WORKERS_FAILURE_CLASS="$workers_class"
            record_update_exit "$status"
        )
        [[ "$(cat "$PINGS")" == "$expected" ]] || fail "exit $status (class '$class', Workers class '$workers_class') pinged: $(cat "$PINGS")"
        if [[ "$status" != 0 ]]; then
            [[ "$log" == *"Job failed: class=${class:-other} exit=$status"* ]] || fail "the failure class was not logged: $log"
        elif [[ -n "$workers_class" ]]; then
            [[ "$log" == *"Workers failure: class=$workers_class; the job exits 0 (CF_ASSETS_REQUIRED=false)"* ]] || fail "the Workers failure was not logged: $log"
        fi
    done
    (
        unset WORKERS_FAILURE_CLASS
        : > "$PINGS"
        HEALTHCHECK_URL=https://hc.example/check-id
        CF_ASSETS_ENABLED=false
        record_update_exit 0 > /dev/null
    )
    [[ "$(cat "$PINGS")" == 'https://hc.example/check-id ok' ]] || fail "a job that ended before publishing did not ping success: $(cat "$PINGS")"
    [[ "$UPDATE_SCRIPT" == *$'    log "❌ All uploads failed"\n    JOB_FAILURE_CLASS=storage\n'* ]] || fail "all storage uploads failing is not the class storage"

    [[ "$UPDATE_SCRIPT" == *$'\nheartbeat /start\nread_promoted_layout\nwarn_do_subtree_order\n'* ]] \
        || fail "the job does not ping its start, read the marker and check the DO order at its start"
    [[ "$UPDATE_SCRIPT" == *$'\nif [[ -n "$JOB_WARN_CLASS" ]]; then\n    JOB_FAILURE_CLASS="$JOB_WARN_CLASS"\n    log "❌ Published, but the charts Worker needs attention ($JOB_WARN_CLASS)"\n    exit 1\nfi\n\nlog "✅ Done! Site: $SITE_URL"'* ]] \
        || fail "the job does not exit non-zero for a promotion despite its charts"
    pass "the heartbeat is off without HEALTHCHECK_URL or with a bad one, never shows the URL, is bounded in time, and pings start, success and the failure class, a Workers failure also when the job exits 0"
}

test_do_subtree_order_warning() {
    local case layout subtrees expected log
    for case in \
        'charts|relay,contact,charts|it starts with relay' \
        'charts| relay charts|it starts with relay' \
        'charts|charts,relay,contact|' \
        'charts||' \
        'beside|relay,contact|'; do
        IFS='|' read -r layout subtrees expected <<< "$case"
        log=$(CHARTS_LAYOUT="$layout" DO_ENABLED=true DO_RCLONE_FAST_LIST_SUBTREES="$subtrees"; warn_do_subtree_order)
        if [[ -n "$expected" ]]; then
            [[ "$log" == *"list charts first in DO_RCLONE_FAST_LIST_SUBTREES ($expected)"* ]] || fail "'$subtrees' ($layout) did not warn: $log"
        else
            [[ -z "$log" ]] || fail "'$subtrees' ($layout) warned: $log"
        fi
    done
    log=$(CHARTS_LAYOUT=charts DO_ENABLED=true DO_RCLONE_FAST_LIST=true DO_RCLONE_FAST_LIST_SUBTREES=relay; warn_do_subtree_order)
    [[ -z "$log" ]] || fail "the subtree order was checked with one fast-list pass"
    pass "with CHARTS_LAYOUT=charts the job warns when DO's fast-list subtrees do not start with charts"
}

test_defaults
test_promoted_layout_marker
test_local_gates
test_heartbeat
test_do_subtree_order_warning
