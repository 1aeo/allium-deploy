#!/usr/bin/env bash

set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

DEPLOY_DIR="$TMP_DIR/deploy"
MOCK_BIN="$TMP_DIR/mock-bin"
FINGERPRINT='DB1629B59707F744A0C7933E56B6802786FFC317'
LATER_FINGERPRINT='F0A9B7C3D2E1F0A9B7C3D2E1F0A9B7C3D2E1F0A9'
CONTACT='0123456789abcdef0123456789abcdef'
PREVIEW='https://12345678-allium-shadow-test.test.workers.dev'
REAL_FIND=$(command -v find)
mkdir -p "$DEPLOY_DIR/scripts" "$MOCK_BIN"
cp "$REPO_DIR/scripts/allium-deploy-verify-cfassets.sh" "$DEPLOY_DIR/scripts/"

# find shim: MOCK_FIND_FAIL_CHARTS=1 makes the chart listing (the only call
# that names *.png) print one chart and then fail, as a partial walk would.
cat > "$MOCK_BIN/find" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
if [[ "${MOCK_FIND_FAIL_CHARTS:-0}" == 1 && " $* " == *' *.png '* ]]; then
    "$MOCK_FIND_REAL" "$@" | head -n 1
    echo "find: simulated walk failure" >&2
    exit 1
fi
exec "$MOCK_FIND_REAL" "$@"
EOF

# curl fixture: a preview serving the tree. MOCK_CHART_MODE changes only the
# *.png answers: ok, missing (404 page, as with a stale .assetsignore),
# redirect (as with a stale _redirects), type (wrong Content-Type) or body
# (different bytes). With CHARTS_LAYOUT=charts the charts sit below charts/,
# which a main Worker preview never serves (a request there fails the
# fixture): moved answers an old chart URL with the _redirects 302 to /charts/,
# moved-absolute the same with the preview's origin, moved-elsewhere a 302
# elsewhere and moved-missing a 404 page. Any other option, such as
# --location, fails the request, so that a verifier following redirects
# cannot pass the redirect cases.
cat > "$MOCK_BIN/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=/dev/null
headers=
url=
while (( $# )); do
    case "$1" in
        --output) output="$2"; shift 2 ;;
        --dump-header) headers="$2"; shift 2 ;;
        --max-time|--write-out) shift 2 ;;
        --silent|--show-error) shift ;;
        http*) url="$1"; shift ;;
        *) echo "unexpected curl argument: $1" >&2; exit 91 ;;
    esac
done
path="/${url#*://*/}"
[[ "$url" =~ ^https://[^/]+/$ ]] && path=/
status=200
header_lines=''
write_body() { [[ "$output" == /dev/null ]] || cp "$1" "$output"; }
case "$path" in
    /) write_body "$MOCK_SOURCE_DIR/index.html"
       header_lines=$'cache-control: public, max-age=0, must-revalidate\r\nx-robots-tag: noindex\r\n' ;;
    /__allium_cfassets_missing_probe__) status=404; : > "$output" ;;
    /search\?q=*) status=302; header_lines="location: /relay/$MOCK_FINGERPRINT/"$'\r\n' ;;
    */index.html|/charts/*) echo "unexpected fixture URL: $url" >&2; exit 90 ;;
    */) write_body "$MOCK_SOURCE_DIR${path}index.html" ;;
    *.png)
        printf '%s\n' "$path" >> "$MOCK_CHART_LOG"
        chart_file="$MOCK_SOURCE_DIR$path"
        [[ "${MOCK_CHART_MODE:-ok}" != moved* ]] || chart_file="$MOCK_SOURCE_DIR/charts$path"
        [[ -f "$chart_file" ]] || { echo "unexpected chart URL: $url" >&2; exit 90; }
        case "${MOCK_CHART_MODE:-ok}" in
            ok) write_body "$MOCK_SOURCE_DIR$path"; header_lines=$'Content-Type: image/png\r\n' ;;
            missing) status=404; write_body "$MOCK_SOURCE_DIR/index.html"; header_lines=$'Content-Type: text/html; charset=utf-8\r\n' ;;
            redirect) status=302; : > "$output"; header_lines="location: /charts$path"$'\r\n' ;;
            type) write_body "$MOCK_SOURCE_DIR$path"; header_lines=$'Content-Type: application/octet-stream\r\n' ;;
            body) printf 'not the chart\n' > "$output"; header_lines=$'Content-Type: image/png\r\n' ;;
            tight) write_body "$MOCK_SOURCE_DIR$path"; header_lines=$'content-type:IMAGE/PNG; charset=binary\r\n' ;;
            subtype) write_body "$MOCK_SOURCE_DIR$path"; header_lines=$'Content-Type: image/png-other\r\n' ;;
            moved) status=302; : > "$output"; header_lines="Location: /charts$path"$'\r\n' ;;
            moved-absolute) status=302; : > "$output"; header_lines="location: ${url%%"$path"}/charts$path"$'\r\n' ;;
            moved-elsewhere) status=302; : > "$output"; header_lines="location: /elsewhere$path"$'\r\n' ;;
            moved-missing) status=404; write_body "$MOCK_SOURCE_DIR/index.html"; header_lines=$'Content-Type: text/html\r\n' ;;
        esac
        ;;
    *)
        if [[ -d "$MOCK_SOURCE_DIR$path" ]]; then
            status=307
        else
            [[ -f "$MOCK_SOURCE_DIR$path" ]] || { echo "unexpected fixture URL: $url" >&2; exit 90; }
            write_body "$MOCK_SOURCE_DIR$path"
        fi
        ;;
esac
if [[ -n "$headers" ]]; then
    printf 'HTTP/1.1 %s X\r\n%s\r\n' "$status" "$header_lines" > "$headers"
fi
printf '%s' "$status"
EOF
chmod 0755 "$MOCK_BIN/find" "$MOCK_BIN/curl"

# make_tree <dir> <charts: relay|contact|none>
make_tree() {
    local dir="$1"
    mkdir -p "$dir/nested" "$dir/relay/$FINGERPRINT/0-sub" "$dir/relay/$LATER_FINGERPRINT" "$dir/contact/$CONTACT"
    printf '<html>root</html>\n' > "$dir/index.html"
    printf '<html>nested route</html>\n' > "$dir/nested/index.html"
    printf '<html>relay</html>\n' > "$dir/relay/$FINGERPRINT/index.html"
    printf '{"meta":{"version":"1.6"},"relays":[{"f":"%s"}]}\n' "$FINGERPRINT" > "$dir/search-index.json"
    head -c 4096 /dev/zero | tr '\0' L > "$dir/large.txt"
    # PNGs at other depths are never chart candidates.
    printf 'not a chart\n' > "$dir/relay/0-top-level.png"
    printf 'not a chart\n' > "$dir/relay/$FINGERPRINT/0-sub/0-deep.png"
    case "$2" in
        relay)
            printf 'png uptime\n' > "$dir/relay/$FINGERPRINT/uptime-6m.png"
            printf 'png bandwidth\n' > "$dir/relay/$FINGERPRINT/bandwidth-1m.png"
            printf 'png later relay\n' > "$dir/relay/$LATER_FINGERPRINT/bandwidth-1m.png"
            printf 'png contact\n' > "$dir/contact/$CONTACT/bandwidth-1m.png"
            ;;
        contact)
            printf 'png contact\n' > "$dir/contact/$CONTACT/bandwidth-6m.png"
            ;;
    esac
}

# run_verifier <tree> <chart mode> [find failure 0|1]; sets RUN_OUTPUT,
# RUN_STATUS and RUN_CHARTS (the chart paths requested). LAYOUT sets
# CHARTS_LAYOUT and NO_CHARTS ALLIUM_NO_CHARTS.
run_verifier() {
    local chart_log="$TMP_DIR/chart-requests"
    : > "$chart_log"
    set +e
    RUN_OUTPUT=$(PATH="$MOCK_BIN:$PATH" \
        CHARTS_LAYOUT="${LAYOUT:-beside}" \
        ALLIUM_NO_CHARTS="${NO_CHARTS:-false}" \
        MOCK_FIND_REAL="$REAL_FIND" \
        MOCK_FIND_FAIL_CHARTS="${3:-0}" \
        MOCK_SOURCE_DIR="$1" \
        MOCK_CHART_MODE="$2" \
        MOCK_CHART_LOG="$chart_log" \
        MOCK_FINGERPRINT="$FINGERPRINT" \
        CF_ASSETS_VERIFY_ATTEMPTS=1 \
        CF_ASSETS_VERIFY_MAX_ATTEMPTS=1 \
        CF_ASSETS_VERIFY_RETRY_DELAY=0 \
        "$DEPLOY_DIR/scripts/allium-deploy-verify-cfassets.sh" "$PREVIEW" "$1" 2>&1)
    RUN_STATUS=$?
    set -e
    RUN_CHARTS=$(sort -u "$chart_log")
}

# assert_chart_failure <mode> <expected log fragment> <description>
assert_chart_failure() {
    run_verifier "$RELAY_TREE" "$1"
    [[ "$RUN_STATUS" == 1 ]] || fail "$1 chart exited $RUN_STATUS instead of 1: $RUN_OUTPUT"
    [[ "$RUN_OUTPUT" == *"$2"* ]] || fail "$1 chart was not reported: $RUN_OUTPUT"
    [[ "$RUN_OUTPUT" != *'all checks passed'* ]] || fail "$1 chart still passed: $RUN_OUTPUT"
    pass "$3"
}

RELAY_TREE="$TMP_DIR/relay-tree"
make_tree "$RELAY_TREE" relay
RELAY_CHART="/relay/$FINGERPRINT/bandwidth-1m.png"

run_verifier "$RELAY_TREE" ok
[[ "$RUN_STATUS" == 0 ]] || fail "healthy preview exited $RUN_STATUS: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *"chart ok: $RELAY_CHART content-type='image/png' sha256="* ]] \
    || fail "healthy preview did not verify $RELAY_CHART: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *'all checks passed'* ]] || fail "healthy preview did not pass: $RUN_OUTPUT"
[[ "$RUN_CHARTS" == "$RELAY_CHART" ]] || fail "unexpected chart requests: $RUN_CHARTS"
pass "the first relay chart two levels deep is fetched and matches the source"

assert_chart_failure missing "chart failed: HTTP 404 for $RELAY_CHART" \
    "a preview whose charts 404 (for example a stale .assetsignore) fails verification"
assert_chart_failure redirect "chart failed: HTTP 302 for $RELAY_CHART" \
    "a preview that redirects charts (for example a stale _redirects) fails verification"
assert_chart_failure type "chart failed: unexpected Content-Type 'application/octet-stream' for $RELAY_CHART" \
    "a chart served without image/png fails verification"
assert_chart_failure body "chart failed: SHA-256 mismatch for $RELAY_CHART" \
    "a chart whose bytes differ from the source fails verification"
assert_chart_failure subtype "chart failed: unexpected Content-Type 'image/png-other' for $RELAY_CHART" \
    "a media type that only starts with image/png fails verification"

run_verifier "$RELAY_TREE" tight
[[ "$RUN_STATUS" == 0 ]] || fail "Content-Type without a space, in capitals and with a parameter exited $RUN_STATUS: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *"chart ok: $RELAY_CHART content-type='IMAGE/PNG; charset=binary' sha256="* ]] \
    || fail "Content-Type without a space was not parsed: $RUN_OUTPUT"
pass "image/png is matched case-insensitively, with or without a space after the colon and with parameters"

CONTACT_TREE="$TMP_DIR/contact-tree"
make_tree "$CONTACT_TREE" contact
run_verifier "$CONTACT_TREE" ok
[[ "$RUN_STATUS" == 0 ]] || fail "contact-only tree exited $RUN_STATUS: $RUN_OUTPUT"
[[ "$RUN_CHARTS" == "/contact/$CONTACT/bandwidth-6m.png" ]] || fail "contact chart was not probed: $RUN_CHARTS"
pass "without relay charts a contact chart is probed"

NO_CHART_TREE="$TMP_DIR/no-chart-tree"
make_tree "$NO_CHART_TREE" none
run_verifier "$NO_CHART_TREE" missing
[[ "$RUN_STATUS" == 0 ]] || fail "tree without charts exited $RUN_STATUS: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *'chart probe skipped'* ]] || fail "skipped chart probe was not logged: $RUN_OUTPUT"
[[ -z "$RUN_CHARTS" ]] || fail "a non-chart PNG was probed: $RUN_CHARTS"
pass "a tree without PNG charts skips the chart probe"

run_verifier "$RELAY_TREE" ok 1
[[ "$RUN_STATUS" == 2 ]] || fail "failed chart listing exited $RUN_STATUS instead of 2: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *"Could not list chart PNGs under $RELAY_TREE/relay"* ]] \
    || fail "failed chart listing was not reported: $RUN_OUTPUT"
[[ -z "$RUN_CHARTS" ]] || fail "a chart was probed after a failed listing: $RUN_CHARTS"
pass "a chart listing error fails closed instead of skipping the probe"

# CHARTS_LAYOUT=charts: the charts below charts/ are the charts Worker's, so
# the old URL of the first relay chart must redirect there, and neither the
# chart nor the largest file is fetched from charts/ (a chart there is the
# largest file of this tree).
MOVED_TREE="$TMP_DIR/moved-tree"
make_tree "$MOVED_TREE" none
mkdir -p "$MOVED_TREE/charts/relay/$FINGERPRINT" "$MOVED_TREE/charts/contact/$CONTACT"
head -c 9000 /dev/zero | tr '\0' C > "$MOVED_TREE/charts/relay/$FINGERPRINT/bandwidth-1m.png"
printf 'png contact\n' > "$MOVED_TREE/charts/contact/$CONTACT/bandwidth-1m.png"
for mode in moved moved-absolute; do
    LAYOUT=charts run_verifier "$MOVED_TREE" "$mode"
    [[ "$RUN_STATUS" == 0 ]] || fail "charts layout ($mode) exited $RUN_STATUS: $RUN_OUTPUT"
    [[ "$RUN_OUTPUT" == *"chart redirect ok: $RELAY_CHART -> /charts$RELAY_CHART"* && "$RUN_OUTPUT" == *'all checks passed'* ]] \
        || fail "charts layout ($mode) did not check the redirect: $RUN_OUTPUT"
    [[ "$RUN_CHARTS" == "$RELAY_CHART" ]] || fail "charts layout ($mode) requested other charts: $RUN_CHARTS"
    [[ "$RUN_OUTPUT" == *'largest ok: /large.txt'* ]] || fail "the largest file was taken from charts/: $RUN_OUTPUT"
done
LAYOUT=charts run_verifier "$MOVED_TREE" moved-elsewhere
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"chart redirect failed: $RELAY_CHART redirects to '/elsewhere$RELAY_CHART', not /charts$RELAY_CHART"* ]] \
    || fail "a redirect elsewhere was accepted: $RUN_OUTPUT"
LAYOUT=charts run_verifier "$MOVED_TREE" moved-missing
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"chart redirect failed: HTTP 404 for $RELAY_CHART"* ]] \
    || fail "a version without the _redirects was accepted: $RUN_OUTPUT"
# A tree whose charts are not below charts/ (here beside the pages) fails
# before any request, however the preview answers.
LAYOUT=charts run_verifier "$RELAY_TREE" missing
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *"No chart PNG under $RELAY_TREE/charts/relay or $RELAY_TREE/charts/contact, which CHARTS_LAYOUT=charts requires"* ]] \
    || fail "a charts-layout tree without charts below charts/ did not fail: $RUN_STATUS $RUN_OUTPUT"
[[ -z "$RUN_CHARTS" && "$RUN_OUTPUT" != *'all checks passed'* ]] || fail "a charts-layout tree without charts below charts/ was probed: $RUN_CHARTS"
pass "with CHARTS_LAYOUT=charts the old chart URL must redirect to /charts/, charts/ stays out of the checks, and a tree without charts below charts/ fails"
# Allium ran with --no-charts (ALLIUM_NO_CHARTS=true): a charts-layout tree
# without a chart below charts/ is checked without the chart probe.
NO_CHARTS_TREE="$TMP_DIR/no-charts-tree"
make_tree "$NO_CHARTS_TREE" none
LAYOUT=charts NO_CHARTS=true run_verifier "$NO_CHARTS_TREE" missing
[[ "$RUN_STATUS" == 0 && -z "$RUN_CHARTS" && "$RUN_OUTPUT" == *'no chart PNG under charts/relay/ or charts/contact/; chart probe skipped'* ]] \
    || fail "ALLIUM_NO_CHARTS=true did not skip the chart probe: $RUN_STATUS $RUN_OUTPUT"
LAYOUT=charts run_verifier "$NO_CHARTS_TREE" missing
[[ "$RUN_STATUS" == 2 ]] || fail "a charts-layout tree without charts passed without ALLIUM_NO_CHARTS: $RUN_STATUS $RUN_OUTPUT"
pass "with ALLIUM_NO_CHARTS=true a charts-layout tree without charts is verified without the chart probe"
