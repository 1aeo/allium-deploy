#!/usr/bin/env bash
# allium-deploy-verify-cfcharts.sh against a local fixture HTTP server that
# serves a charts stage like the charts Worker (and old chart URLs like the
# main Worker's _redirects): the sample taken from the pages (a vanity-domain
# page included) and the stage, the build ID, the charts Worker's marker
# header, every per-chart check, the 304 and missing-chart checks, the
# failures for an empty stage and for pages without or with unknown chart
# links, the production route check with its definitive and inconclusive
# failures in either order, its bootstrap form, and the redirect check.

set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=$(mktemp -d)
SERVER_PID=""
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
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

command -v python3 >/dev/null 2>&1 || fail "python3 is required for the fixture HTTP server"

STAGE="$TMP_DIR/stage"
OUT="$TMP_DIR/output"
MODE_FILE="$TMP_DIR/mode"
REQUESTS="$TMP_DIR/requests"
VERIFY="$REPO_DIR/scripts/allium-deploy-verify-cfcharts.sh"

# The fixture server answers from the stage as the charts Worker does: a chart
# with its type, nosniff, a noindex, the marker X-Allium-Origin: charts and a
# content ETag (304 on a match), the build ID, a miss with 404 and
# charts/404.html. Old chart URLs get the main Worker's 302. The words in the
# mode file each break one property: nosniff, noindex, nomarker (also only
# nomarkerid, nomarkerchart or nomarker404), type, body,
# noetag, no304, missing200, missingbody, redirect (charts redirect too, the
# build ID does not), noroute (everything below /charts/ gets the main
# Worker's 404, without the marker), norouteredirect (old URLs 404),
# wrongredirect, challenge (403 with cf-mitigated: challenge below /charts/),
# unavailable (503 below /charts/), ratelimited (429), badgateway (502), waf
# (403 without cf-mitigated), othermarker (X-Allium-Origin: main), robots404
# (X-Robots-Tag on the 404 page only), flip (the build ID alternates between
# another one and a 503), flop (a 503 first, then another build ID) and
# flopok (a 503 first, then the right build ID). /charts/404.html itself is
# served as a page, as the charts Worker serves it. Each request is logged.
cat > "$TMP_DIR/server.py" <<'EOF'
import hashlib, http.server, os, re, sys

stage, mode_file, log_file, port_file = sys.argv[1:5]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status, headers, body=b""):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        modes = open(mode_file).read().split() if os.path.exists(mode_file) else []
        condition = self.headers.get("If-None-Match")
        with open(log_file, "a") as log:
            log.write(("conditional " if condition else "") + self.path + "\n")
        path = self.path.split("?")[0]
        old = re.fullmatch(r"/(relay|contact)/([^/]+)/([^/]+\.png)", path)
        if old:
            if "norouteredirect" in modes:
                return self.send(404, [("Content-Type", "text/html")], b"main 404")
            target = "/charts" + path
            if "wrongredirect" in modes:
                target = "/elsewhere" + path
            return self.send(302, [("Location", target)])
        if "redirect" in modes and path != "/charts/build-id.txt":
            return self.send(302, [("Location", "/elsewhere" + path)])
        if "noroute" in modes:
            return self.send(404, [("Content-Type", "text/html"), ("X-Content-Type-Options", "nosniff")],
                             open(os.path.join(stage, "charts", "404.html"), "rb").read())
        if "challenge" in modes:
            return self.send(403, [("Content-Type", "text/html"), ("cf-mitigated", "challenge")], b"challenge")
        if "unavailable" in modes:
            return self.send(503, [("Content-Type", "text/html")], b"unavailable")
        for mode, status in (("ratelimited", 429), ("badgateway", 502), ("waf", 403)):
            if mode in modes:
                return self.send(status, [("Content-Type", "text/html")], mode.encode())
        file = os.path.join(stage, path.lstrip("/"))
        common = [("X-Content-Type-Options", "nosniff")] if "nosniff" not in modes else []
        if "noindex" not in modes:
            common.append(("X-Robots-Tag", "noindex"))
        def marker(kind):
            if "nomarker" in modes or "nomarker" + kind in modes:
                return []
            return [("X-Allium-Origin", "main" if "othermarker" in modes else "charts")]
        flipping = [mode for mode in ("flip", "flop", "flopok") if mode in modes]
        if path == "/charts/build-id.txt" and flipping:
            flips = os.path.join(os.path.dirname(log_file), "flips")
            count = int(open(flips).read()) + 1 if os.path.exists(flips) else 1
            open(flips, "w").write(str(count))
            if (count % 2 == 0) == (flipping[0] == "flip"):
                return self.send(503, [("Content-Type", "text/html")], b"unavailable")
            if flipping[0] != "flopok":
                return self.send(200, common + marker("id") + [("Content-Type", "text/plain")], b"another build\n")
        if path == "/charts/build-id.txt" and os.path.isfile(file):
            return self.send(200, common + marker("id") + [("Content-Type", "text/plain")], open(file, "rb").read())
        if path.startswith("/charts/") and path.endswith(".png") and os.path.isfile(file):
            body = open(file, "rb").read()
            etag = '"%s"' % hashlib.sha256(body).hexdigest()[:32]
            chart_type = "text/html" if "type" in modes else "image/png-other" if "subtype" in modes else "IMAGE/PNG; charset=binary" if "upper" in modes else "image/png"
            headers = common + marker("chart") + [("Content-Type", chart_type)]
            if "noetag" not in modes:
                headers.append(("ETag", etag))
            if condition == etag and "no304" not in modes:
                return self.send(304, headers)
            return self.send(200, headers, b"other bytes" if "body" in modes else body)
        page = open(os.path.join(stage, "charts", "404.html"), "rb").read()
        if "missingbody" in modes:
            page = b"another page"
        html = [("Content-Type", "text/html; charset=utf-8")]
        if path == "/charts/404.html":
            return self.send(200, common + marker("404") + html, page)
        status = 200 if "missing200" in modes else 404
        robots = [("X-Robots-Tag", "noindex")] if "robots404" in modes else []
        return self.send(status, common + robots + marker("404") + html, page)

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(port_file + ".tmp", "w") as handle:
    handle.write(str(server.server_address[1]))
os.rename(port_file + ".tmp", port_file)
server.serve_forever()
EOF

put() {
    mkdir -p "$(dirname "$1")"
    head -c "$2" /dev/zero | tr '\0' "${3:-x}" > "$1"
}
# Twelve relays and two contacts, one chart clearly the largest. Files that
# are not depth-two chart PNGs below charts/ are never sampled.
for n in 01 02 03 04 05 06 07 08 09 10 11 12; do
    put "$STAGE/charts/relay/FP$n/bandwidth-1m.png" $((100 + 10#$n)) a
    put "$STAGE/charts/relay/FP$n/uptime-6m.png" $((200 + 10#$n)) b
done
put "$STAGE/charts/relay/FP07/uptime-1y.png" 9000 c
put "$STAGE/charts/contact/c1/bandwidth-1y.png" 150 d
put "$STAGE/charts/contact/c2/bandwidth-6m.png" 160 e
put "$STAGE/charts/relay/top.png" 20000 t
put "$STAGE/charts/relay/FP01/sub/deep.png" 20000 s
put "$STAGE/_headers" 50 h
printf '<html>Not Found</html>\n' > "$STAGE/charts/404.html"
printf '2026-10-14T00:00:00Z 100-1\n' > "$STAGE/charts/build-id.txt"

# write_page <page> <src...>: a page with these image sources.
write_page() {
    local page="$1" src
    shift
    mkdir -p "$(dirname "$OUT/$page")"
    {
        printf '<html><img src="../../static/images/flags/de.png">\n'
        for src in "$@"; do
            printf '<a href="%s"><img src="%s" width="1080"></a>\n' "$src" "$src"
        done
        printf '</html>\n'
    } > "$OUT/$page"
}
for n in 01 02 03 04 05 06 07 08 09 10 11 12; do
    write_page "relay/FP$n/index.html" "../../charts/relay/FP$n/bandwidth-1m.png" "../../charts/relay/FP$n/uptime-6m.png?v=1"
done
write_page relay/FP07/index.html ../../charts/relay/FP07/uptime-1y.png ../../charts/relay/FP07/bandwidth-1m.png
write_page contact/c1/index.html ../../charts/contact/c1/bandwidth-1y.png
write_page contact/c2/index.html /charts/contact/c2/bandwidth-6m.png
# A vanity-domain page, one level deep, and a top-level page without charts
# that sorts before it.
write_page aaa.example/index.html
write_page vanity.example/index.html ../charts/contact/c2/bandwidth-6m.png

python3 "$TMP_DIR/server.py" "$STAGE" "$MODE_FILE" "$REQUESTS" "$TMP_DIR/port" &
SERVER_PID=$!
for _ in $(seq 1 100); do
    [[ -s "$TMP_DIR/port" ]] && break
    sleep 0.1
done
[[ -s "$TMP_DIR/port" ]] || fail "the fixture server did not start"
PORT=$(cat "$TMP_DIR/port")
# Version-prefixed hosts, as preview URLs are; both resolve to the fixture.
PREVIEW="http://0a1b2c3d-allium-charts-test.localhost:$PORT"
OTHER_PREVIEW="http://fedcba98-allium-charts-test.localhost:$PORT"
SITE="http://127.0.0.1:$PORT"
MISSING='/charts/relay/__allium_cfcharts_missing_probe__/bandwidth-1m.png'

# run_verifier <arguments...>: MODES, PASSES and ATTEMPTS (default 1 and 1)
# apply. Sets RUN_OUTPUT, RUN_STATUS, RUN_REQUESTS (every request in order)
# and RUN_CHARTS (plain chart requests, sorted).
run_verifier() {
    printf '%s\n' "${MODES:-}" > "$MODE_FILE"
    : > "$REQUESTS"
    rm -f "$TMP_DIR/flips"
    set +e
    RUN_OUTPUT=$(CF_ASSETS_VERIFY_ATTEMPTS="${PASSES:-1}" CF_ASSETS_VERIFY_MAX_ATTEMPTS="${ATTEMPTS:-1}" \
        CF_ASSETS_VERIFY_RETRY_DELAY=0 CF_ASSETS_VERIFY_CURL_TIMEOUT=10 \
        "$VERIFY" "$@" 2>&1)
    RUN_STATUS=$?
    set -e
    RUN_REQUESTS=$(cat "$REQUESTS")
    RUN_CHARTS=$(grep -v -e '^conditional ' -e "^$MISSING\$" -e '^/charts/build-id.txt$' "$REQUESTS" | LC_ALL=C sort || true)
}

# curl resolves localhost subdomains to the loopback interface itself. Where
# it does not, the version-seeded picks cannot be compared across versions.
if ! curl --silent --max-time 5 --output /dev/null "$PREVIEW$MISSING"; then
    PREVIEW="$SITE"
    OTHER_PREVIEW=""
fi

run_verifier "$PREVIEW" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 0 && "$RUN_OUTPUT" == *'all chart checks passed 1 consecutive times'* ]] \
    || fail "a healthy preview did not pass: $RUN_STATUS $RUN_OUTPUT"
# From the pages: the first relay's and the first contact's, two each at most,
# resolved from the page; then the stage's first relay chart, the largest and
# the first contact chart.
for expected in /charts/relay/FP01/bandwidth-1m.png /charts/relay/FP01/uptime-6m.png /charts/contact/c1/bandwidth-1y.png \
    /charts/contact/c2/bandwidth-6m.png /charts/relay/FP07/uptime-1y.png; do
    grep -Fqx -- "$expected" <<< "$RUN_CHARTS" || fail "$expected was not sampled: $RUN_CHARTS"
done
while IFS= read -r sampled; do
    [[ "$sampled" =~ ^/charts/(relay|contact)/[^/]+/[^/]*\.png$ && "$sampled" != /charts/relay/top.png ]] || fail "a non-chart file was sampled: $sampled"
done <<< "$RUN_CHARTS"
count=$(wc -l <<< "$RUN_CHARTS" | tr -d ' ')
(( count >= 4 && count <= 12 )) || fail "unexpected sample size $count: $RUN_CHARTS"
[[ "$(grep -c '^conditional ' <<< "$RUN_REQUESTS")" == 1 && "$RUN_REQUESTS" == *$'\n'"conditional /charts/relay/FP01/bandwidth-1m.png"$'\n'"$MISSING" ]] \
    || fail "the 304 and missing-chart checks did not follow the sample: $RUN_REQUESTS"
[[ "$RUN_REQUESTS" == $'/charts/build-id.txt\n'* && "$RUN_OUTPUT" == *'build ID ok: 2026-10-14T00:00:00Z 100-1'* ]] \
    || fail "the build ID was not checked first: $RUN_REQUESTS"
FIRST_SAMPLE="$RUN_CHARTS"
run_verifier "$PREVIEW" "$STAGE" "$OUT"
[[ "$RUN_CHARTS" == "$FIRST_SAMPLE" ]] || fail "the same preview sampled different charts"
if [[ -n "$OTHER_PREVIEW" ]]; then
    run_verifier "$OTHER_PREVIEW" "$STAGE" "$OUT"
    [[ "$RUN_STATUS" == 0 && "$RUN_CHARTS" != "$FIRST_SAMPLE" ]] || fail "another version sampled the same charts: $RUN_CHARTS"
fi
[[ "$RUN_OUTPUT" == *"missing chart ok: 404 page for $MISSING"* ]] || fail "the missing chart was not checked: $RUN_OUTPUT"
pass "the sample takes charts the new pages link to (a vanity-domain page's included), then the stage's first, largest, first contact and version-seeded charts"

# assert_failure <modes> <expected log fragment> <description>
assert_failure() {
    MODES="$1" run_verifier "$PREVIEW" "$STAGE" "$OUT"
    [[ "$RUN_STATUS" == 1 ]] || fail "$1 exited $RUN_STATUS instead of 1: $RUN_OUTPUT"
    [[ "$RUN_OUTPUT" == *"$2"* ]] || fail "$1 was not reported: $RUN_OUTPUT"
    [[ "$RUN_OUTPUT" != *'all chart checks passed'* ]] || fail "$1 still passed"
    pass "$3"
}
assert_failure nosniff 'chart failed: no X-Content-Type-Options: nosniff for /charts/relay/FP01/bandwidth-1m.png' \
    "a chart without nosniff fails"
assert_failure nomarkerid 'build ID failed: no X-Allium-Origin: charts for /charts/build-id.txt (another Worker answered)' \
    "a build ID without the charts Worker's marker fails"
assert_failure nomarkerchart 'chart failed: no X-Allium-Origin: charts for /charts/relay/FP01/bandwidth-1m.png' \
    "a chart without the charts Worker's marker fails"
assert_failure nomarker404 "missing chart failed: no X-Allium-Origin: charts for $MISSING" \
    "a 404 page without the charts Worker's marker fails: the main Worker's is byte for byte the same"
assert_failure noindex 'chart failed: the preview is missing noindex' "a chart without the preview's noindex fails"
assert_failure type "chart failed: unexpected Content-Type 'text/html'" "a chart that is not image/png fails"
assert_failure subtype "chart failed: unexpected Content-Type 'image/png-other'" \
    "a media type that only starts with image/png fails"
MODES=upper run_verifier "$PREVIEW" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 0 ]] || fail "an upper-case image/png with a parameter exited $RUN_STATUS: $RUN_OUTPUT"
pass "image/png is matched without regard to case and with parameters"
assert_failure body 'chart failed: SHA-256 mismatch for /charts/relay/FP01/bandwidth-1m.png' "a chart whose bytes differ from the stage fails"
assert_failure noetag 'chart failed: no ETag' "a chart without an ETag fails"
assert_failure no304 'conditional request failed: HTTP 200 instead of 304' "a chart that ignores If-None-Match fails"
assert_failure missing200 'missing chart failed: HTTP 200 instead of 404' "a missing chart that does not 404 fails"
assert_failure missingbody 'missing chart failed: the body is not charts/404.html' "a missing chart without charts/404.html fails"
assert_failure redirect 'chart failed: HTTP 302 for /charts/relay/FP01/bandwidth-1m.png' "a redirected chart fails; redirects are not followed"

# Nothing to verify, or pages that do not match the stage, fail before any
# request.
mkdir -p "$TMP_DIR/empty-stage/charts"
cp "$STAGE/_headers" "$TMP_DIR/empty-stage/"
cp "$STAGE/charts/404.html" "$TMP_DIR/empty-stage/charts/"
run_verifier "$PREVIEW" "$TMP_DIR/empty-stage" "$OUT"
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'No chart PNG to verify under'* && -z "$RUN_REQUESTS" ]] \
    || fail "an empty stage did not fail: $RUN_STATUS $RUN_OUTPUT"
BESIDE_OUT="$TMP_DIR/beside-output"
cp -R "$OUT" "$BESIDE_OUT"
# Pages of the beside layout link to charts in their own folder.
for page in relay/FP{01,02,03,04,05,06,07,08,09,10,11,12}/index.html contact/c1/index.html vanity.example/index.html; do
    OUT="$BESIDE_OUT" write_page "$page" bandwidth-1m.png uptime-6m.png
done
run_verifier "$PREVIEW" "$STAGE" "$BESIDE_OUT"
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'link to no chart below charts/'* && -z "$RUN_REQUESTS" ]] \
    || fail "pages without chart links did not fail: $RUN_STATUS $RUN_OUTPUT"
write_page relay/FP01/index.html ../../charts/relay/FP01/bandwidth-1m.png ../../charts/relay/FP01/gone-1y.png
run_verifier "$PREVIEW" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'links to /charts/relay/FP01/gone-1y.png, which the stage lacks'* && -z "$RUN_REQUESTS" ]] \
    || fail "a page linking to an unstaged chart did not fail: $RUN_STATUS $RUN_OUTPUT"
write_page relay/FP01/index.html ../../charts/relay/FP01/bandwidth-1m.png ../../charts/relay/FP01/uptime-6m.png
mv "$OUT/contact/c1/index.html" "$TMP_DIR/contact-page"
run_verifier "$PREVIEW" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'holds charts for contact/c1/index.html'* ]] || fail "a missing page did not fail: $RUN_STATUS $RUN_OUTPUT"
mv "$TMP_DIR/contact-page" "$OUT/contact/c1/index.html"
run_verifier "$PREVIEW" "$STAGE"
[[ "$RUN_STATUS" == 0 && "$RUN_CHARTS" != *FP01/uptime-6m.png* ]] || fail "without an output tree the stage sample alone did not pass: $RUN_OUTPUT"
pass "an empty stage, pages without chart links, links to unstaged charts and missing pages fail without a request; the output tree is optional"

# Passes must be consecutive, as in the main Worker's verifier.
PASSES=2 ATTEMPTS=2 MODES=missing200 run_verifier "$PREVIEW" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'2 consecutive passes were not reached in 2 attempts'* ]] \
    || fail "failing check sets passed: $RUN_STATUS $RUN_OUTPUT"
PASSES=2 ATTEMPTS=2 run_verifier "$PREVIEW" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 0 && "$(grep -c "^$MISSING\$" <<< "$RUN_REQUESTS")" == 2 ]] || fail "two passes were not two check sets"
pass "the preview check needs the configured consecutive passes"

# The production route check: the stage's build ID, then the charts the pages
# link to (without the version's pick) and the stage's first relay chart, the
# largest and the first contact chart below /charts/, then the missing chart;
# every answer with the marker and without X-Robots-Tag.
MODES=noindex run_verifier --route "$SITE" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 0 ]] || fail "the route check failed: $RUN_OUTPUT"
[[ "$RUN_REQUESTS" == $'/charts/build-id.txt\n'* && "$RUN_REQUESTS" == *$'\n'"$MISSING" ]] \
    || fail "the route check did not start with the build ID and end with the missing chart: $RUN_REQUESTS"
[[ "$RUN_CHARTS" == $'/charts/contact/c1/bandwidth-1y.png\n/charts/contact/c2/bandwidth-6m.png\n/charts/relay/FP01/bandwidth-1m.png\n/charts/relay/FP01/uptime-6m.png\n/charts/relay/FP07/uptime-1y.png' ]] \
    || fail "unexpected route check sample: $RUN_CHARTS"
[[ "$RUN_REQUESTS" != *conditional* ]] || fail "the route check sent a conditional request"
MODES=noindex run_verifier --route "$SITE" "$STAGE"
[[ "$RUN_STATUS" == 0 && "$RUN_CHARTS" == $'/charts/contact/c1/bandwidth-1y.png\n/charts/relay/FP01/bandwidth-1m.png\n/charts/relay/FP07/uptime-1y.png' ]] \
    || fail "the route check without an output tree: $RUN_STATUS $RUN_CHARTS"
# Definitive failures: wrong answers from production.
for modes in body type redirect noroute nomarkerchart nomarker404 ''; do
    MODES="${modes:-index} ${modes:+noindex}" run_verifier --route "$SITE" "$STAGE" "$OUT"
    [[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'the <host>/charts/* route is missing or reaches another Worker or version'* ]] \
        || fail "the route check accepted '$modes': $RUN_STATUS $RUN_OUTPUT"
done
[[ "$RUN_OUTPUT" == *"build ID failed: production sends X-Robots-Tag 'noindex' for /charts/build-id.txt"* ]] \
    || fail "an X-Robots-Tag on production was not reported: $RUN_OUTPUT"
MODES="noindex noroute" run_verifier --route "$SITE" "$STAGE" "$OUT"
[[ "$RUN_OUTPUT" == *'build ID failed: HTTP 404 for /charts/build-id.txt'* ]] || fail "a missing route was not reported: $RUN_OUTPUT"
ATTEMPTS=3 MODES="noindex body" run_verifier --route "$SITE" "$STAGE"
[[ "$RUN_STATUS" == 1 && "$(grep -c '^/charts/relay/FP01/bandwidth-1m.png$' <<< "$RUN_REQUESTS")" == 3 ]] \
    || fail "the route check was not retried: $RUN_REQUESTS"
# Inconclusive failures: a challenge, 503s, a closed port. Only --route tells
# them apart; a wrong answer in any attempt is definitive.
for modes in challenge unavailable; do
    ATTEMPTS=2 MODES="noindex $modes" run_verifier --route "$SITE" "$STAGE" "$OUT"
    [[ "$RUN_STATUS" == 75 && "$RUN_OUTPUT" == *'inconclusive: every failed attempt met'* ]] \
        || fail "'$modes' was not inconclusive: $RUN_STATUS $RUN_OUTPUT"
done
[[ "$RUN_OUTPUT" == *"inconclusive: HTTP 503 for $SITE/charts/build-id.txt"* ]] || fail "a 503 was not logged: $RUN_OUTPUT"
MODES="noindex challenge" run_verifier --route "$SITE" "$STAGE"
[[ "$RUN_OUTPUT" == *'inconclusive: HTTP 403 (cf-mitigated: challenge)'* ]] || fail "a challenge was not logged: $RUN_OUTPUT"
CLOSED_PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
ATTEMPTS=1 run_verifier --route "http://127.0.0.1:$CLOSED_PORT" "$STAGE"
[[ "$RUN_STATUS" == 75 && "$RUN_OUTPUT" == *'transient curl/network error'* ]] || fail "a network error was not inconclusive: $RUN_STATUS $RUN_OUTPUT"
ATTEMPTS=2 MODES="noindex flip" run_verifier --route "$SITE" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"is not this stage's build ID"* && "$RUN_OUTPUT" == *'inconclusive: HTTP 503'* ]] \
    || fail "a wrong answer followed by a 503 was not definitive: $RUN_STATUS $RUN_OUTPUT"
# The other order: a 503 first, then a wrong answer, about the build ID or,
# once that matches, about a chart.
ATTEMPTS=2 MODES="noindex flop" run_verifier --route "$SITE" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"is not this stage's build ID"* && "$RUN_OUTPUT" == *'inconclusive: HTTP 503'* ]] \
    || fail "a 503 followed by another build ID was not definitive: $RUN_STATUS $RUN_OUTPUT"
ATTEMPTS=2 MODES="noindex flopok body" run_verifier --route "$SITE" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'build ID ok'* && "$RUN_OUTPUT" == *'chart failed: SHA-256 mismatch'* && "$RUN_OUTPUT" == *'inconclusive: HTTP 503'* ]] \
    || fail "a 503 followed by a wrong chart was not definitive: $RUN_STATUS $RUN_OUTPUT"
# Rate limits, other 5xx answers and a 403 without a challenge are
# inconclusive too; another Worker's marker value is a wrong answer, and so is
# an X-Robots-Tag on the 404 page alone.
for case in ratelimited:75:'HTTP 429' badgateway:75:'HTTP 502' waf:75:'HTTP 403 for' \
    othermarker:1:'no X-Allium-Origin: charts for /charts/build-id.txt' \
    robots404:1:"missing chart failed: production sends X-Robots-Tag 'noindex'"; do
    IFS=: read -r modes expected message <<< "$case"
    MODES="noindex $modes" run_verifier --route "$SITE" "$STAGE" "$OUT"
    [[ "$RUN_STATUS" == "$expected" && "$RUN_OUTPUT" == *"$message"* ]] || fail "'$modes' did not exit $expected: $RUN_STATUS $RUN_OUTPUT"
done
MODES=unavailable run_verifier "$PREVIEW" "$STAGE"
[[ "$RUN_STATUS" == 1 ]] || fail "the preview check did not fail plainly on 503s: $RUN_STATUS"
# Production still serves the previous version: this build's stage adds a
# relay and changes a chart that is not sampled, so every sampled chart still
# matches, but the build ID does not.
NEXT_STAGE="$TMP_DIR/next-stage"
cp -R "$STAGE" "$NEXT_STAGE"
put "$NEXT_STAGE/charts/relay/FP02/bandwidth-1m.png" 333 z
put "$NEXT_STAGE/charts/relay/FP99/bandwidth-1m.png" 120 n
printf '2026-10-14T00:30:00Z 200-2\n' > "$NEXT_STAGE/charts/build-id.txt"
run_verifier --route "$SITE" "$NEXT_STAGE"
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"build ID failed: $SITE/charts/build-id.txt is not this stage's build ID, 2026-10-14T00:30:00Z 200-2"* ]] \
    || fail "the route check accepted the previous version: $RUN_STATUS $RUN_OUTPUT"
rm "$NEXT_STAGE/charts/build-id.txt"
run_verifier --route "$SITE" "$NEXT_STAGE"
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'The stage has no charts/build-id.txt'* && -z "$RUN_REQUESTS" ]] \
    || fail "a stage without a build ID was accepted: $RUN_STATUS $RUN_OUTPUT"
pass "the route check needs production's /charts/ to serve this stage's build ID, the pages' and the stage's charts byte for byte and the 404 page, each with the marker and no X-Robots-Tag; only challenges, 403, 429, 5xx and network errors exit 75"

# The bootstrap form, before the switch: the bootstrap stage has only the
# _headers and charts/404.html. /charts/404.html must be that page, and a
# missing chart must get it as the 404 page, from the charts Worker; the main
# Worker answers both with its own 404 page, without the marker.
BOOTSTRAP_STAGE="$TMP_DIR/bootstrap-stage"
mkdir -p "$BOOTSTRAP_STAGE/charts"
cp "$STAGE/_headers" "$BOOTSTRAP_STAGE/"
cp "$STAGE/charts/404.html" "$BOOTSTRAP_STAGE/charts/"
MODES=noindex run_verifier --route-bootstrap "$SITE" "$BOOTSTRAP_STAGE"
[[ "$RUN_STATUS" == 0 && "$RUN_REQUESTS" == "/charts/404.html"$'\n'"$MISSING" && "$RUN_OUTPUT" == *'404 page ok: /charts/404.html'* ]] \
    || fail "the bootstrap route check: $RUN_STATUS $RUN_REQUESTS $RUN_OUTPUT"
for case in noroute:1:'404 page failed: HTTP 404 for /charts/404.html' nomarker404:1:'404 page failed: no X-Allium-Origin: charts' \
    missingbody:1:"404 page failed: /charts/404.html is not the stage's charts/404.html" \
    robots404:1:'missing chart failed: production sends X-Robots-Tag' missing200:1:'missing chart failed: HTTP 200 instead of 404' \
    unavailable:75:'inconclusive: HTTP 503'; do
    IFS=: read -r modes expected message <<< "$case"
    ATTEMPTS=2 MODES="noindex $modes" run_verifier --route-bootstrap "$SITE" "$BOOTSTRAP_STAGE"
    [[ "$RUN_STATUS" == "$expected" && "$RUN_OUTPUT" == *"$message"* ]] || fail "bootstrap route check, '$modes': $RUN_STATUS $RUN_OUTPUT"
done
MODES=index run_verifier --route-bootstrap "$SITE" "$BOOTSTRAP_STAGE"
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"404 page failed: production sends X-Robots-Tag 'noindex'"* ]] || fail "the bootstrap route check accepted X-Robots-Tag: $RUN_OUTPUT"
run_verifier --route-bootstrap "$SITE" "$BOOTSTRAP_STAGE" "$OUT"
[[ "$RUN_STATUS" == 2 && -z "$RUN_REQUESTS" ]] || fail "the bootstrap route check accepted an output tree"
rm "$BOOTSTRAP_STAGE/charts/404.html"
run_verifier --route-bootstrap "$SITE" "$BOOTSTRAP_STAGE"
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'The stage has no charts/404.html'* && -z "$RUN_REQUESTS" ]] || fail "a bootstrap stage without its 404 page was accepted"
pass "the bootstrap route check needs production's /charts/404.html and a missing chart to get the stage's 404 page from the charts Worker, without X-Robots-Tag"

# The production redirect check: old chart URLs get a 302 to /charts/.
run_verifier --redirects "$SITE" "$NEXT_STAGE"
[[ "$RUN_STATUS" == 0 && "$RUN_REQUESTS" == $'/relay/FP01/bandwidth-1m.png\n/contact/c1/bandwidth-1y.png' ]] \
    || fail "the redirect check: $RUN_STATUS $RUN_REQUESTS $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *"redirect ok: $SITE/relay/FP01/bandwidth-1m.png -> /charts/relay/FP01/bandwidth-1m.png"* ]] \
    || fail "the redirect was not logged: $RUN_OUTPUT"
MODES=wrongredirect run_verifier --redirects "$SITE" "$STAGE"
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"redirects to '/elsewhere/relay/FP01/bandwidth-1m.png', not /charts/relay/FP01/bandwidth-1m.png"* ]] \
    || fail "a wrong redirect was accepted: $RUN_OUTPUT"
MODES=norouteredirect run_verifier --redirects "$SITE" "$STAGE"
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'redirect failed: HTTP 404 for /relay/FP01/bandwidth-1m.png'* && "$RUN_OUTPUT" == *'lacks the CHARTS_LAYOUT=charts _redirects'* ]] \
    || fail "a missing redirect was accepted: $RUN_OUTPUT"
run_verifier --redirects "$SITE" "$STAGE" "$OUT"
[[ "$RUN_STATUS" == 2 ]] || fail "a production check accepted an output tree"
pass "the redirect check needs old chart URLs to redirect to their /charts/ paths"
