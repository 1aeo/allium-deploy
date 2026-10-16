#!/usr/bin/env bash
# allium-deploy-charts-route.sh against a fake Cloudflare API (a curl stub
# keeping the zone's routes in a file): status lists the routes; create adds
# exactly <host>/charts/* to the charts Worker beside the one site route and
# prints its ID; delete removes it, but never while CHARTS_LAYOUT=charts or
# the promoted layout is charts. The token never reaches a command line or
# the output. A copy of the script runs with a fake config.env.

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

command -v jq >/dev/null 2>&1 || fail "jq is required"

DEPLOY_DIR="$TMP_DIR/deploy"
MOCK_BIN="$TMP_DIR/bin"
ROUTES="$TMP_DIR/routes.json"
CALLS="$TMP_DIR/calls"
TOKEN='test-token-0123456789'
mkdir -p "$DEPLOY_DIR/scripts" "$DEPLOY_DIR/logs" "$MOCK_BIN" "$TMP_DIR/home/.config/cloudflare"
cp "$REPO_DIR/scripts/allium-deploy-charts-route.sh" "$DEPLOY_DIR/scripts/"
printf 'CLOUDFLARE_API_TOKEN=%s\n' "$TOKEN" > "$TMP_DIR/home/.config/cloudflare/workers_api_token"

# The fake API: one zone, example.org; GET, POST and DELETE on its Worker
# routes. Each call is recorded as "METHOD path auth=<ok|missing>" plus
# "argv-token" when the token was on the command line. MOCK_API_FAIL=1 makes
# every call fail as Cloudflare does; MOCK_POST_NOOP=1 makes a creation
# report success without adding the route.
cat > "$MOCK_BIN/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
config=$(cat)
auth=missing
[[ "$config" != "header = \"Authorization: Bearer $MOCK_TOKEN\"" ]] || auth=ok
leak=""
[[ "$*" != *"$MOCK_TOKEN"* ]] || leak=" argv-token"
method=GET
data=""
url=""
while (( $# )); do
    case "$1" in
        --request) method="$2"; shift ;;
        --data) data="$2"; shift ;;
        https://*) url="$1" ;;
    esac
    shift
done
path="${url#https://api.cloudflare.com/client/v4}"
printf '%s %s auth=%s%s\n' "$method" "$path" "$auth" "$leak" >> "$MOCK_CALLS"
if [[ "${MOCK_API_FAIL:-}" == 1 ]]; then
    printf '{"success":false,"errors":[{"message":"Authentication error"}]}\n403'
    exit 0
fi
case "$method $path" in
    "GET /zones?name=example.org") body='{"success":true,"result":[{"id":"zone-1","name":"example.org"}]}' ;;
    "GET /zones?name="*) body='{"success":true,"result":[]}' ;;
    "GET /zones/zone-1/workers/routes") body=$(jq -c '{success: true, result: .}' "$MOCK_ROUTES") ;;
    "POST /zones/zone-1/workers/routes")
        route=$(jq -c '. + {id: "route-new"}' <<< "$data")
        if [[ "${MOCK_POST_NOOP:-}" != 1 ]]; then
            jq -c --argjson route "$route" '. + [$route]' "$MOCK_ROUTES" > "$MOCK_ROUTES.tmp"
            mv "$MOCK_ROUTES.tmp" "$MOCK_ROUTES"
        fi
        body=$(jq -c '{success: true, result: .}' <<< "$route")
        ;;
    "DELETE /zones/zone-1/workers/routes/"*)
        jq -c --arg id "${path##*/}" 'map(select(.id != $id))' "$MOCK_ROUTES" > "$MOCK_ROUTES.tmp"
        mv "$MOCK_ROUTES.tmp" "$MOCK_ROUTES"
        body=$(jq -c --arg id "${path##*/}" '{success: true, result: {id: $id}}' <<< '{}')
        ;;
    *) body='{"success":false,"errors":[{"message":"not found"}]}'; printf '%s\n404' "$body"; exit 0 ;;
esac
printf '%s\n200' "$body"
EOF
chmod 0755 "$MOCK_BIN/curl"

SITE_ROUTE='{"id":"route-site","pattern":"metrics.example.org/*","script":"allium-main-test"}'
CHARTS_ROUTE_PATTERN='metrics.example.org/charts/*'

# write_config [extra lines...]
write_config() {
    {
        printf '%s\n' SITE_URL=https://metrics.example.org/ CF_CHARTS_WORKER_NAME=allium-charts-test
        printf '%s\n' "$@"
    } > "$DEPLOY_DIR/config.env"
}

# run_route <mode> [NAME=value...]: sets RUN_OUTPUT and RUN_STATUS.
run_route() {
    local mode="$1"
    shift
    : > "$CALLS"
    set +e
    RUN_OUTPUT=$(env -i HOME="$TMP_DIR/home" PATH="$MOCK_BIN:$PATH" MOCK_TOKEN="$TOKEN" \
        MOCK_CALLS="$CALLS" MOCK_ROUTES="$ROUTES" "$@" \
        "$DEPLOY_DIR/scripts/allium-deploy-charts-route.sh" "$mode" 2>&1)
    RUN_STATUS=$?
    set -e
    [[ "$RUN_OUTPUT" != *"$TOKEN"* ]] || fail "the token was printed by $mode"
    ! grep -q -e 'argv-token' -e 'auth=missing' "$CALLS" || fail "$mode sent the token on a command line or not at all: $(cat "$CALLS")"
}

calls() {
    grep -v '^GET /zones?name=' "$CALLS" | cut -d' ' -f1,2
}

write_config
printf '[%s]\n' "$SITE_ROUTE" > "$ROUTES"
run_route status
[[ "$RUN_STATUS" == 0 && "$RUN_OUTPUT" == *'route route-site metrics.example.org/* -> allium-main-test'* \
    && "$RUN_OUTPUT" == *'1 routes in the zone of metrics.example.org'* ]] || fail "status: $RUN_STATUS $RUN_OUTPUT"
[[ "$(grep '^GET /zones?name=' "$CALLS" | cut -d' ' -f2)" == $'/zones?name=metrics.example.org\n/zones?name=example.org' ]] \
    || fail "the zone was not found from the host's parent names: $(cat "$CALLS")"
pass "status lists the zone's routes, the zone found from SITE_URL's host"

run_route create
[[ "$RUN_STATUS" == 0 && "$RUN_OUTPUT" == *"created $CHARTS_ROUTE_PATTERN -> allium-charts-test"* && "$RUN_OUTPUT" == *$'\nROUTE_ID=route-new'* ]] \
    || fail "create: $RUN_STATUS $RUN_OUTPUT"
[[ "$(calls)" == $'GET /zones/zone-1/workers/routes\nPOST /zones/zone-1/workers/routes\nGET /zones/zone-1/workers/routes' ]] \
    || fail "unexpected create calls: $(calls)"
[[ "$(jq -c '.[1] | {pattern, script}' "$ROUTES")" == "{\"pattern\":\"$CHARTS_ROUTE_PATTERN\",\"script\":\"allium-charts-test\"}" ]] \
    || fail "the created route is not the charts route: $(cat "$ROUTES")"
run_route create
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'refusing create: expected exactly one route'*'found 2'* && "$(calls)" != *POST* ]] \
    || fail "a second create was not refused: $RUN_STATUS $RUN_OUTPUT"
printf '[]\n' > "$ROUTES"
run_route create
[[ "$RUN_STATUS" == 1 && "$(calls)" != *POST* ]] || fail "create without the site route was not refused"
printf '[%s]\n' "$SITE_ROUTE" > "$ROUTES"
run_route create MOCK_POST_NOOP=1
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'the zone does not hold exactly the site'*'check it'* && "$RUN_OUTPUT" != *ROUTE_ID=* ]] \
    || fail "a creation that did not add the route passed: $RUN_STATUS $RUN_OUTPUT"
printf '[{"id":"other","pattern":"%s","script":"allium-charts-test"}]\n' "$CHARTS_ROUTE_PATTERN" > "$ROUTES"
run_route create
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"$CHARTS_ROUTE_PATTERN already exists"* && "$(calls)" != *POST* ]] \
    || fail "create over an existing charts route was not refused: $RUN_OUTPUT"
pass "create adds only <host>/charts/* to the charts Worker beside exactly one route, checks two after, and prints the route ID"

charts_route=$(printf '{"id":"route-charts","pattern":"%s","script":"allium-charts-test"}' "$CHARTS_ROUTE_PATTERN")
printf '[%s,%s]\n' "$SITE_ROUTE" "$charts_route" > "$ROUTES"
for case in 'CHARTS_LAYOUT=charts|CHARTS_LAYOUT=charts: pages link to /charts/|' \
    "CHARTS_LAYOUT=beside|chart layout 'charts'|charts" \
    "CHARTS_LAYOUT=beside|chart layout 'garbage'|garbage"; do
    IFS='|' read -r setting expected marker <<< "$case"
    write_config "$setting"
    rm -f "$DEPLOY_DIR/logs/charts-layout-promoted"
    [[ -z "$marker" ]] || printf '%s\n' "$marker" > "$DEPLOY_DIR/logs/charts-layout-promoted"
    run_route delete
    [[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"refusing delete: "*"$expected"* && "$(calls)" != *DELETE* ]] \
        || fail "delete with $setting and marker '$marker' was not refused: $RUN_STATUS $RUN_OUTPUT"
done
[[ "$(jq length "$ROUTES")" == 2 ]] || fail "a refused delete changed the routes"
write_config CHARTS_LAYOUT=beside
printf 'beside\n' > "$DEPLOY_DIR/logs/charts-layout-promoted"
run_route delete
[[ "$RUN_STATUS" == 0 && "$RUN_OUTPUT" == *"deleted route-charts ($CHARTS_ROUTE_PATTERN)"* ]] || fail "delete: $RUN_STATUS $RUN_OUTPUT"
[[ "$(calls)" == $'GET /zones/zone-1/workers/routes\nDELETE /zones/zone-1/workers/routes/route-charts\nGET /zones/zone-1/workers/routes' ]] \
    || fail "unexpected delete calls: $(calls)"
[[ "$(jq -c 'map(.id)' "$ROUTES")" == '["route-site"]' ]] || fail "delete removed the wrong route: $(cat "$ROUTES")"
run_route delete
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'found 1 routes'* && "$(calls)" != *DELETE* ]] || fail "delete without a charts route was not refused"
printf '[%s,%s]\n' "$SITE_ROUTE" "${charts_route/allium-charts-test/another-worker}" > "$ROUTES"
run_route delete
[[ "$RUN_STATUS" == 1 && "$(calls)" != *DELETE* ]] || fail "a charts route to another Worker was deleted"
pass "delete removes only the charts route to the charts Worker, and never while the configured or the promoted layout is charts"

printf '[%s]\n' "$SITE_ROUTE" > "$ROUTES"
run_route status MOCK_API_FAIL=1
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'the Cloudflare API refused GET /zones?name=metrics.example.org (HTTP 403: Authentication error)'* ]] \
    || fail "an API refusal was not reported: $RUN_STATUS $RUN_OUTPUT"
for setting in SITE_URL=http://metrics.example.org 'CF_CHARTS_WORKER_NAME=Bad_Name'; do
    write_config "$setting"
    run_route create
    [[ "$RUN_STATUS" == 2 && ! -s "$CALLS" ]] || fail "'$setting' was accepted: $RUN_STATUS $RUN_OUTPUT"
done
write_config
rm "$TMP_DIR/home/.config/cloudflare/workers_api_token"
run_route status
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'CLOUDFLARE_API_TOKEN is not configured'* && ! -s "$CALLS" ]] || fail "a missing token was not refused"
run_route sideways
[[ "$RUN_STATUS" == 2 ]] || fail "an unknown mode was accepted"
pass "API refusals, bad settings, a missing token and an unknown mode stop the helper"
