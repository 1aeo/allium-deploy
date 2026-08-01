#!/usr/bin/env bash
# Gated, reversible Stage 6 migration from a Worker route over a Pages CNAME to
# a Worker Custom Domain. --preflight is read-only. --execute refuses to mutate
# anything unless the clean-window audit, date gate, exact control-plane shape,
# checkout, confirmation, and API permissions all pass.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
MODE="${1:---preflight}"
case "$MODE" in
    --preflight|--execute) ;;
    *) echo "Usage: $0 [--preflight|--execute]" >&2; exit 2 ;;
esac

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    # shellcheck disable=SC1091
    source "$DEPLOY_DIR/config.env"
elif [[ "${STAGE6_TEST_MODE:-}" != "1" ]]; then
    echo "not ok - config.env is missing" >&2
    exit 1
fi

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

SITE_URL="${SITE_URL:-https://metrics.1aeo.com}"
SITE_HOST="${STAGE6_SITE_HOST:-${SITE_URL#https://}}"
SITE_HOST="${SITE_HOST%%/*}"
ZONE_NAME="${STAGE6_ZONE_NAME:-1aeo.com}"
WORKER_NAME="${CF_ASSETS_WORKER_NAME:-1aeo-metrics-assets-stage2}"
PAGES_PROJECT="${PAGES_PROJECT_NAME:-1aeo-metrics}"
PAGES_DIRECT_URL="${PAGES_PURGE_URL:-https://${PAGES_PROJECT}.pages.dev}"
EXPECTED_PAGES_CNAME="${STAGE6_EXPECTED_PAGES_CNAME:-${PAGES_PROJECT}.pages.dev}"
EXPECTED_ROUTE_PATTERN="${STAGE6_EXPECTED_ROUTE_PATTERN:-${SITE_HOST}/*}"
CONFIG_FILE="${STAGE6_CONFIG_FILE:-$DEPLOY_DIR/config.env}"
AUDIT_SCRIPT="${STAGE6_AUDIT_SCRIPT:-$SCRIPT_DIR/run-cfassets-remediation-audit.sh}"
STATE_DIR="${STAGE6_STATE_DIR:-$DEPLOY_DIR/logs}"
API_BASE="${STAGE6_API_BASE:-https://api.cloudflare.com/client/v4}"
CURL_BIN="${STAGE6_CURL_BIN:-curl}"
EARLIEST_UTC="${STAGE6_EARLIEST_UTC:-2026-08-04T02:56:35Z}"
HEALTH_PASSES="${STAGE6_HEALTH_PASSES:-3}"
HEALTH_ATTEMPTS="${STAGE6_HEALTH_ATTEMPTS:-12}"
HEALTH_RETRY_DELAY="${STAGE6_HEALTH_RETRY_DELAY:-10}"
LOCK_FILE="${STAGE6_LOCK_FILE:-/tmp/allium-deploy.lock}"

ACCOUNT_ID=""
ZONE_ID=""
DNS_RECORD_ID=""
ROUTE_ID=""
WORKER_DOMAIN_ID=""
SNAPSHOT_FILE=""
DNS_REMOVED=false
DOMAIN_ATTACHED=false
ROUTE_REMOVED=false

log() { printf '[Stage6] %s\n' "$1"; }
fail() { printf '[Stage6] not ok - %s\n' "$1" >&2; return 1; }

require_safe_inputs() {
    [[ "$SITE_URL" == "https://${SITE_HOST}" || "$SITE_URL" == "https://${SITE_HOST}/" ]] \
        || { fail "SITE_URL must be the HTTPS root for SITE_HOST"; return 1; }
    [[ "$SITE_HOST" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] \
        || { fail "invalid production hostname"; return 1; }
    [[ "$ZONE_NAME" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] \
        || { fail "invalid zone name"; return 1; }
    [[ "$WORKER_NAME" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] \
        || { fail "invalid Worker name"; return 1; }
    [[ "$PAGES_PROJECT" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] \
        || { fail "invalid Pages project name"; return 1; }
    [[ "$EXPECTED_PAGES_CNAME" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] \
        || { fail "invalid expected Pages CNAME"; return 1; }
    [[ "$EXPECTED_ROUTE_PATTERN" == "${SITE_HOST}/*" ]] \
        || { fail "route pattern must be exactly ${SITE_HOST}/*"; return 1; }
    [[ "$HEALTH_PASSES" =~ ^[1-9][0-9]*$ && "$HEALTH_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] \
        || { fail "health attempts and passes must be positive integers"; return 1; }
    (( HEALTH_PASSES <= HEALTH_ATTEMPTS )) \
        || { fail "health passes cannot exceed health attempts"; return 1; }
}

load_cloudflare_token() {
    local token_file pages_token_file
    if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
        for token_file in \
            "$HOME/.config/cloudflare/workers_api_token" \
            "$HOME/.config/cloudflare/api_token"; do
            if [[ -f "$token_file" ]]; then
                # shellcheck disable=SC1090
                source "$token_file"
                break
            fi
        done
    fi
    [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] \
        || fail "Cloudflare API token is unavailable"

    # Pages deployment has historically used its own least-privilege token.
    # Keep the broader Worker/DNS/route credential separate and select the
    # Pages token only for /pages/ API paths.
    if [[ -z "${CLOUDFLARE_PAGES_API_TOKEN:-}" ]]; then
        pages_token_file="$HOME/.config/cloudflare/api_token"
        if [[ -f "$pages_token_file" ]]; then
            CLOUDFLARE_PAGES_API_TOKEN=$(
                unset CLOUDFLARE_API_TOKEN
                # shellcheck disable=SC1090
                source "$pages_token_file"
                printf '%s' "${CLOUDFLARE_API_TOKEN:-}"
            )
        fi
    fi
    CLOUDFLARE_PAGES_API_TOKEN="${CLOUDFLARE_PAGES_API_TOKEN:-$CLOUDFLARE_API_TOKEN}"
    [[ -n "$CLOUDFLARE_PAGES_API_TOKEN" ]] \
        || fail "Cloudflare Pages API token is unavailable"
    export CLOUDFLARE_API_TOKEN CLOUDFLARE_PAGES_API_TOKEN
}

api_token_for_path() {
    local path="$1"
    if [[ "$path" == /accounts/*/pages/* ]]; then
        printf '%s' "$CLOUDFLARE_PAGES_API_TOKEN"
    else
        printf '%s' "$CLOUDFLARE_API_TOKEN"
    fi
}

cf_api() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    local response_file http_code authorization_token
    response_file=$(mktemp)
    authorization_token=$(api_token_for_path "$path")
    local args=(--max-time 60 -sS -o "$response_file" -w '%{http_code}'
        -X "$method" -H "Authorization: Bearer $authorization_token"
        -H 'Content-Type: application/json')
    if [[ -n "$body" ]]; then
        args+=(-d "$body")
    fi
    if ! http_code=$("$CURL_BIN" "${args[@]}" "${API_BASE}${path}"); then
        rm -f "$response_file"
        fail "Cloudflare API transport failed for $method $path"
        return 1
    fi
    if [[ "$http_code" != 2* ]] || ! jq -e '.success == true' "$response_file" >/dev/null 2>&1; then
        local message
        message=$(jq -r '[.errors[]?.message] | join("; ")' "$response_file" 2>/dev/null || true)
        rm -f "$response_file"
        fail "Cloudflare API rejected $method $path (HTTP $http_code${message:+: $message})"
        return 1
    fi
    cat "$response_file"
    rm -f "$response_file"
}

resolve_account_and_zone() {
    local accounts zones
    if [[ -n "${CLOUDFLARE_ACCOUNT_ID:-}" && "$CLOUDFLARE_ACCOUNT_ID" =~ ^[0-9a-f]{32}$ ]]; then
        ACCOUNT_ID="$CLOUDFLARE_ACCOUNT_ID"
    else
        accounts=$(cf_api GET '/accounts') || return 1
        ACCOUNT_ID=$(jq -er '.result | select(length == 1) | .[0].id' <<<"$accounts") \
            || { fail "token must expose exactly one Cloudflare account"; return 1; }
    fi
    zones=$(cf_api GET "/zones?name=${ZONE_NAME}") || return 1
    ZONE_ID=$(jq -er --arg zone "$ZONE_NAME" \
        '.result | map(select(.name == $zone)) | select(length == 1) | .[0].id' \
        <<<"$zones") || { fail "expected exactly one active $ZONE_NAME zone"; return 1; }
}

collect_control_plane() {
    local dns routes domains pages
    dns=$(cf_api GET "/zones/${ZONE_ID}/dns_records?name=${SITE_HOST}") || return 1
    routes=$(cf_api GET "/zones/${ZONE_ID}/workers/routes") || return 1
    domains=$(cf_api GET "/accounts/${ACCOUNT_ID}/workers/domains") || return 1
    pages=$(cf_api GET "/accounts/${ACCOUNT_ID}/pages/projects/${PAGES_PROJECT}/domains") \
        || { fail "Pages API access is required (Account / Cloudflare Pages / Edit)"; return 1; }

    CONTROL_PLANE=$(jq -n \
        --argjson dns "$(jq '.result' <<<"$dns")" \
        --argjson routes "$(jq '.result' <<<"$routes")" \
        --argjson domains "$(jq '.result' <<<"$domains")" \
        --argjson pages "$(jq '.result' <<<"$pages")" \
        '{dns:$dns,routes:$routes,worker_domains:$domains,pages_domains:$pages}')
}

validate_route_soak_state() {
    local dns_count route_count domain_count pages_count
    dns_count=$(jq --arg host "$SITE_HOST" --arg target "$EXPECTED_PAGES_CNAME" \
        '[.dns[] | select(.name == $host and .type == "CNAME" and .content == $target and .proxied == true)] | length' \
        <<<"$CONTROL_PLANE")
    route_count=$(jq --arg pattern "$EXPECTED_ROUTE_PATTERN" --arg worker "$WORKER_NAME" \
        '[.routes[] | select(.pattern == $pattern and .script == $worker)] | length' \
        <<<"$CONTROL_PLANE")
    domain_count=$(jq --arg host "$SITE_HOST" \
        '[.worker_domains[] | select(.hostname == $host)] | length' <<<"$CONTROL_PLANE")
    pages_count=$(jq --arg host "$SITE_HOST" \
        '[.pages_domains[] | select(.name == $host)] | length' <<<"$CONTROL_PLANE")

    [[ "$dns_count" == 1 ]] || { fail "expected one exact proxied Pages CNAME"; return 1; }
    [[ "$(jq --arg host "$SITE_HOST" '[.dns[] | select(.name == $host)] | length' <<<"$CONTROL_PLANE")" == 1 ]] \
        || { fail "unexpected additional production DNS record"; return 1; }
    [[ "$route_count" == 1 ]] || { fail "expected one exact production Worker route"; return 1; }
    [[ "$(jq '.routes | length' <<<"$CONTROL_PLANE")" == 1 ]] \
        || { fail "unexpected additional zone Worker route requires separate review"; return 1; }
    [[ "$domain_count" == 0 ]] || { fail "Worker Custom Domain already exists"; return 1; }
    [[ "$pages_count" == 1 ]] || { fail "expected Pages project to retain the production domain"; return 1; }

    DNS_RECORD_ID=$(jq -er --arg host "$SITE_HOST" --arg target "$EXPECTED_PAGES_CNAME" \
        '.dns[] | select(.name == $host and .type == "CNAME" and .content == $target) | .id' \
        <<<"$CONTROL_PLANE")
    ROUTE_ID=$(jq -er --arg pattern "$EXPECTED_ROUTE_PATTERN" --arg worker "$WORKER_NAME" \
        '.routes[] | select(.pattern == $pattern and .script == $worker) | .id' \
        <<<"$CONTROL_PLANE")
}

assert_checkout_ready() {
    local head origin dirty
    run_with_timeout 30 git -C "$DEPLOY_DIR" fetch --quiet origin main \
        || { fail "could not fetch origin/main"; return 1; }
    head=$(git -C "$DEPLOY_DIR" rev-parse HEAD)
    origin=$(git -C "$DEPLOY_DIR" rev-parse origin/main)
    dirty=$(git -C "$DEPLOY_DIR" status --porcelain --untracked-files=normal)
    [[ "$head" == "$origin" ]] || { fail "checkout does not match origin/main"; return 1; }
    [[ -z "$dirty" ]] || { fail "checkout has tracked or unignored changes"; return 1; }
}

date_gate_passes() {
    local now_epoch earliest_epoch
    now_epoch="${STAGE6_NOW_EPOCH:-$(date -u +%s)}"
    earliest_epoch="${STAGE6_EARLIEST_EPOCH:-$(date -u -d "$EARLIEST_UTC" +%s)}"
    [[ "$now_epoch" =~ ^[0-9]+$ && "$earliest_epoch" =~ ^[0-9]+$ ]] \
        || { fail "date gate epochs are invalid"; return 1; }
    (( now_epoch >= earliest_epoch )) \
        || { fail "seven-day boundary has not passed ($EARLIEST_UTC)"; return 1; }
}

run_acceptance_audit() {
    if ! CF_REMEDIATION_AUDIT_CALLER_HOLDS_LOCK="${1:-false}" \
        "$AUDIT_SCRIPT" --full; then
        fail "post-remediation smoke/24-hour acceptance audit did not pass"
        return 1
    fi
}

write_snapshot() {
    mkdir -p "$STATE_DIR"
    SNAPSHOT_FILE="$STATE_DIR/stage6-pre-cutover-$(date -u '+%Y%m%dT%H%M%SZ').json"
    local tmp="${SNAPSHOT_FILE}.tmp"
    jq -n \
        --arg captured_utc "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        --arg checkout "$(git -C "$DEPLOY_DIR" rev-parse HEAD)" \
        --arg account_id "$ACCOUNT_ID" --arg zone_id "$ZONE_ID" \
        --arg site_host "$SITE_HOST" --arg worker "$WORKER_NAME" \
        --arg pages_project "$PAGES_PROJECT" --arg pages_direct_url "$PAGES_DIRECT_URL" \
        --argjson control_plane "$CONTROL_PLANE" \
        '{captured_utc:$captured_utc,checkout:$checkout,account_id:$account_id,
          zone_id:$zone_id,site_host:$site_host,worker:$worker,
          pages_project:$pages_project,pages_direct_url:$pages_direct_url,
          control_plane:$control_plane}' > "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$SNAPSHOT_FILE"
    log "wrote pre-cutover snapshot: $SNAPSHOT_FILE"
}

assert_worker_domain_state() {
    local domains count
    domains=$(cf_api GET "/accounts/${ACCOUNT_ID}/workers/domains") || return 1
    count=$(jq --arg host "$SITE_HOST" --arg worker "$WORKER_NAME" --arg zone "$ZONE_ID" \
        '[.result[] | select(.hostname == $host and .service == $worker and .zone_id == $zone)] | length' \
        <<<"$domains")
    [[ "$count" == 1 ]] || { fail "exact Worker Custom Domain is not active in the API"; return 1; }
    WORKER_DOMAIN_ID=$(jq -er --arg host "$SITE_HOST" --arg worker "$WORKER_NAME" --arg zone "$ZONE_ID" \
        '.result[] | select(.hostname == $host and .service == $worker and .zone_id == $zone) | .id' \
        <<<"$domains")
}

assert_route_absent() {
    local routes count
    routes=$(cf_api GET "/zones/${ZONE_ID}/workers/routes") || return 1
    count=$(jq '.result | length' <<<"$routes")
    [[ "$count" == 0 ]] || { fail "a zone Worker route still exists"; return 1; }
}

restore_route() {
    local body
    body=$(jq -cn --arg pattern "$EXPECTED_ROUTE_PATTERN" --arg script "$WORKER_NAME" \
        '{pattern:$pattern,script:$script}')
    cf_api POST "/zones/${ZONE_ID}/workers/routes" "$body" >/dev/null
    ROUTE_REMOVED=false
    log "restored the exact production Worker route"
}

restore_pages_cname() {
    local body attempt
    body=$(jq -cn --arg type CNAME --arg name "$SITE_HOST" \
        --arg content "$EXPECTED_PAGES_CNAME" \
        '{type:$type,name:$name,content:$content,ttl:1,proxied:true}')
    for attempt in 1 2 3 4 5 6; do
        if cf_api POST "/zones/${ZONE_ID}/dns_records" "$body" >/dev/null; then
            DNS_REMOVED=false
            log "restored the exact proxied Pages CNAME"
            return 0
        fi
        (( attempt < 6 )) && sleep 5
    done
    fail "could not restore the exact proxied Pages CNAME"
}

rollback_after_failure() {
    local status=$?
    trap - ERR
    set +e
    if [[ "$ROUTE_REMOVED" == true ]]; then
        restore_route || log "URGENT: automatic route restoration failed"
    elif [[ "$DOMAIN_ATTACHED" == true && -n "$WORKER_DOMAIN_ID" ]]; then
        if cf_api DELETE "/accounts/${ACCOUNT_ID}/workers/domains/${WORKER_DOMAIN_ID}" >/dev/null; then
            DOMAIN_ATTACHED=false
            restore_pages_cname || log "URGENT: automatic Pages CNAME restoration failed"
        else
            log "URGENT: could not detach the incomplete Worker Custom Domain"
        fi
    elif [[ "$DNS_REMOVED" == true ]]; then
        restore_pages_cname || log "URGENT: automatic Pages CNAME restoration failed"
    fi
    log "cutover stopped with production route protection restored or retained; snapshot=$SNAPSHOT_FILE"
    return "$status"
}

repeat_locked_health_gate() {
    local attempt consecutive=0
    for ((attempt=1; attempt<=HEALTH_ATTEMPTS; attempt++)); do
        log "post-route-removal health attempt $attempt/$HEALTH_ATTEMPTS; consecutive=$consecutive/$HEALTH_PASSES"
        if assert_worker_domain_state && assert_route_absent && run_acceptance_audit true; then
            consecutive=$((consecutive + 1))
            if (( consecutive >= HEALTH_PASSES )); then
                return 0
            fi
        else
            consecutive=0
        fi
        (( attempt < HEALTH_ATTEMPTS )) && sleep "$HEALTH_RETRY_DELAY"
    done
    fail "Worker Custom Domain did not pass the bounded health gate"
}

wait_for_domain_continuity() {
    local attempt
    for ((attempt=1; attempt<=HEALTH_ATTEMPTS; attempt++)); do
        log "custom-domain continuity attempt $attempt/$HEALTH_ATTEMPTS"
        if assert_worker_domain_state && run_acceptance_audit true; then
            return 0
        fi
        (( attempt < HEALTH_ATTEMPTS )) && sleep "$HEALTH_RETRY_DELAY"
    done
    fail "Worker Custom Domain did not become healthy behind the protective route"
}

detach_pages_domain() {
    if cf_api DELETE "/accounts/${ACCOUNT_ID}/pages/projects/${PAGES_PROJECT}/domains/${SITE_HOST}" >/dev/null; then
        log "detached production hostname from the Pages project"
        return 0
    fi
    fail "could not detach the Pages custom domain"
}

set_pages_maintenance() {
    local expected="$1" replacement="$2" count tmp mode
    count=$(grep -Ec '^PAGES_ROLLBACK_MAINTENANCE_ENABLED=' "$CONFIG_FILE" || true)
    [[ "$count" == 1 ]] || { fail "expected exactly one Pages maintenance setting in config.env"; return 1; }
    grep -Fxq "PAGES_ROLLBACK_MAINTENANCE_ENABLED=${expected}" "$CONFIG_FILE" \
        || { fail "Pages maintenance setting is not ${expected}"; return 1; }
    tmp="${CONFIG_FILE}.stage6.tmp.$$"
    awk -v replacement="PAGES_ROLLBACK_MAINTENANCE_ENABLED=${replacement}" \
        '/^PAGES_ROLLBACK_MAINTENANCE_ENABLED=/{print replacement; next} {print}' \
        "$CONFIG_FILE" > "$tmp"
    mode=$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null || stat -f '%Lp' "$CONFIG_FILE")
    chmod "$mode" "$tmp"
    mv "$tmp" "$CONFIG_FILE"
    grep -Fxq "PAGES_ROLLBACK_MAINTENANCE_ENABLED=${replacement}" "$CONFIG_FILE"
}

validate_pages_maintenance_setting() {
    local count
    count=$(grep -Ec '^PAGES_ROLLBACK_MAINTENANCE_ENABLED=' "$CONFIG_FILE" || true)
    [[ "$count" == 1 ]] \
        || { fail "expected exactly one Pages maintenance setting in config.env"; return 1; }
    grep -Fxq 'PAGES_ROLLBACK_MAINTENANCE_ENABLED=true' "$CONFIG_FILE" \
        || { fail "Pages rollback maintenance must remain true before Stage 6"; return 1; }
}

preflight() {
    local failures=0
    require_safe_inputs || failures=$((failures + 1))
    load_cloudflare_token || failures=$((failures + 1))
    if (( failures == 0 )); then
        resolve_account_and_zone || failures=$((failures + 1))
    fi
    if (( failures == 0 )); then
        collect_control_plane || failures=$((failures + 1))
    fi
    if (( failures == 0 )); then
        validate_route_soak_state || failures=$((failures + 1))
    fi
    validate_pages_maintenance_setting || failures=$((failures + 1))
    assert_checkout_ready || failures=$((failures + 1))
    date_gate_passes || failures=$((failures + 1))
    run_acceptance_audit false || failures=$((failures + 1))
    if (( failures == 0 )); then
        log "ok - Stage 6 preflight passed without mutation"
        return 0
    fi
    fail "Stage 6 preflight has $failures blocking check(s)"
}

execute_cutover() {
    [[ "${STAGE6_CONFIRM_CUTOVER:-}" == "$SITE_HOST" ]] \
        || { fail "set STAGE6_CONFIRM_CUTOVER=$SITE_HOST for the reviewed live action"; return 1; }

    require_safe_inputs
    load_cloudflare_token
    assert_checkout_ready
    date_gate_passes

    exec 9>"$LOCK_FILE"
    flock -w 1800 9 || { fail "could not acquire deployment lock"; return 1; }
    run_acceptance_audit true
    resolve_account_and_zone
    collect_control_plane
    validate_route_soak_state
    validate_pages_maintenance_setting
    write_snapshot

    trap rollback_after_failure ERR

    cf_api DELETE "/zones/${ZONE_ID}/dns_records/${DNS_RECORD_ID}" >/dev/null
    DNS_REMOVED=true
    log "removed the exact Pages CNAME"

    local domain_body
    domain_body=$(jq -cn --arg hostname "$SITE_HOST" --arg service "$WORKER_NAME" \
        --arg zone_id "$ZONE_ID" --arg zone_name "$ZONE_NAME" \
        '{hostname:$hostname,service:$service,zone_id:$zone_id,zone_name:$zone_name}')
    local domain_response
    domain_response=$(cf_api PUT "/accounts/${ACCOUNT_ID}/workers/domains" "$domain_body")
    WORKER_DOMAIN_ID=$(jq -er '.result.id' <<<"$domain_response")
    DOMAIN_ATTACHED=true
    log "attached Worker Custom Domain while retaining the protective Worker route"

    # The broad route still has precedence here; this check proves continuity,
    # while the checks after route deletion prove the Custom Domain itself.
    wait_for_domain_continuity

    cf_api DELETE "/zones/${ZONE_ID}/workers/routes/${ROUTE_ID}" >/dev/null
    ROUTE_REMOVED=true
    assert_route_absent
    log "removed the now-redundant production Worker route"

    repeat_locked_health_gate
    detach_pages_domain
    run_acceptance_audit true
    set_pages_maintenance true false
    log "disabled Pages deployment and purge maintenance"

    # The desired external and runtime state is complete. A local evidence-file
    # error must be reported, but must not reintroduce the protective route.
    trap - ERR
    printf '%s\t%s\t%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        "$WORKER_DOMAIN_ID" "$WORKER_NAME" "$SNAPSHOT_FILE" \
        > "$STATE_DIR/stage6-worker-domain-active.tsv"
    chmod 600 "$STATE_DIR/stage6-worker-domain-active.tsv"
    flock -u 9
    log "ok - Stage 6 Worker Custom Domain cutover completed"
}

if [[ "${STAGE6_TEST_MODE:-}" == "1" ]]; then
    # shellcheck disable=SC2317
    return 0 2>/dev/null || exit 0
fi

case "$MODE" in
    --preflight) preflight ;;
    --execute) execute_cutover ;;
esac
