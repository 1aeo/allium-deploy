#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail_test() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

export STAGE6_TEST_MODE=1
export STAGE6_CONFIG_FILE="$TMP_DIR/config.env"
export STAGE6_STATE_DIR="$TMP_DIR/logs"
export SITE_URL=https://metrics.1aeo.com
export PAGES_PROJECT_NAME=1aeo-metrics
export PAGES_PURGE_URL=https://1aeo-metrics.pages.dev
export CF_ASSETS_WORKER_NAME=1aeo-metrics-assets-stage2

# shellcheck source=../scripts/run-stage6-worker-domain-cutover.sh
source "$ROOT_DIR/scripts/run-stage6-worker-domain-cutover.sh"

# shellcheck disable=SC2034
CLOUDFLARE_API_TOKEN=worker-token
# shellcheck disable=SC2034
CLOUDFLARE_PAGES_API_TOKEN=pages-token
[[ "$(api_token_for_path /zones/zone-id/workers/routes)" == worker-token ]] \
    || fail_test "zone route API did not select the Worker credential"
[[ "$(api_token_for_path /accounts/account-id/workers/domains)" == worker-token ]] \
    || fail_test "Worker domain API did not select the Worker credential"
[[ "$(api_token_for_path /accounts/account-id/pages/projects/project/domains)" == pages-token ]] \
    || fail_test "Pages API did not select the Pages credential"
pass "Stage 6 keeps Worker and Pages credentials least-privilege and path-scoped"

require_safe_inputs
original_site_url="$SITE_URL"
SITE_URL=http://metrics.1aeo.com
if require_safe_inputs >/dev/null 2>&1; then
    fail_test "an HTTP production URL passed the safe-input gate"
fi
SITE_URL="$original_site_url"
pass "Stage 6 accepts only the reviewed production hostname, route, and names"

# shellcheck disable=SC2034
STAGE6_EARLIEST_EPOCH=100
# shellcheck disable=SC2034
STAGE6_NOW_EPOCH=100
date_gate_passes
# shellcheck disable=SC2034
STAGE6_NOW_EPOCH=99
if date_gate_passes >/dev/null 2>&1; then
    fail_test "date gate allowed execution before the reviewed boundary"
fi
pass "Stage 6 date gate fails closed before the seven-day boundary"

cat > "$STAGE6_CONFIG_FILE" <<'EOF'
PAGES_ROLLBACK_MAINTENANCE_ENABLED=true
PURGE_SECRET=preserve-this-value
EOF
chmod 600 "$STAGE6_CONFIG_FILE"
validate_pages_maintenance_setting
set_pages_maintenance true false
grep -Fxq 'PAGES_ROLLBACK_MAINTENANCE_ENABLED=false' "$STAGE6_CONFIG_FILE"
grep -Fxq 'PURGE_SECRET=preserve-this-value' "$STAGE6_CONFIG_FILE"
mode=$(stat -c '%a' "$STAGE6_CONFIG_FILE" 2>/dev/null || stat -f '%Lp' "$STAGE6_CONFIG_FILE")
[[ "$mode" == 600 ]] || fail_test "config mode changed during the atomic edit"
if set_pages_maintenance true false >/dev/null 2>&1; then
    fail_test "stale expected config value was accepted"
fi
if validate_pages_maintenance_setting >/dev/null 2>&1; then
    fail_test "disabled Pages maintenance was accepted as pre-cutover state"
fi
pass "Pages maintenance activation is atomic, mode-preserving, and stale-safe"

cat > "$STAGE6_CONFIG_FILE" <<'EOF'
PAGES_ROLLBACK_MAINTENANCE_ENABLED=true
PAGES_ROLLBACK_MAINTENANCE_ENABLED=true
EOF
if set_pages_maintenance true false >/dev/null 2>&1; then
    fail_test "duplicate Pages maintenance settings were accepted"
fi
if validate_pages_maintenance_setting >/dev/null 2>&1; then
    fail_test "duplicate Pages maintenance settings passed preflight validation"
fi
pass "Pages maintenance activation rejects duplicate settings"

CONTROL_PLANE=$(cat <<'JSON'
{
  "dns": [
    {"id":"dns-id","type":"CNAME","name":"metrics.1aeo.com","content":"1aeo-metrics.pages.dev","proxied":true,"ttl":1}
  ],
  "routes": [
    {"id":"route-id","pattern":"metrics.1aeo.com/*","script":"1aeo-metrics-assets-stage2"}
  ],
  "worker_domains": [],
  "pages_domains": [
    {"name":"metrics.1aeo.com","status":"active"},
    {"name":"1aeo-metrics.pages.dev","status":"active"}
  ]
}
JSON
)
validate_route_soak_state
[[ "$DNS_RECORD_ID" == dns-id && "$ROUTE_ID" == route-id ]] \
    || fail_test "exact control-plane IDs were not selected"
pass "Stage 6 accepts the exact Worker-route-over-Pages starting state"

original_state="$CONTROL_PLANE"
CONTROL_PLANE=$(jq '.dns += [{"id":"extra","type":"A","name":"metrics.1aeo.com","content":"192.0.2.1","proxied":true}]' <<<"$original_state")
if validate_route_soak_state >/dev/null 2>&1; then
    fail_test "an additional production DNS record was accepted"
fi

CONTROL_PLANE=$(jq '.worker_domains += [{"id":"domain-id","hostname":"metrics.1aeo.com","service":"1aeo-metrics-assets-stage2"}]' <<<"$original_state")
if validate_route_soak_state >/dev/null 2>&1; then
    fail_test "an existing Worker Custom Domain was accepted as pre-cutover state"
fi

CONTROL_PLANE=$(jq '.routes[0].script = "wrong-worker"' <<<"$original_state")
if validate_route_soak_state >/dev/null 2>&1; then
    fail_test "a route to the wrong Worker was accepted"
fi

CONTROL_PLANE=$(jq '.routes += [{"id":"unrelated","pattern":"other.1aeo.com/*","script":"other-worker"}]' <<<"$original_state")
if validate_route_soak_state >/dev/null 2>&1; then
    fail_test "an unreviewed additional zone route was accepted"
fi
pass "Stage 6 rejects ambiguous DNS, existing domains, and unreviewed routes"

run_successful_execution_order_test() (
    events="$TMP_DIR/execute-events"
    : > "$events"
    mkdir -p "$STATE_DIR"
    cat > "$STAGE6_CONFIG_FILE" <<'EOF'
PAGES_ROLLBACK_MAINTENANCE_ENABLED=true
PURGE_SECRET=preserve-this-value
EOF
    chmod 600 "$STAGE6_CONFIG_FILE"

    # shellcheck disable=SC2034
    STAGE6_CONFIRM_CUTOVER=metrics.1aeo.com
    # shellcheck disable=SC2034
    LOCK_FILE="$TMP_DIR/deploy.lock"
    # shellcheck disable=SC2034
    HEALTH_PASSES=1
    # shellcheck disable=SC2034
    HEALTH_ATTEMPTS=1

    require_safe_inputs() { echo safe-inputs >> "$events"; }
    load_cloudflare_token() { echo token >> "$events"; }
    assert_checkout_ready() { echo checkout >> "$events"; }
    date_gate_passes() { echo date-gate >> "$events"; }
    flock() { return 0; }
    run_acceptance_audit() { echo "audit:$1" >> "$events"; }
    resolve_account_and_zone() {
        echo resolve >> "$events"
        # shellcheck disable=SC2034
        ACCOUNT_ID=account-id
        # shellcheck disable=SC2034
        ZONE_ID=zone-id
    }
    collect_control_plane() { echo collect >> "$events"; }
    validate_route_soak_state() {
        echo validate-start >> "$events"
        DNS_RECORD_ID=dns-id
        ROUTE_ID=route-id
    }
    write_snapshot() {
        echo snapshot >> "$events"
        SNAPSHOT_FILE="$STATE_DIR/pre-cutover.json"
        printf '{}\n' > "$SNAPSHOT_FILE"
    }
    cf_api() {
        echo "$1 $2" >> "$events"
        if [[ "$1 $2" == "PUT /accounts/account-id/workers/domains" ]]; then
            printf '{"success":true,"result":{"id":"domain-id"}}\n'
        fi
    }
    assert_worker_domain_state() {
        echo domain-state >> "$events"
        # shellcheck disable=SC2034
        WORKER_DOMAIN_ID=domain-id
    }
    assert_route_absent() { echo route-absent >> "$events"; }

    execute_cutover >/dev/null
    grep -Fxq 'PAGES_ROLLBACK_MAINTENANCE_ENABLED=false' "$STAGE6_CONFIG_FILE"
    grep -Fxq 'PURGE_SECRET=preserve-this-value' "$STAGE6_CONFIG_FILE"
    [[ -s "$STATE_DIR/stage6-worker-domain-active.tsv" ]]

    expected=$(cat <<'EOF'
safe-inputs
token
checkout
date-gate
audit:true
resolve
collect
validate-start
snapshot
DELETE /zones/zone-id/dns_records/dns-id
PUT /accounts/account-id/workers/domains
domain-state
audit:true
DELETE /zones/zone-id/workers/routes/route-id
route-absent
domain-state
route-absent
audit:true
DELETE /accounts/account-id/pages/projects/1aeo-metrics/domains/metrics.1aeo.com
audit:true
EOF
)
    [[ "$(cat "$events")" == "$expected" ]] \
        || fail_test "Stage 6 execution order differed from the reviewed sequence"
)
run_successful_execution_order_test
pass "Stage 6 executes the reviewed control-plane order before disabling Pages maintenance"

run_rollback_tests() (
    rollback_events="$TMP_DIR/rollback-events"
    : > "$rollback_events"
    restore_route() {
        echo route-restored >> "$rollback_events"
        ROUTE_REMOVED=false
    }
    restore_pages_cname() {
        echo cname-restored >> "$rollback_events"
        DNS_REMOVED=false
    }
    cf_api() {
        echo "$1 $2" >> "$rollback_events"
        return 0
    }

    SNAPSHOT_FILE="$TMP_DIR/snapshot.json"
    ROUTE_REMOVED=true
    DOMAIN_ATTACHED=true
    # shellcheck disable=SC2034
    WORKER_DOMAIN_ID=domain-id
    set +e
    false
    rollback_after_failure >/dev/null
    status=$?
    set -e
    [[ "$status" == 1 ]] || fail_test "route-removal rollback hid the triggering failure"
    grep -Fxq route-restored "$rollback_events" \
        || fail_test "route-removal failure did not restore the route"

    : > "$rollback_events"
    # shellcheck disable=SC2034
    ROUTE_REMOVED=false
    # shellcheck disable=SC2034
    DOMAIN_ATTACHED=false
    # shellcheck disable=SC2034
    DNS_REMOVED=true
    set +e
    false
    rollback_after_failure >/dev/null
    status=$?
    set -e
    [[ "$status" == 1 ]] || fail_test "pre-attach rollback hid the triggering failure"
    grep -Fxq cname-restored "$rollback_events" \
        || fail_test "pre-attach failure did not restore the Pages CNAME"
)
run_rollback_tests
pass "Stage 6 restores the protective route or Pages CNAME on bounded failure paths"

echo "stage6 cutover helper tests passed"
