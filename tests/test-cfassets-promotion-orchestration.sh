#!/usr/bin/env bash

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

MOCK_PROMOTER="$TMP_DIR/promote"
MOCK_CALLS="$TMP_DIR/calls"
# The quoted lines are the literal body of the generated mock executable.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\\n" "$@" >> "$MOCK_PROMOTION_CALLS"' \
    'exit "${MOCK_PROMOTION_EXIT:-0}"' \
    > "$MOCK_PROMOTER"
chmod 0755 "$MOCK_PROMOTER"

export ALLIUM_DEPLOY_TEST_MODE=1
export CF_ASSETS_SCRIPT="$MOCK_PROMOTER"
export CF_ASSETS_ALLOW_PROMOTION=true
export CF_ASSETS_ENABLED=true
export CF_ASSETS_REQUIRED=true
export MOCK_PROMOTION_CALLS="$MOCK_CALLS"

# shellcheck source=../scripts/allium-deploy-update.sh
source "$ROOT_DIR/scripts/allium-deploy-update.sh"

set +e
promote_verified_cfassets_if_ready 17
status=$?
set -e
[[ "$status" -eq 17 ]] || fail "upload failure returned $status instead of 17"
[[ ! -e "$MOCK_CALLS" ]] || fail "upload failure invoked the promoter"
pass "upload or preview failure prevents promotion"

CF_ASSETS_ALLOW_PROMOTION=false
promote_verified_cfassets_if_ready 0
[[ ! -e "$MOCK_CALLS" ]] || fail "disabled promotion invoked the promoter"
pass "disabled promotion leaves a verified candidate unpromoted"

CF_ASSETS_ALLOW_PROMOTION=true
promote_verified_cfassets_if_ready 0
[[ "$(cat "$MOCK_CALLS")" == "--promote" ]] || fail "successful candidate used unexpected promoter arguments"
pass "successful verified candidate invokes the guarded promoter once"

: > "$MOCK_CALLS"
export MOCK_PROMOTION_EXIT=42
set +e
promote_verified_cfassets_if_ready 0
status=$?
set -e
[[ "$status" -eq 42 ]] || fail "promoter failure returned $status instead of 42"
[[ "$(cat "$MOCK_CALLS")" == "--promote" ]] || fail "failed promoter invocation was not recorded exactly once"
pass "promotion failure propagates without a retry or fallback deployment"

set +e
assert_boolean_setting CF_ASSETS_ALLOW_PROMOTION yes >/dev/null
status=$?
set -e
[[ "$status" -eq 2 ]] || fail "invalid orchestrator boolean returned $status instead of 2"
pass "orchestrator feature gates accept only explicit true or false"

set +e
assert_boolean_setting PAGES_ROLLBACK_MAINTENANCE_ENABLED yes >/dev/null
status=$?
set -e
[[ "$status" -eq 2 ]] || fail "invalid Pages rollback maintenance boolean returned $status instead of 2"
pass "Pages rollback maintenance accepts only explicit true or false"
