#!/usr/bin/env bash
# Read-only post-remediation smoke/acceptance audit. It never changes routes,
# DNS, deployment percentages, mirrors, backup cadence, retention, or Pages.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
MODE="${1:---smoke}"
case "$MODE" in
    --smoke|--full) ;;
    *) echo "Usage: $0 [--smoke|--full]" >&2; exit 2 ;;
esac

if [[ ! -f "$DEPLOY_DIR/config.env" ]]; then
    echo "not ok - config.env is missing" >&2
    exit 1
fi
# shellcheck disable=SC1091
source "$DEPLOY_DIR/config.env"
# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

START_FILE="${CF_REMEDIATION_START_FILE:-$DEPLOY_DIR/logs/cfassets-remediation-start-utc}"
STARTED_UTC=$(cat "$START_FILE" 2>/dev/null || true)
SITE_URL="${SITE_URL:-https://metrics.1aeo.com}"
PAGES_URL="${PAGES_PURGE_URL:-}"
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/metrics-output}"
RCLONE="${RCLONE_PATH:-$HOME/bin/rclone}"
DO_BUCKET_NAME="${DO_SPACES_BUCKET:?DO_SPACES_BUCKET must be configured}"
DO_REMOTE="spaces-metrics:${DO_BUCKET_NAME}"
FAILURES=0

remove_one_shot_cron_entry() {
    local cron_tag="${CF_REMEDIATION_AUDIT_CRON_TAG:-}"
    local cron_tmp

    [[ -n "$cron_tag" ]] || return 0
    cron_tmp=$(mktemp)
    if crontab -l 2>/dev/null | awk -v tag="$cron_tag" 'index($0, tag) == 0' > "$cron_tmp" &&
        crontab "$cron_tmp"; then
        printf 'schedule_cleanup=removed one-shot cron entry\n'
    else
        printf 'schedule_cleanup=failed to remove one-shot cron entry\n' >&2
    fi
    rm -f "$cron_tmp"
}
trap remove_one_shot_cron_entry EXIT

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
expect_equal() {
    local actual="$1"
    local expected="$2"
    local pass_message="$3"
    local fail_message="$4"
    if [[ "$actual" == "$expected" ]]; then
        pass "$pass_message"
    else
        fail "$fail_message (got $actual)"
    fi
}
http_status() { curl --max-time 60 -sS -o /dev/null -w '%{http_code}' "$@"; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
sha256_url() { curl --max-time 60 -fsS "$1" | sha256sum | awk '{print $1}'; }
remote_sha256() {
    timeout 120 "$RCLONE" cat "$1" --log-level ERROR | sha256sum | awk '{print $1}'
}

printf 'Workers Static Assets reliability remediation audit\n'
printf 'mode=%s\nstarted_utc=%s\naudit_utc=%s\ncheckout=%s\n' \
    "$MODE" "$STARTED_UTC" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    "$(git -C "$DEPLOY_DIR" rev-parse HEAD)"

if [[ ! "$STARTED_UTC" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    fail "remediation start marker is missing or malformed"
fi

audit_lock_owned=false
case "${CF_REMEDIATION_AUDIT_CALLER_HOLDS_LOCK:-false}" in
    true)
        pass "caller holds the deployment lock; output is stable"
        ;;
    false)
        exec {audit_lock_fd}>/tmp/allium-deploy.lock
        if flock -w "${CF_REMEDIATION_AUDIT_LOCK_WAIT_SECONDS:-1800}" "$audit_lock_fd"; then
            audit_lock_owned=true
            pass "scheduled deployment output is idle and stable"
        else
            fail "deployment lock did not become available"
        fi
        ;;
    *)
        fail "CF_REMEDIATION_AUDIT_CALLER_HOLDS_LOCK must be true or false"
        ;;
esac
smoke_report="$DEPLOY_DIR/logs/cfassets-remediation-smoke-report.json"
if node "$SCRIPT_DIR/audit-cfassets-soak.js" \
    --shadow "$DEPLOY_DIR/logs/cfassets-shadow-summary.tsv" \
    --jobs "$DEPLOY_DIR/logs/cfassets-stage2-job-summary.tsv" \
    --counter "$DEPLOY_DIR/logs/cfassets-shadow-consecutive-successes" \
    --target 10 --require-complete > "${smoke_report}.tmp"; then
    mv "${smoke_report}.tmp" "$smoke_report"
    cat "$smoke_report"
    pass "at least 10 consecutive post-fix jobs use immutable version previews"
else
    mv "${smoke_report}.tmp" "$smoke_report"
    cat "$smoke_report"
    fail "10-build immutable-preview smoke gate is incomplete or failed"
fi

if [[ "$MODE" == "--full" ]]; then
    full_report="$DEPLOY_DIR/logs/cfassets-remediation-24h-report.json"
    if node "$SCRIPT_DIR/audit-cfassets-stage4.js" \
        --jobs "$DEPLOY_DIR/logs/cfassets-stage2-job-summary.tsv" \
        --shadow "$DEPLOY_DIR/logs/cfassets-shadow-summary.tsv" \
        --promotions "$DEPLOY_DIR/logs/cfassets-promotion-summary.tsv" \
        --started "$STARTED_UTC" \
        --minimum-jobs 48 \
        --minimum-elapsed-seconds 86400 \
        --max-job-seconds 1800 \
        --require-complete > "${full_report}.tmp"; then
        mv "${full_report}.tmp" "$full_report"
        cat "$full_report"
        pass "24 clean hours, 48 jobs, and exact-version promotions passed"
    else
        mv "${full_report}.tmp" "$full_report"
        cat "$full_report"
        fail "24-hour no-failure/no-missed-slot gate is incomplete or failed"
    fi
fi

root_status=$(http_status "$SITE_URL/") || root_status=curl-failed
search_status=$(http_status "$SITE_URL/search?q=DB1629B59707F744A0C7933E56B6802786FFC317") || search_status=curl-failed
missing_status=$(http_status "$SITE_URL/__allium_remediation_missing__") || missing_status=curl-failed
gptbot_status=$(http_status -A 'GPTBot/1.0' "$SITE_URL/") || gptbot_status=curl-failed
expect_equal "$root_status" 200 "production root returns 200" "production root status is incorrect"
expect_equal "$search_status" 302 "production search returns 302" "production search status is incorrect"
expect_equal "$missing_status" 404 "production missing path returns 404" "production missing status is incorrect"
expect_equal "$gptbot_status" 200 "GPTBot remains allowed" "GPTBot status is incorrect"

local_root_hash=$(sha256_file "$OUTPUT_DIR/index.html") || local_root_hash=local-read-failed
live_root_hash=$(sha256_url "$SITE_URL/") || live_root_hash=live-read-failed
local_search_hash=$(sha256_file "$OUTPUT_DIR/search-index.json") || local_search_hash=local-read-failed
live_search_hash=$(sha256_url "$SITE_URL/search-index.json") || live_search_hash=live-read-failed
expect_equal "$live_root_hash" "$local_root_hash" "production root matches generated output" "production root hash mismatch"
expect_equal "$live_search_hash" "$local_search_hash" "production search index matches generated output" "production search-index hash mismatch"

do_root_hash=$(remote_sha256 "$DO_REMOTE/index.html") || do_root_hash=do-read-failed
do_search_hash=$(remote_sha256 "$DO_REMOTE/search-index.json") || do_search_hash=do-read-failed
expect_equal "$do_root_hash" "$local_root_hash" "DO hot mirror root is current" "DO hot mirror root hash mismatch"
expect_equal "$do_search_hash" "$local_search_hash" "DO hot mirror search index is current" "DO hot mirror search-index hash mismatch"

if [[ "$PAGES_URL" == https://* ]]; then
    pages_root_hash=$(sha256_url "${PAGES_URL%/}/") || pages_root_hash=pages-read-failed
    pages_search_hash=$(sha256_url "${PAGES_URL%/}/search-index.json") || pages_search_hash=pages-read-failed
    expect_equal "$pages_root_hash" "$local_root_hash" "Pages rollback root is current" "Pages rollback root hash mismatch"
    expect_equal "$pages_search_hash" "$local_search_hash" "Pages rollback search index is current" "Pages rollback search-index hash mismatch"
else
    fail "PAGES_PURGE_URL is not a direct HTTPS Pages rollback URL"
fi

if [[ "${R2_CONTENT_SYNC_INTERVAL:-every-build}" == daily ]]; then
    pass "R2 live replication remains daily"
else
    fail "R2 live replication interval is ${R2_CONTENT_SYNC_INTERVAL:-unset}"
fi
r2_marker=$(cat "$DEPLOY_DIR/logs/last-r2-content-sync-date" 2>/dev/null || true)
if [[ "$r2_marker" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    pass "R2 daily sync has a valid success marker ($r2_marker)"
else
    fail "R2 daily sync success marker is missing or malformed"
fi

latest_version=$(tail -n 1 "$DEPLOY_DIR/logs/cfassets-promotion-summary.tsv" | cut -f2)
for token_file in \
    "$HOME/.config/cloudflare/workers_api_token" \
    "$HOME/.config/cloudflare/api_token"; do
    if [[ -f "$token_file" ]]; then
        # shellcheck disable=SC1090
        source "$token_file"
        break
    fi
done
export CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
export CLOUDFLARE_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:-}"
# `deployments status --json` is emitted at Wrangler's normal log level. It is
# captured and parsed below; the single bounded diagnostic path still applies.
export WRANGLER_LOG=log
export WRANGLER_LOG_PATH="$DEPLOY_DIR/logs/wrangler-debug-sink.log"
export WRANGLER_LOG_SANITIZE=true
if ! prepare_null_log_sink "$WRANGLER_LOG_PATH"; then
    fail "could not prepare Wrangler's debug-log sink"
fi
if deployment_status=$(cd "$DEPLOY_DIR" && corepack pnpm exec wrangler deployments status \
    --json --config "$DEPLOY_DIR/wrangler.assets.toml" 2>/dev/null) &&
    jq -e --arg version "$latest_version" \
        '.versions | length == 1 and .[0].version_id == $version and .[0].percentage == 100' \
        <<< "$deployment_status" >/dev/null; then
    pass "latest verified version serves 100% of production"
else
    fail "Cloudflare production version does not match the latest promotion"
fi

if [[ "$audit_lock_owned" == true ]]; then
    flock -u "$audit_lock_fd" || true
fi
printf 'failures=%s\n' "$FAILURES"
(( FAILURES == 0 ))
