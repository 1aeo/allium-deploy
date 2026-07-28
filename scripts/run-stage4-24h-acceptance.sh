#!/usr/bin/env bash
# Read-only Stage 4 24-hour acceptance audit. This script never changes the
# R2 cadence or any Cloudflare, DNS, Pages, backup, or retention setting.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

if [[ ! -f "$DEPLOY_DIR/config.env" ]]; then
    echo "not ok - config.env is missing" >&2
    exit 1
fi

# shellcheck disable=SC1091
source "$DEPLOY_DIR/config.env"

OUTPUT_DIR="${OUTPUT_DIR:-$HOME/metrics-output}"
SITE_URL="${SITE_URL:-https://metrics.1aeo.com}"
RCLONE="${RCLONE_PATH:-$HOME/bin/rclone}"
R2_BUCKET_NAME="${R2_BUCKET:?R2_BUCKET must be configured}"
DO_BUCKET_NAME="${DO_SPACES_BUCKET:?DO_SPACES_BUCKET must be configured}"
R2_REMOTE="r2-metrics:${R2_BUCKET_NAME}"
DO_REMOTE="spaces-metrics:${DO_BUCKET_NAME}"
VERIFY_PATHS="${R2_CONTENT_VERIFY_PATHS:-index.html,search-index.json,1aeo.com/index.html}"
EXPECTED_BACKUP_DATE="$(date '+%Y-%m-%d')"
FAILURES=0

remove_one_shot_cron_entry() {
    local cron_tag="${STAGE4_AUDIT_CRON_TAG:-}"
    local cron_tmp

    [[ -n "$cron_tag" ]] || return 0
    cron_tmp=$(mktemp)
    if crontab -l 2>/dev/null | awk -v tag="$cron_tag" 'index($0, tag) == 0' > "$cron_tmp" &&
        crontab "$cron_tmp"; then
        echo "schedule_cleanup=removed one-shot cron entry"
    else
        echo "schedule_cleanup=failed to remove one-shot cron entry" >&2
    fi
    rm -f "$cron_tmp"
    return 0
}

trap remove_one_shot_cron_entry EXIT

pass() {
    printf 'ok - %s\n' "$1"
}

fail() {
    printf 'not ok - %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
}

http_status() {
    curl --max-time 60 -sS -o /dev/null -w '%{http_code}' "$@"
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

sha256_url() {
    curl --max-time 60 -fsS "$1" | sha256sum | awk '{print $1}'
}

size_stats() {
    timeout 600 "$RCLONE" size "$1" --json --log-level ERROR \
        --exclude '_backups/**' --exclude '_headers' |
        jq -er '[.count, .bytes] | @tsv'
}

remote_sha256() {
    timeout 120 "$RCLONE" cat "$1" --log-level ERROR |
        sha256sum | awk '{print $1}'
}

printf 'Stage 4 24-hour acceptance audit\n'
printf 'started_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'host=%s\n' "$(hostname)"
printf 'checkout=%s\n' "$(git -C "$DEPLOY_DIR" rev-parse HEAD)"

if flock -n /tmp/allium-deploy.lock true; then
    pass "scheduled deployment output is idle and stable"
else
    fail "a scheduled deployment is active; mirror parity cannot be audited safely"
fi

if node "$SCRIPT_DIR/audit-cfassets-stage4.js" \
    --jobs "$DEPLOY_DIR/logs/cfassets-stage2-job-summary.tsv" \
    --shadow "$DEPLOY_DIR/logs/cfassets-shadow-summary.tsv" \
    --promotions "$DEPLOY_DIR/logs/cfassets-promotion-summary.tsv" \
    --started 2026-07-28T02:45:01Z \
    --minimum-jobs 48 \
    --minimum-elapsed-seconds 86400 \
    --require-complete; then
    pass "24-hour, 48-job candidate/promotion audit passed"
else
    fail "24-hour, 48-job candidate/promotion audit failed or is incomplete"
fi

if [[ "${R2_CONTENT_SYNC_INTERVAL:-every-build}" == "every-build" ]]; then
    pass "R2 remains every-build during the acceptance audit"
else
    fail "R2 cadence changed before acceptance (${R2_CONTENT_SYNC_INTERVAL:-unset})"
fi

root_status=$(http_status "$SITE_URL/") || root_status=curl-failed
search_index_status=$(http_status "$SITE_URL/search-index.json") || search_index_status=curl-failed
search_status=$(http_status "$SITE_URL/search?q=DB1629B59707F744A0C7933E56B6802786FFC317") || search_status=curl-failed
missing_status=$(http_status "$SITE_URL/codex-stage4-24h-missing-check") || missing_status=curl-failed
gptbot_status=$(http_status -A 'GPTBot/1.0' "$SITE_URL/") || gptbot_status=curl-failed

[[ "$root_status" == 200 ]] && pass "production root returns 200" || fail "production root status is $root_status"
[[ "$search_index_status" == 200 ]] && pass "production search index returns 200" || fail "production search index status is $search_index_status"
[[ "$search_status" == 302 ]] && pass "production search returns 302" || fail "production search status is $search_status"
[[ "$missing_status" == 404 ]] && pass "production missing probe returns 404" || fail "production missing probe status is $missing_status"
[[ "$gptbot_status" == 200 ]] && pass "GPTBot remains allowed" || fail "GPTBot status is $gptbot_status"

root_local_hash=$(sha256_file "$OUTPUT_DIR/index.html") || root_local_hash=local-read-failed
root_live_hash=$(sha256_url "$SITE_URL/") || root_live_hash=live-read-failed
search_local_hash=$(sha256_file "$OUTPUT_DIR/search-index.json") || search_local_hash=local-read-failed
search_live_hash=$(sha256_url "$SITE_URL/search-index.json") || search_live_hash=live-read-failed
[[ "$root_local_hash" == "$root_live_hash" ]] && pass "production root hash matches generated output" || fail "production root hash mismatch"
[[ "$search_local_hash" == "$search_live_hash" ]] && pass "production search-index hash matches generated output" || fail "production search-index hash mismatch"

root_headers=$(curl --max-time 60 -fsS -D - -o /dev/null "$SITE_URL/" | tr -d '\r') || root_headers=''
grep -qi '^cf-cache-status: HIT$' <<< "$root_headers" && pass "production root is a Cloudflare cache HIT" || fail "production root is not a Cloudflare cache HIT"
grep -qi '^cache-control: public, max-age=0, must-revalidate$' <<< "$root_headers" && pass "production root cache-control is correct" || fail "production root cache-control is incorrect"
grep -qi '^etag:' <<< "$root_headers" && pass "production root includes an ETag" || fail "production root has no ETag"
grep -qi '^cf-ray:' <<< "$root_headers" && pass "production root includes a CF-Ray" || fail "production root has no CF-Ray"
if grep -qiE '^(x-robots-tag|x-served-from):' <<< "$root_headers"; then
    fail "production root includes a legacy source or noindex header"
else
    pass "production root is indexable and has no legacy source header"
fi

if source_stats=$(size_stats "$OUTPUT_DIR") &&
    do_stats=$(size_stats "$DO_REMOTE") &&
    r2_stats=$(size_stats "$R2_REMOTE"); then
    printf 'mirror_stats source=%s do=%s r2=%s\n' "$source_stats" "$do_stats" "$r2_stats"
    [[ "$source_stats" == "$do_stats" ]] && pass "DO object count and bytes match generated output" || fail "DO object count or bytes differ"
    [[ "$source_stats" == "$r2_stats" ]] && pass "R2 object count and bytes match generated output" || fail "R2 object count or bytes differ"
else
    fail "could not measure generated, DO, and R2 object counts and bytes"
fi

IFS=',' read -r -a representative_paths <<< "$VERIFY_PATHS"
for representative_path in "${representative_paths[@]}"; do
    representative_path="${representative_path#"${representative_path%%[![:space:]]*}"}"
    representative_path="${representative_path%"${representative_path##*[![:space:]]}"}"
    local_hash=$(sha256_file "$OUTPUT_DIR/$representative_path") || local_hash=local-read-failed
    do_hash=$(remote_sha256 "$DO_REMOTE/$representative_path") || do_hash=do-read-failed
    r2_hash=$(remote_sha256 "$R2_REMOTE/$representative_path") || r2_hash=r2-read-failed
    [[ "$local_hash" == "$do_hash" ]] && pass "DO hash matches: $representative_path" || fail "DO hash mismatch: $representative_path"
    [[ "$local_hash" == "$r2_hash" ]] && pass "R2 hash matches: $representative_path" || fail "R2 hash mismatch: $representative_path"
done

for marker_spec in \
    "last-local-backup-date:local-from-R2 backup" \
    "last-r2-backup-date:R2 remote backup" \
    "last-do-local-backup-date:local-from-DO backup" \
    "last-do-backup-date:DO remote backup"; do
    marker_name=${marker_spec%%:*}
    marker_label=${marker_spec#*:}
    marker_value=$(cat "$DEPLOY_DIR/logs/$marker_name" 2>/dev/null || true)
    if [[ "$marker_value" == "$EXPECTED_BACKUP_DATE" ]]; then
        pass "$marker_label completed on $EXPECTED_BACKUP_DATE"
    else
        fail "$marker_label marker is ${marker_value:-missing}; expected $EXPECTED_BACKUP_DATE"
    fi
done

if purge_errors=$(awk -v start='[2026-07-27 19:45:01]' '
    /^\[20[0-9][0-9]-/ { active = substr($0, 1, 21) >= start }
    active && tolower($0) ~ /(http[^0-9]*405|purge[^:]*failed|failed[^:]*purge)/ { print; bad = 1 }
    END { exit bad }
' "$DEPLOY_DIR/logs/update.log"); then
    pass "no Pages purge 405 or purge failure occurred during Stage 4"
else
    fail "Pages purge errors occurred during Stage 4: $purge_errors"
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
if deployment_status=$(NO_COLOR=1 corepack pnpm exec wrangler deployments status \
    --config "$DEPLOY_DIR/wrangler.assets.toml" 2>&1) &&
    grep -Fq "(100%) $latest_version" <<< "$deployment_status"; then
    pass "Cloudflare serves the latest verified version at 100% ($latest_version)"
else
    fail "Cloudflare deployment does not show the latest verified version at 100%"
fi

printf 'manual_review=Cloudflare Workers invocation and current billing dashboard review remains required before activation\n'
printf 'finished_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'failures=%s\n' "$FAILURES"

(( FAILURES == 0 ))
