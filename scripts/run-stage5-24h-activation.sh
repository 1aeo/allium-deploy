#!/usr/bin/env bash
# One-shot, pass-gated Stage 5 activation. This runner executes the read-only
# 24-hour audit, changes only R2 live-content cadence, forces and verifies one
# R2 sync, and observes the next normal deployment before recording evidence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${STAGE5_CONFIG_FILE:-$DEPLOY_DIR/config.env}"
AUDIT_SCRIPT="${STAGE5_AUDIT_SCRIPT:-$SCRIPT_DIR/run-stage4-24h-acceptance.sh}"
AUDIT_LOG="${STAGE5_AUDIT_LOG:-$DEPLOY_DIR/logs/cfassets-stage4-24h-acceptance.log}"
ACTIVATION_LOG="${STAGE5_ACTIVATION_LOG:-$DEPLOY_DIR/logs/cfassets-stage5-activation.log}"
FORCE_SYNC_LOG="${STAGE5_FORCE_SYNC_LOG:-$DEPLOY_DIR/logs/cfassets-stage5-force-sync.log}"
JOB_SUMMARY="${STAGE5_JOB_SUMMARY:-$DEPLOY_DIR/logs/cfassets-stage2-job-summary.tsv}"
UPDATE_LOG="${STAGE5_UPDATE_LOG:-$DEPLOY_DIR/logs/update.log}"
MARKER_FILE="${STAGE5_MARKER_FILE:-$DEPLOY_DIR/logs/last-r2-content-sync-date}"
EVIDENCE_FILE="${STAGE5_EVIDENCE_FILE:-$DEPLOY_DIR/docs/WORKERS_STATIC_ASSETS_STAGE5_ACTIVATION.md}"
LOCK_FILE="${STAGE5_LOCK_FILE:-/tmp/allium-deploy.lock}"
CHECKPOINT_UTC="${STAGE5_CHECKPOINT_UTC:-2026-07-29T02:56:35Z}"
STAGE4_STARTED_UTC="${STAGE5_STAGE4_STARTED_UTC:-2026-07-28T02:45:01Z}"
LOCK_WAIT_SECONDS="${STAGE5_LOCK_WAIT_SECONDS:-7200}"
JOB_WAIT_SECONDS="${STAGE5_JOB_WAIT_SECONDS:-7200}"
POLL_SECONDS="${STAGE5_POLL_SECONDS:-15}"
MIN_ACTIVATION_WINDOW_SECONDS="${STAGE5_MIN_ACTIVATION_WINDOW_SECONDS:-900}"
REUSE_AUDIT="${STAGE5_REUSE_AUDIT:-false}"

ROLLBACK_NEEDED=false
ACTIVATION_UTC=""
ORIGINAL_HEAD=""

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$ACTIVATION_LOG"
}

remove_one_shot_cron_entry() {
    local cron_tag="${STAGE5_ACTIVATION_CRON_TAG:-}"
    local cron_tmp

    [[ -n "$cron_tag" ]] || return 0
    cron_tmp=$(mktemp)
    if crontab -l 2>/dev/null | awk -v tag="$cron_tag" 'index($0, tag) == 0' > "$cron_tmp" &&
        crontab "$cron_tmp"; then
        log "Removed one-shot Stage 5 activation schedule"
    else
        log "WARNING: failed to remove one-shot Stage 5 activation schedule"
    fi
    rm -f "$cron_tmp"
}

config_interval() {
    awk -F= '$1 == "R2_CONTENT_SYNC_INTERVAL" { print substr($0, index($0, "=") + 1) }' \
        "$CONFIG_FILE"
}

file_mode() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

set_config_interval() {
    local expected="$1"
    local replacement="$2"
    local current count config_tmp

    count=$(grep -c '^R2_CONTENT_SYNC_INTERVAL=' "$CONFIG_FILE" || true)
    if [[ "$count" != 1 ]]; then
        log "ERROR: expected exactly one R2_CONTENT_SYNC_INTERVAL line; found $count"
        return 1
    fi
    current=$(config_interval)
    if [[ "$current" != "$expected" ]]; then
        log "ERROR: expected R2_CONTENT_SYNC_INTERVAL=$expected; found $current"
        return 1
    fi

    config_tmp=$(mktemp "${CONFIG_FILE}.stage5.XXXXXX")
    if ! awk -v replacement="$replacement" '
        /^R2_CONTENT_SYNC_INTERVAL=/ {
            print "R2_CONTENT_SYNC_INTERVAL=" replacement
            next
        }
        { print }
    ' "$CONFIG_FILE" > "$config_tmp"; then
        rm -f "$config_tmp"
        return 1
    fi
    chmod "$(file_mode "$CONFIG_FILE")" "$config_tmp"
    mv "$config_tmp" "$CONFIG_FILE"
    log "Set R2_CONTENT_SYNC_INTERVAL=$replacement"
}

rollback_if_needed() {
    local rollback_lock_fd

    [[ "$ROLLBACK_NEEDED" == true ]] || return 0
    log "Stage 5 verification did not complete; restoring every-build R2 cadence"
    exec {rollback_lock_fd}>"$LOCK_FILE"
    if flock -w 300 "$rollback_lock_fd"; then
        if [[ "$(config_interval 2>/dev/null || true)" == daily ]]; then
            set_config_interval daily every-build ||
                log "ERROR: automatic cadence rollback failed; manual repair required"
        fi
        flock -u "$rollback_lock_fd" || true
    else
        log "ERROR: could not acquire deployment lock for cadence rollback"
    fi
}

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    rollback_if_needed
    remove_one_shot_cron_entry
    exit "$status"
}

require_log_pattern() {
    local segment="$1"
    local pattern="$2"
    local label="$3"

    if grep -Fq "$pattern" <<< "$segment"; then
        log "Verified next job: $label"
    else
        log "ERROR: next job did not prove $label"
        return 1
    fi
}

verify_job_segment() {
    local segment="$1"

    require_log_pattern "$segment" \
        'Skipping R2 live content sync (already verified today:' \
        'only R2 live content was skipped' || return 1
    require_log_pattern "$segment" 'DO Spaces upload completed' \
        'DigitalOcean mirror completed' || return 1
    require_log_pattern "$segment" \
        'Workers Assets shadow upload and verification completed' \
        'Workers candidate upload and preview verification completed' || return 1
    require_log_pattern "$segment" 'Workers Assets promotion completed successfully' \
        'the verified Worker version was promoted' || return 1
    require_log_pattern "$segment" 'Purged ' \
        'the retained Pages rollback purge completed' || return 1
    require_log_pattern "$segment" 'Stage 2 job result: status=0' \
        'the whole scheduled job exited successfully' || return 1

    if grep -Fq 'R2 live content synchronization is due' <<< "$segment" ||
        grep -Fq 'Forcing R2 live content synchronization' <<< "$segment"; then
        log "ERROR: next job performed an unexpected R2 live-content sync"
        return 1
    fi
}

validate_existing_audit() {
    local audit_started audit_started_epoch checkpoint_epoch audit_mtime

    [[ -f "$AUDIT_LOG" ]] || { log "ERROR: scheduled audit log is missing"; return 1; }
    if grep -Fq 'not ok -' "$AUDIT_LOG" || ! grep -Fxq 'failures=0' "$AUDIT_LOG"; then
        log "ERROR: scheduled audit log is not a clean failures=0 result"
        return 1
    fi
    audit_started=$(awk -F= '$1 == "started_utc" { print $2; exit }' "$AUDIT_LOG")
    [[ -n "$audit_started" ]] || { log "ERROR: scheduled audit has no started_utc"; return 1; }
    audit_started_epoch=$(date -u -d "$audit_started" +%s)
    checkpoint_epoch=$(date -u -d "$CHECKPOINT_UTC" +%s)
    (( audit_started_epoch >= checkpoint_epoch )) || {
        log "ERROR: scheduled audit started before the formal checkpoint"
        return 1
    }
    audit_mtime=$(stat -c '%Y' "$AUDIT_LOG" 2>/dev/null || stat -f '%m' "$AUDIT_LOG")
    (( audit_mtime >= checkpoint_epoch )) || {
        log "ERROR: scheduled audit file predates the formal checkpoint"
        return 1
    }
    log "Accepted fresh passing scheduled audit from $audit_started"
}

seconds_until_next_allium_slot() {
    local now_epoch="$1"
    local next_slot

    # Allium starts at :15 and :45. Epoch time is hour-zone-independent, so
    # these slots are 900 seconds after each 1,800-second boundary.
    next_slot=$(( ((now_epoch - 900) / 1800 + 1) * 1800 + 900 ))
    printf '%s\n' "$((next_slot - now_epoch))"
}

acquire_safe_activation_window() {
    local lock_fd="$1"
    local wait_deadline now_epoch remaining wait_for_lock

    wait_deadline=$(( $(date +%s) + LOCK_WAIT_SECONDS ))
    while (( $(date +%s) < wait_deadline )); do
        wait_for_lock=$((wait_deadline - $(date +%s)))
        if ! flock -w "$wait_for_lock" "$lock_fd"; then
            break
        fi

        now_epoch=$(date +%s)
        remaining=$(seconds_until_next_allium_slot "$now_epoch")
        if (( remaining >= MIN_ACTIVATION_WINDOW_SECONDS )); then
            log "Acquired deployment lock with ${remaining}s before the next Allium slot"
            return 0
        fi

        log "Only ${remaining}s remain before the next Allium slot; waiting for that job to finish"
        flock -u "$lock_fd"
        sleep $((remaining + 5))
    done

    log "ERROR: no safe activation window appeared inside $LOCK_WAIT_SECONDS seconds"
    return 1
}

http_status() {
    curl --max-time 60 -sS -o /dev/null -w '%{http_code}' "$@"
}

verify_production() {
    local site_url="$1"
    local output_dir="$2"
    local root_status search_index_status search_status missing_status gptbot_status
    local local_root_hash live_root_hash local_search_hash live_search_hash

    root_status=$(http_status "$site_url/") || root_status=curl-failed
    search_index_status=$(http_status "$site_url/search-index.json") || search_index_status=curl-failed
    search_status=$(http_status "$site_url/search?q=DB1629B59707F744A0C7933E56B6802786FFC317") || search_status=curl-failed
    missing_status=$(http_status "$site_url/codex-stage5-post-activation-missing-check") || missing_status=curl-failed
    gptbot_status=$(http_status -A 'GPTBot/1.0' "$site_url/") || gptbot_status=curl-failed

    [[ "$root_status" == 200 ]] || { log "ERROR: production root status=$root_status"; return 1; }
    [[ "$search_index_status" == 200 ]] || { log "ERROR: production search-index status=$search_index_status"; return 1; }
    [[ "$search_status" == 302 ]] || { log "ERROR: production search status=$search_status"; return 1; }
    [[ "$missing_status" == 404 ]] || { log "ERROR: production missing status=$missing_status"; return 1; }
    [[ "$gptbot_status" == 200 ]] || { log "ERROR: GPTBot status=$gptbot_status"; return 1; }

    local_root_hash=$(sha256sum "$output_dir/index.html" | awk '{print $1}')
    live_root_hash=$(curl --max-time 60 -fsS "$site_url/" | sha256sum | awk '{print $1}')
    local_search_hash=$(sha256sum "$output_dir/search-index.json" | awk '{print $1}')
    live_search_hash=$(curl --max-time 60 -fsS "$site_url/search-index.json" | sha256sum | awk '{print $1}')
    [[ "$local_root_hash" == "$live_root_hash" ]] || { log "ERROR: production root hash mismatch"; return 1; }
    [[ "$local_search_hash" == "$live_search_hash" ]] || { log "ERROR: production search-index hash mismatch"; return 1; }
    log "Verified production status, GPTBot access, and representative hashes"
}

append_activation_evidence() {
    local verified_job_row="$1"
    local marker_value="$2"
    local audit_sha force_sha active_head evidence_tmp

    audit_sha=$(sha256sum "$AUDIT_LOG" | awk '{print $1}')
    force_sha=$(sha256sum "$FORCE_SYNC_LOG" | awk '{print $1}')
    active_head=$(git -C "$DEPLOY_DIR" rev-parse HEAD)
    evidence_tmp=$(mktemp "${EVIDENCE_FILE}.XXXXXX")
    cat > "$evidence_tmp" <<EOF
# Workers Static Assets Stage 5 activation result

**Activated UTC:** $ACTIVATION_UTC

**Status:** Passed. R2 live-content replication is daily. Workers Static
Assets remains production, DigitalOcean remains an every-build mirror, daily
backup behavior is unchanged, and Pages remains the current rollback target.

## Gated evidence

- The read-only 24-hour audit passed after the formal checkpoint with at least
  48 complete candidate, promotion, production, mirror, and backup checks.
- Audit log SHA-256: \`$audit_sha\`.
- Only \`R2_CONTENT_SYNC_INTERVAL\` changed, from \`every-build\` to \`daily\`.
- A forced R2 live sync completed count, byte, and representative-hash
  verification before writing the UTC marker \`$marker_value\`.
- Force-sync log SHA-256: \`$force_sha\`.
- The following normal cron job completed successfully after activation:

  \`$verified_job_row\`

- That job skipped only R2 live content. DO mirroring, Workers candidate
  upload and preview verification, exact-version promotion, the retained Pages
  rollback purge, and the whole-job success record all completed.
- Post-job production root, search index, search redirect, custom 404, GPTBot
  access, and representative hashes passed.
- No route, DNS, Pages, purge, backup, or retention setting changed.

## Rollback

Set \`R2_CONTENT_SYNC_INTERVAL=every-build\`, force and verify one R2 content
sync, and confirm the following normal job performs an every-build R2 sync.
No object or backup deletion is part of rollback.

**Activation runner checkout before evidence commit:** \`$active_head\`.
EOF
    chmod 644 "$evidence_tmp"
    mv "$evidence_tmp" "$EVIDENCE_FILE"
}

commit_evidence() {
    local evidence_lock_fd attempt

    exec {evidence_lock_fd}>"$LOCK_FILE"
    if ! flock -w 300 "$evidence_lock_fd"; then
        log "ERROR: could not acquire deployment lock to commit evidence"
        return 1
    fi

    git -C "$DEPLOY_DIR" fetch origin main
    if [[ -n "$(git -C "$DEPLOY_DIR" status --porcelain)" ]]; then
        log "ERROR: deployment checkout became dirty before evidence commit"
        flock -u "$evidence_lock_fd" || true
        return 1
    fi
    if [[ "$(git -C "$DEPLOY_DIR" rev-parse HEAD)" != "$(git -C "$DEPLOY_DIR" rev-parse origin/main)" ]]; then
        log "ERROR: deployment checkout is not aligned with origin/main"
        flock -u "$evidence_lock_fd" || true
        return 1
    fi

    append_activation_evidence "$VERIFIED_JOB_ROW" "$VERIFIED_MARKER"
    git -C "$DEPLOY_DIR" add -- docs/WORKERS_STATIC_ASSETS_STAGE5_ACTIVATION.md
    git -C "$DEPLOY_DIR" -c user.name=1aeo -c user.email=github@1aeo.com \
        commit -m 'docs: record stage5 daily R2 activation'

    for attempt in 1 2 3; do
        if git -C "$DEPLOY_DIR" push origin main; then
            log "Committed and pushed Stage 5 activation evidence as 1aeo"
            flock -u "$evidence_lock_fd" || true
            return 0
        fi
        log "WARNING: evidence push attempt $attempt failed"
        sleep $((attempt * 5))
    done

    log "ERROR: evidence commit exists locally but could not be pushed"
    flock -u "$evidence_lock_fd" || true
    return 1
}

if [[ "${STAGE5_ACTIVATION_TEST_MODE:-}" == 1 ]]; then
    # shellcheck disable=SC2317
    return 0 2>/dev/null || exit 0
fi

trap cleanup EXIT
mkdir -p "$(dirname "$ACTIVATION_LOG")"
: > "$ACTIVATION_LOG"
log "Starting pass-gated Stage 5 activation"

checkpoint_epoch=$(date -u -d "$CHECKPOINT_UTC" +%s)
if (( $(date +%s) < checkpoint_epoch )); then
    log "ERROR: checkpoint $CHECKPOINT_UTC has not arrived"
    exit 1
fi
[[ -f "$CONFIG_FILE" ]] || { log "ERROR: config.env is missing"; exit 1; }
[[ -r "$AUDIT_SCRIPT" ]] || { log "ERROR: acceptance audit is not readable"; exit 1; }
[[ "$(config_interval)" == every-build ]] || {
    log "ERROR: R2 cadence is not every-build before the acceptance audit"
    exit 1
}

if [[ "$REUSE_AUDIT" == true ]]; then
    log "Validating the completed scheduled 24-hour acceptance audit"
    validate_existing_audit
else
    log "Running the read-only 24-hour acceptance audit"
    if ! STAGE4_AUDIT_CRON_TAG='' /bin/bash "$AUDIT_SCRIPT" > "$AUDIT_LOG" 2>&1; then
        log "ERROR: 24-hour acceptance audit failed; cadence remains every-build"
        exit 1
    fi
    validate_existing_audit
fi
log "The read-only 24-hour acceptance audit passed"

ORIGINAL_HEAD=$(git -C "$DEPLOY_DIR" rev-parse HEAD)
git -C "$DEPLOY_DIR" fetch origin main
[[ -z "$(git -C "$DEPLOY_DIR" status --porcelain)" ]] || {
    log "ERROR: deployment checkout is dirty"
    exit 1
}
[[ "$ORIGINAL_HEAD" == "$(git -C "$DEPLOY_DIR" rev-parse origin/main)" ]] || {
    log "ERROR: deployment checkout is not aligned with origin/main"
    exit 1
}

# shellcheck disable=SC1090
source "$CONFIG_FILE"
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/metrics-output}"
SITE_URL="${SITE_URL:-https://metrics.1aeo.com}"
today_utc=$(date -u '+%Y-%m-%d')

exec {activation_lock_fd}>"$LOCK_FILE"
if ! acquire_safe_activation_window "$activation_lock_fd"; then
    exit 1
fi

git -C "$DEPLOY_DIR" fetch origin main
[[ -z "$(git -C "$DEPLOY_DIR" status --porcelain)" ]] || {
    log "ERROR: deployment checkout became dirty while waiting for activation"
    exit 1
}
[[ "$(git -C "$DEPLOY_DIR" rev-parse HEAD)" == "$(git -C "$DEPLOY_DIR" rev-parse origin/main)" ]] || {
    log "ERROR: deployment checkout changed or fell behind while waiting for activation"
    exit 1
}

set_config_interval every-build daily
ROLLBACK_NEEDED=true
ACTIVATION_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
log "Forcing one fully verified R2 live-content sync"
if ! "$SCRIPT_DIR/allium-deploy-upload-r2.sh" --force-content-sync "$OUTPUT_DIR" \
    > "$FORCE_SYNC_LOG" 2>&1; then
    log "ERROR: forced R2 live-content sync failed"
    exit 1
fi
marker_value=$(cat "$MARKER_FILE" 2>/dev/null || true)
if [[ "$marker_value" != "$today_utc" ]]; then
    log "ERROR: R2 daily marker is ${marker_value:-missing}; expected $today_utc"
    exit 1
fi
log "Forced R2 sync and UTC marker passed"

baseline_job_lines=$(wc -l < "$JOB_SUMMARY")
baseline_update_lines=$(wc -l < "$UPDATE_LOG")
flock -u "$activation_lock_fd"

log "Waiting for the next normal Allium cron job to complete"
deadline=$(( $(date +%s) + JOB_WAIT_SECONDS ))
VERIFIED_JOB_ROW=""
while (( $(date +%s) < deadline )); do
    current_job_lines=$(wc -l < "$JOB_SUMMARY")
    if (( current_job_lines > baseline_job_lines )); then
        VERIFIED_JOB_ROW=$(sed -n "$((baseline_job_lines + 1))p" "$JOB_SUMMARY")
        break
    fi
    sleep "$POLL_SECONDS"
done
if [[ -z "$VERIFIED_JOB_ROW" ]]; then
    log "ERROR: no completed normal cron job appeared inside $JOB_WAIT_SECONDS seconds"
    exit 1
fi

IFS=$'\t' read -r job_started job_finished job_status job_duration job_cadence job_counter \
    <<< "$VERIFIED_JOB_ROW"
log "Observed next job: start=$job_started finish=$job_finished duration=${job_duration}s counter=$job_counter"
if [[ "$job_status" != 0 || "$job_cadence" != true ]]; then
    log "ERROR: next cron job failed: $VERIFIED_JOB_ROW"
    exit 1
fi
next_job_segment=$(tail -n "+$((baseline_update_lines + 1))" "$UPDATE_LOG" |
    awk '{ print } /Stage 2 job result:/ { exit }')
verify_job_segment "$next_job_segment"

node "$SCRIPT_DIR/audit-cfassets-stage4.js" \
    --jobs "$DEPLOY_DIR/logs/cfassets-stage2-job-summary.tsv" \
    --shadow "$DEPLOY_DIR/logs/cfassets-shadow-summary.tsv" \
    --promotions "$DEPLOY_DIR/logs/cfassets-promotion-summary.tsv" \
    --started "$STAGE4_STARTED_UTC" \
    --minimum-jobs 48 \
    --minimum-elapsed-seconds 86400 \
    --require-complete >> "$ACTIVATION_LOG"

VERIFIED_MARKER=$(cat "$MARKER_FILE" 2>/dev/null || true)
[[ "$VERIFIED_MARKER" == "$today_utc" ]] || {
    log "ERROR: R2 marker changed after the next cron job"
    exit 1
}
[[ "$(config_interval)" == daily ]] || {
    log "ERROR: R2 cadence is not daily after the next cron job"
    exit 1
}
verify_production "$SITE_URL" "$OUTPUT_DIR"

# Operational activation is now proven. A later evidence-push failure must not
# roll back a healthy daily cadence; it is reported for manual Git recovery.
ROLLBACK_NEEDED=false
log "Stage 5 daily R2 cadence passed the following normal cron job"
commit_evidence
log "Stage 5 activation completed successfully"
