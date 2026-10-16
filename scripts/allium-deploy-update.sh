#!/usr/bin/env bash
# Allium Deploy - Update Metrics
# Runs allium to generate site, uploads to configured storage backends, prunes old backups
# Cron: */30 * * * * /path/to/allium-deploy-update.sh >> /path/to/logs/update.log 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
UPDATE_STARTED_EPOCH="$(date +%s)"
UPDATE_STARTED_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

if [[ "${ALLIUM_DEPLOY_TEST_MODE:-}" == "1" ]]; then
    :
elif [[ -f "$DEPLOY_DIR/config.env" ]]; then
    source "$DEPLOY_DIR/config.env"
else
    echo "Error: config.env not found"
    exit 1
fi

ALLIUM_CONFIG_DIR="${ALLIUM_REPO_DIR:-${ALLIUM_DIR:-$HOME/allium}}"
ALLIUM_CONFIG_DIR="${ALLIUM_CONFIG_DIR%/}"
if [[ -d "$ALLIUM_CONFIG_DIR/.git" ]]; then
    ALLIUM_REPO_DIR="$ALLIUM_CONFIG_DIR"
elif [[ -d "$ALLIUM_CONFIG_DIR/../.git" ]]; then
    ALLIUM_REPO_DIR="$(cd "$ALLIUM_CONFIG_DIR/.." && pwd)"
else
    ALLIUM_REPO_DIR="$ALLIUM_CONFIG_DIR"
fi
if [[ -f "$ALLIUM_CONFIG_DIR/allium.py" ]]; then
    ALLIUM_DIR="$ALLIUM_CONFIG_DIR"
else
    ALLIUM_DIR="${ALLIUM_REPO_DIR%/}/allium"
fi
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/metrics-output}"
SITE_URL="${SITE_URL:-https://metrics.example.com}"
PAGES_PURGE_URL="${PAGES_PURGE_URL:-$SITE_URL}"
PAGES_ROLLBACK_MAINTENANCE_ENABLED="${PAGES_ROLLBACK_MAINTENANCE_ENABLED:-true}"
PAGES_BULK_PURGE_ENABLED="${PAGES_BULK_PURGE_ENABLED:-true}"
CONSECUTIVE_FAILURES_FILE="/tmp/allium-deploy-failures"

# Storage configuration
STORAGE_ORDER="${STORAGE_ORDER:-r2,do,failover}"
R2_ENABLED="${R2_ENABLED:-true}"
DO_ENABLED="${DO_ENABLED:-false}"
CF_ASSETS_ENABLED="${CF_ASSETS_ENABLED:-false}"
CF_ASSETS_REQUIRED="${CF_ASSETS_REQUIRED:-false}"
CF_ASSETS_ALLOW_PROMOTION="${CF_ASSETS_ALLOW_PROMOTION:-false}"
CF_ASSETS_REQUIRE_FRESH_CHECKOUT="${CF_ASSETS_REQUIRE_FRESH_CHECKOUT:-true}"
CF_ASSETS_SCRIPT="${CF_ASSETS_SCRIPT:-$SCRIPT_DIR/allium-deploy-cfassets.sh}"
CF_ASSETS_CONSECUTIVE_FILE="${CF_ASSETS_CONSECUTIVE_FILE:-$DEPLOY_DIR/logs/cfassets-shadow-consecutive-successes}"
CF_ASSETS_JOB_SUMMARY_FILE="${CF_ASSETS_JOB_SUMMARY_FILE:-$DEPLOY_DIR/logs/cfassets-stage2-job-summary.tsv}"
CF_ASSETS_MAX_JOB_SECONDS="${CF_ASSETS_MAX_JOB_SECONDS:-1800}"
CF_ASSETS_TOOLCHAIN_AUTO_SYNC="${CF_ASSETS_TOOLCHAIN_AUTO_SYNC:-true}"
CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT="${CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT:-180}"
CF_ASSETS_TOOLCHAIN_RETRY_SECONDS="${CF_ASSETS_TOOLCHAIN_RETRY_SECONDS:-3600}"
CF_ASSETS_TOOLCHAIN_SYNC_SCRIPT="${CF_ASSETS_TOOLCHAIN_SYNC_SCRIPT:-$SCRIPT_DIR/allium-deploy-sync-toolchain.sh}"
# The main Worker's verified version and promotion rows, as in
# allium-deploy-cfassets.sh: a promotion withheld here is recorded there too,
# and the withheld version is removed from the version file.
CF_ASSETS_LAST_VERSION_FILE="${CF_ASSETS_LAST_VERSION_FILE:-$DEPLOY_DIR/logs/cfassets-last-version}"
CF_ASSETS_PROMOTION_SUMMARY_FILE="${CF_ASSETS_PROMOTION_SUMMARY_FILE:-$DEPLOY_DIR/logs/cfassets-promotion-summary.tsv}"
# beside: chart PNGs next to their relay and contact pages, served by the main
# Worker. charts: below charts/, served by the charts-only Worker of
# allium-deploy-cfcharts.sh on the zone route <host>/charts/*.
CHARTS_LAYOUT="${CHARTS_LAYOUT:-beside}"
CF_CHARTS_WORKER_NAME="${CF_CHARTS_WORKER_NAME:-}"
CF_CHARTS_SCRIPT="${CF_CHARTS_SCRIPT:-$SCRIPT_DIR/allium-deploy-cfcharts.sh}"
# The chart layout of the last main Worker version this job promoted: beside
# (also when the file is missing) or charts. A build whose CHARTS_LAYOUT
# differs is a transition build (see check_output_tree and
# main_may_follow_failed_charts).
CHARTS_LAYOUT_MARKER_FILE="${CHARTS_LAYOUT_MARKER_FILE:-$DEPLOY_DIR/logs/charts-layout-promoted}"
# The charts the promoted main Worker version's pages link (charts layout
# only); the charts Worker keeps them while that version is live.
CF_CHARTS_LIVE_LIST="${CF_CHARTS_LIVE_LIST:-$DEPLOY_DIR/logs/cfcharts-live-charts}"
# true: promote the main Worker although the charts Worker failed, in a build
# that keeps the promoted layout; the job then exits non-zero.
CF_CHARTS_ALLOW_STALE="${CF_CHARTS_ALLOW_STALE:-false}"
CF_CHARTS_TIMING_FILE="${CF_CHARTS_TIMING_FILE:-$DEPLOY_DIR/logs/cfcharts-job-timing.tsv}"
# true: run Allium with --no-charts, which drops every chart PNG from the
# tree, to stay below the per-version file limit in an emergency.
ALLIUM_NO_CHARTS="${ALLIUM_NO_CHARTS:-false}"
# A dead-man heartbeat: a healthchecks.io-style ping URL (see heartbeat).
# Unset, no ping is sent.
HEALTHCHECK_URL="${HEALTHCHECK_URL:-}"

# Keep human-readable deployment output and error-only Wrangler diagnostics
# bounded. Compact job/candidate/promotion TSV summaries are retained
# separately and are not affected by this rotation.
ALLIUM_UPDATE_LOG_FILE="${ALLIUM_UPDATE_LOG_FILE:-$DEPLOY_DIR/logs/update.log}"
ALLIUM_UPDATE_LOG_MAX_BYTES="${ALLIUM_UPDATE_LOG_MAX_BYTES:-33554432}"
ALLIUM_UPDATE_LOG_ARCHIVES="${ALLIUM_UPDATE_LOG_ARCHIVES:-3}"
WRANGLER_LOG="${WRANGLER_LOG:-error}"
WRANGLER_DEFAULT_LOG_PATH="$DEPLOY_DIR/logs/wrangler-debug-sink.log"
WRANGLER_LOG_PATH="${WRANGLER_LOG_PATH:-$WRANGLER_DEFAULT_LOG_PATH}"
WRANGLER_LOG_SANITIZE="${WRANGLER_LOG_SANITIZE:-true}"
WRANGLER_ERROR_LOG_MAX_BYTES="${WRANGLER_ERROR_LOG_MAX_BYTES:-8388608}"
WRANGLER_ERROR_LOG_ARCHIVES="${WRANGLER_ERROR_LOG_ARCHIVES:-2}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

assert_boolean_setting() {
    local name="$1"
    local value="$2"

    case "$value" in
        true|false) return 0 ;;
        *)
            log "invalid $name=$value; expected true or false"
            return 2
            ;;
    esac
}

assert_charts_layout() {
    case "$CHARTS_LAYOUT" in
        beside|charts) return 0 ;;
        *)
            log "invalid CHARTS_LAYOUT=$CHARTS_LAYOUT; expected beside or charts"
            return 2
            ;;
    esac
}

# The child scripts source config.env again. Hand them this job's layout and
# Workers settings, so that an edit to config.env while the job runs cannot mix
# two layouts in one job. CF_ASSETS_ALLOW_PROMOTION is not among them: each
# --promote reads it from config.env again, so that setting it to false stops
# the promotions of a job that is already running.
export_job_settings() {
    export CHARTS_LAYOUT ALLIUM_NO_CHARTS CF_CHARTS_WORKER_NAME CF_ASSETS_ENABLED
}

# Allium's arguments. CHARTS_LAYOUT=charts writes the charts below charts/ and
# asks for PNG charts, so that a broken PNG install fails the build instead of
# switching every chart to SVG, which that layout does not publish.
# ALLIUM_NO_CHARTS=true writes no chart at all.
set_allium_arguments() {
    ALLIUM_ARGS=(--out "$OUTPUT_DIR" --base-url "$SITE_URL" --progress)
    if [[ "$CHARTS_LAYOUT" == "charts" ]]; then
        ALLIUM_ARGS+=(--chart-layout charts --chart-format png)
    fi
    if [[ "$ALLIUM_NO_CHARTS" == "true" ]]; then
        ALLIUM_ARGS+=(--no-charts)
    fi
}

# heartbeat <suffix> [message]: ping HEALTHCHECK_URL followed by the suffix
# (/start when the job starts, nothing when it succeeds, /fail when it fails,
# /log for a warning), with the message as the body. The URL goes to curl on
# standard input, so it is neither printed nor on a command line. A failed
# ping never changes the job, and an endpoint that does not answer delays it
# by about ten seconds per ping at most.
heartbeat() {
    [[ -n "$HEALTHCHECK_URL" ]] || return 0
    printf 'url = "%s%s"\n' "$HEALTHCHECK_URL" "$1" |
        curl --config - --fail --silent --connect-timeout 5 --max-time 5 --retry 1 --retry-max-time 10 \
            --output /dev/null --data-raw "${2:-}" >/dev/null 2>&1 ||
        log "⚠️ Heartbeat ping ${1:-(success)} failed"
    return 0
}

check_heartbeat_url() {
    [[ -n "$HEALTHCHECK_URL" ]] || return 0
    if [[ "$HEALTHCHECK_URL" != https://?* || "$HEALTHCHECK_URL" == *[[:space:]\"\\]* ]]; then
        log "⚠️ HEALTHCHECK_URL is not an https:// URL; the heartbeat is off"
        HEALTHCHECK_URL=""
    fi
}

# Sets PROMOTED_LAYOUT from CHARTS_LAYOUT_MARKER_FILE and CHARTS_TRANSITION.
# An unreadable or unknown marker makes every build a transition build, the
# stricter case.
read_promoted_layout() {
    PROMOTED_LAYOUT=beside
    if [[ -e "$CHARTS_LAYOUT_MARKER_FILE" ]]; then
        PROMOTED_LAYOUT=$(cat "$CHARTS_LAYOUT_MARKER_FILE" 2>/dev/null) || PROMOTED_LAYOUT=""
        case "$PROMOTED_LAYOUT" in
            beside|charts) ;;
            *)
                log "⚠️ $CHARTS_LAYOUT_MARKER_FILE is unreadable or holds no layout; treating this build as a layout transition"
                PROMOTED_LAYOUT=unknown
                ;;
        esac
    fi
    CHARTS_TRANSITION=false
    if [[ "$CHARTS_LAYOUT" != "$PROMOTED_LAYOUT" ]]; then
        CHARTS_TRANSITION=true
        log "Chart layout transition build: CHARTS_LAYOUT=$CHARTS_LAYOUT, promoted main Worker layout $PROMOTED_LAYOUT"
    fi
}

# After a main Worker promotion: the promoted version's layout. A version
# without charts (ALLIUM_NO_CHARTS=true) says nothing about the layout.
record_promoted_layout() {
    [[ "$ALLIUM_NO_CHARTS" != "true" ]] || return 0
    if mkdir -p "$(dirname "$CHARTS_LAYOUT_MARKER_FILE")" &&
        printf '%s\n' "$CHARTS_LAYOUT" > "$CHARTS_LAYOUT_MARKER_FILE.tmp.$$" &&
        mv "$CHARTS_LAYOUT_MARKER_FILE.tmp.$$" "$CHARTS_LAYOUT_MARKER_FILE"; then
        if [[ "$PROMOTED_LAYOUT" != "$CHARTS_LAYOUT" ]]; then
            log "✅ The promoted main Worker version now has the chart layout $CHARTS_LAYOUT (was $PROMOTED_LAYOUT)"
        fi
    else
        rm -f "$CHARTS_LAYOUT_MARKER_FILE.tmp.$$"
        log "⚠️ Could not record the promoted chart layout in $CHARTS_LAYOUT_MARKER_FILE"
    fi
}

# After a main Worker promotion in the charts layout: the charts its pages
# link, so that later charts versions keep them until another main version is
# promoted (see keep_live_charts in allium-deploy-cfassets.sh). A beside
# version links none; a version without charts leaves the list as it is.
record_live_charts() {
    [[ "$ALLIUM_NO_CHARTS" != "true" ]] || return 0
    if [[ "$CHARTS_LAYOUT" != "charts" ]]; then
        rm -f -- "$CF_CHARTS_LIVE_LIST" || log "⚠️ Could not remove $CF_CHARTS_LIVE_LIST"
        return 0
    fi
    if mkdir -p "$(dirname "$CF_CHARTS_LIVE_LIST")" &&
        (cd "$OUTPUT_DIR" && find charts -type f -name '*.png' -print) | LC_ALL=C sort > "$CF_CHARTS_LIVE_LIST.tmp.$$" &&
        mv "$CF_CHARTS_LIVE_LIST.tmp.$$" "$CF_CHARTS_LIVE_LIST"; then
        return 0
    fi
    rm -f "$CF_CHARTS_LIVE_LIST.tmp.$$"
    log "⚠️ Could not record the live main Worker version's charts in $CF_CHARTS_LIVE_LIST"
}

# DO_RCLONE_FAST_LIST_SUBTREES syncs its subtrees one pass at a time, each
# deleting what the tree no longer has. A switch of layout moves every chart:
# with charts first, the new chart keys exist before the relay/ and contact/
# passes delete the old ones.
warn_do_subtree_order() {
    local first
    [[ "$CHARTS_LAYOUT" == "charts" && "$DO_ENABLED" == "true" && "${DO_RCLONE_FAST_LIST:-false}" != "true" ]] || return 0
    first="${DO_RCLONE_FAST_LIST_SUBTREES:-}"
    first="${first#"${first%%[![:space:],]*}"}"
    first="${first%%[ ,]*}"
    if [[ -n "$first" && "$first" != charts ]]; then
        log "⚠️ CHARTS_LAYOUT=charts: list charts first in DO_RCLONE_FAST_LIST_SUBTREES (it starts with $first), so that a switch of layout adds the new chart keys before deleting the old ones"
    fi
}

# allium.py lists --chart-layout among its options. Otherwise sets
# ALLIUM_LAYOUT_PROBLEM: the option is missing, or allium.py --help failed, with
# the last lines it printed (a Python traceback ends with the error).
allium_has_chart_layout() {
    local help status=0
    help=$(cd "$ALLIUM_DIR" && python3 allium.py --help 2>&1) || status=$?
    if (( status != 0 )); then
        ALLIUM_LAYOUT_PROBLEM="python3 allium.py --help failed (exit $status): $(tail -n 3 <<< "$help" | tr '\n' ' ')"
        return 1
    fi
    ALLIUM_LAYOUT_PROBLEM="it has no --chart-layout"
    [[ "$help" == *--chart-layout* ]]
}

# CHARTS_LAYOUT=charts: check what the layout needs before Allium rewrites the
# output tree and the storage mirrors move every chart. The charts Worker's
# settings must be valid, and Allium must have --chart-layout. An Allium
# pulled by this job without it is set back to the previous checkout for this
# build, so that a revert in Allium cannot stop every build; the heartbeat
# gets a warning, as Allium updates then stop reaching the site.
check_charts_layout_prerequisites() {
    local pulled
    [[ "$CHARTS_LAYOUT" == "charts" ]] || return 0
    if [[ "$CF_ASSETS_ENABLED" == "true" ]] && ! "$CF_CHARTS_SCRIPT" --check-config; then
        log "❌ CHARTS_LAYOUT=charts: the charts Worker's settings are invalid"
        JOB_FAILURE_CLASS=charts_config
        return 1
    fi
    allium_has_chart_layout && return 0
    if [[ -n "${ALLIUM_ROLLBACK_SHA:-}" ]]; then
        pulled=$(git -C "$ALLIUM_REPO_DIR" rev-parse HEAD 2>/dev/null) || pulled=unknown
        log "⚠️ The pulled Allium $pulled cannot build CHARTS_LAYOUT=charts ($ALLIUM_LAYOUT_PROBLEM); building with $ALLIUM_ROLLBACK_SHA"
        rollback_repo_to_sha "allium" "$ALLIUM_REPO_DIR" "$ALLIUM_ROLLBACK_SHA" || { JOB_FAILURE_CLASS=allium; return 1; }
        unset ALLIUM_ROLLBACK_SHA
        heartbeat /log "warn=allium_held sha=$pulled"
        allium_has_chart_layout && return 0
    fi
    log "❌ Allium cannot build CHARTS_LAYOUT=charts ($ALLIUM_LAYOUT_PROBLEM): restore an Allium that has --chart-layout, or set CHARTS_LAYOUT=beside"
    JOB_FAILURE_CLASS=allium
    return 1
}

promote_verified_cfassets_if_ready() {
    local upload_exit="${1:-1}"

    if [[ ! "$upload_exit" =~ ^[0-9]+$ ]] || (( upload_exit > 255 )); then
        log "invalid Workers Assets upload status: $upload_exit"
        return 2
    fi
    if (( upload_exit != 0 )); then
        return "$upload_exit"
    fi
    if [[ "$CF_ASSETS_ALLOW_PROMOTION" != "true" ]]; then
        return 0
    fi

    "$CF_ASSETS_SCRIPT" --promote
}

require_current_deploy_checkout() {
    log "Verifying allium-deploy checkout before schema-triggered deploy..."

    cd "$DEPLOY_DIR"
    if ! run_with_timeout 30 git fetch --quiet origin main; then
        log "refusing schema-triggered deploy: could not fetch origin/main"
        return 1
    fi

    local local_head origin_head dirty
    if ! local_head="$(git rev-parse HEAD)" || ! origin_head="$(git rev-parse origin/main)"; then
        log "refusing schema-triggered deploy: could not resolve checkout or origin/main"
        return 1
    fi

    if [[ "$local_head" != "$origin_head" ]]; then
        log "refusing schema-triggered deploy: checkout HEAD $local_head is not origin/main $origin_head"
        return 1
    fi

    dirty="$(git status --porcelain --untracked-files=normal)"
    if [[ -n "$dirty" ]]; then
        log "refusing schema-triggered deploy: working tree has tracked or unignored changes"
        printf '%s\n' "$dirty" | sed 's/^/[dirty] /' >&2
        return 1
    fi

    log "allium-deploy checkout is current and clean"
    return 0
}

# Redeploy the Pages project (including functions/search.js) after a
# search-index schema change. Gated only by Pages rollback maintenance.
deploy_pages_for_schema_change() {
    if [[ "$PAGES_ROLLBACK_MAINTENANCE_ENABLED" != "true" ]]; then
        log "ℹ️  Pages rollback maintenance disabled; skipping schema-triggered Pages deploy"
    elif ! require_current_deploy_checkout; then
        log "❌ search.js auto-deploy skipped - deploy checkout is not safe"
        log "❌ Update/clean $DEPLOY_DIR, then run: $DEPLOY_DIR/scripts/allium-deploy-cfpages.sh"
    elif "$DEPLOY_DIR/scripts/allium-deploy-cfpages.sh" >> "$DEPLOY_DIR/logs/cfpages-deploy.log" 2>&1; then
        log "✅ search.js auto-deployed successfully"
    else
        log "❌ search.js auto-deploy FAILED - manual deploy required!"
        log "❌ Run: $DEPLOY_DIR/scripts/allium-deploy-cfpages.sh"
    fi
}

get_failures() {
    cat "$CONSECUTIVE_FAILURES_FILE" 2>/dev/null || echo 0
}

increment_failures() {
    echo $(($(get_failures) + 1)) > "$CONSECUTIVE_FAILURES_FILE"
}

reset_failures() {
    echo 0 > "$CONSECUTIVE_FAILURES_FILE"
}

fetch_check_runs() {
    local repo="$1"
    local sha="$2"
    local url="https://api.github.com/repos/$repo/commits/$sha/check-runs?per_page=100"
    local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
    local header_file page next_url

    while [[ -n "$url" ]]; do
        header_file=$(mktemp)
        if [[ -n "$token" ]]; then
            if ! page=$(run_with_timeout 30 curl -fsSL -D "$header_file" \
                -H "Accept: application/vnd.github+json" \
                -H "X-GitHub-Api-Version: 2022-11-28" \
                -H "Authorization: Bearer $token" \
                "$url"); then
                rm -f "$header_file"
                return 1
            fi
        else
            if ! page=$(run_with_timeout 30 curl -fsSL -D "$header_file" \
                -H "Accept: application/vnd.github+json" \
                -H "X-GitHub-Api-Version: 2022-11-28" \
                "$url"); then
                rm -f "$header_file"
                return 1
            fi
        fi

        printf '%s\n' "$page"
        next_url=$(awk -F'[<>]' 'tolower($0) ~ /^link:/ {
            for (i = 2; i <= NF; i += 2) {
                if ($(i + 1) ~ /rel="next"/) {
                    print $i
                    exit
                }
            }
        }' "$header_file")
        rm -f "$header_file"
        url="$next_url"
    done
}

check_runs_are_green() {
    local repo="$1"
    local sha="$2"
    local label="$3"
    local payload total failing summary

    if ! command -v curl &>/dev/null; then
        log "Guarded auto-pull skipped for $label: curl is not installed"
        return 1
    fi

    if ! command -v jq &>/dev/null; then
        log "Guarded auto-pull skipped for $label: jq is not installed"
        return 1
    fi

    if ! payload=$(fetch_check_runs "$repo" "$sha" 2>/dev/null); then
        log "Guarded auto-pull skipped for $label@$sha: could not read GitHub check-runs"
        return 1
    fi

    total=$(jq -s -r '[.[].check_runs[]] | length' <<< "$payload" 2>/dev/null || echo 0)
    if (( total < 1 )); then
        log "Guarded auto-pull skipped for $label@$sha: no GitHub check-runs found"
        return 1
    fi

    failing=$(jq -s -r '[.[].check_runs[] | select(.status != "completed" or (.conclusion != "success" and .conclusion != "skipped"))] | length' <<< "$payload" 2>/dev/null || echo 1)
    if (( failing == 0 )); then
        return 0
    fi

    summary=$(jq -s -r '[
        .[].check_runs[]
        | select(.status != "completed" or (.conclusion != "success" and .conclusion != "skipped"))
        | "\(.name):\(.status)/\(.conclusion // "null")"
    ] | join(";")' <<< "$payload" 2>/dev/null || true)
    log "Guarded auto-pull skipped for $label@$sha: checks not all success or skipped (${summary:-unknown})"
    return 1
}

guarded_pull_repo() {
    local label="$1"
    local repo_dir="$2"
    local github_repo="$3"
    local branch="$4"
    local rollback_var="$5"
    local current_branch pre_sha remote_sha post_sha

    if [[ ! -d "$repo_dir/.git" ]]; then
        log "Guarded auto-pull skipped for $label: $repo_dir is not a git checkout"
        return 0
    fi

    if ! git -C "$repo_dir" diff --quiet || ! git -C "$repo_dir" diff --cached --quiet; then
        log "Guarded auto-pull skipped for $label: tracked working tree changes are present"
        return 0
    fi

    pre_sha=$(git -C "$repo_dir" rev-parse HEAD)

    if ! run_with_timeout 30 git -C "$repo_dir" fetch origin "$branch" >/dev/null 2>&1; then
        log "Guarded auto-pull skipped for $label@$pre_sha: git fetch origin $branch failed"
        return 0
    fi

    remote_sha=$(git -C "$repo_dir" rev-parse "origin/$branch")
    if [[ "$pre_sha" == "$remote_sha" ]]; then
        log "Guarded auto-pull: $label already current at $pre_sha"
        return 0
    fi

    if ! check_runs_are_green "$github_repo" "$remote_sha" "$label"; then
        return 0
    fi

    current_branch=$(git -C "$repo_dir" symbolic-ref --quiet --short HEAD 2>/dev/null || true)
    if [[ "$current_branch" != "$branch" ]]; then
        log "Guarded auto-pull skipped for $label: checkout is on ${current_branch:-detached HEAD}, expected $branch"
        return 0
    fi

    if ! git -C "$repo_dir" merge --ff-only "origin/$branch" >/dev/null 2>&1; then
        log "Guarded auto-pull skipped for $label: $pre_sha cannot fast-forward to $remote_sha"
        return 0
    fi

    post_sha=$(git -C "$repo_dir" rev-parse HEAD)
    printf -v "$rollback_var" '%s' "$pre_sha"
    export "${rollback_var?}"
    log "Guarded auto-pull: $label $pre_sha -> $post_sha"
}

guarded_pull_allium() {
    guarded_pull_repo "allium" "$ALLIUM_REPO_DIR" "1aeo/allium" "master" "ALLIUM_ROLLBACK_SHA"
}

guarded_pull_allium_deploy() {
    guarded_pull_repo "allium-deploy" "$DEPLOY_DIR" "1aeo/allium-deploy" "main" "ALLIUM_DEPLOY_ROLLBACK_SHA"
}

# A guarded auto-pull may change package.json/pnpm-lock.yaml. Install the pinned
# Wrangler before the Workers snapshot; the sync script restores the previous
# node_modules on failure, so a failed install keeps the last working toolchain.
sync_workers_toolchain() {
    if [[ "$CF_ASSETS_ENABLED" != "true" ]]; then
        return 0
    fi
    if [[ "$CF_ASSETS_TOOLCHAIN_AUTO_SYNC" != "true" ]]; then
        log "ℹ️  Workers toolchain auto-sync disabled"
        return 0
    fi

    if ! CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT="$CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT" \
        CF_ASSETS_TOOLCHAIN_RETRY_SECONDS="$CF_ASSETS_TOOLCHAIN_RETRY_SECONDS" \
        "$CF_ASSETS_TOOLCHAIN_SYNC_SCRIPT"; then
        log "⚠️ Workers toolchain sync failed; continuing with the previously installed toolchain"
    fi
    return 0
}

capture_cfassets_deploy_snapshot() {
    unset CF_ASSETS_EXPECTED_DEPLOY_SHA

    if [[ "$CF_ASSETS_ENABLED" != "true" || "$CF_ASSETS_REQUIRE_FRESH_CHECKOUT" != "true" ]]; then
        return 0
    fi

    local head_sha origin_sha dirty
    if ! run_with_timeout 30 git -C "$DEPLOY_DIR" fetch --quiet origin main; then
        log "refusing Workers snapshot: could not fetch origin/main"
        return 1
    fi
    if ! head_sha=$(git -C "$DEPLOY_DIR" rev-parse HEAD) ||
        ! origin_sha=$(git -C "$DEPLOY_DIR" rev-parse origin/main); then
        log "refusing Workers snapshot: could not resolve checkout or origin/main"
        return 1
    fi
    dirty=$(git -C "$DEPLOY_DIR" status --porcelain --untracked-files=normal)

    [[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || {
        log "refusing Workers snapshot: checkout HEAD is malformed"
        return 1
    }
    [[ "$head_sha" == "$origin_sha" ]] || {
        log "refusing Workers snapshot: checkout HEAD $head_sha does not match origin/main $origin_sha"
        return 1
    }
    [[ -z "$dirty" ]] || {
        log "refusing Workers snapshot: checkout has tracked or unignored changes"
        printf '%s\n' "$dirty" >&2
        return 1
    }

    CF_ASSETS_EXPECTED_DEPLOY_SHA="$head_sha"
    export CF_ASSETS_EXPECTED_DEPLOY_SHA
    log "Pinned Workers deployment snapshot at $CF_ASSETS_EXPECTED_DEPLOY_SHA"
}

rollback_repo_to_sha() {
    local label="$1"
    local repo_dir="$2"
    local sha="$3"

    if [[ -z "$sha" ]]; then
        return 0
    fi

    if git -C "$repo_dir" reset --hard "$sha" >/dev/null 2>&1; then
        log "Rolled back $label checkout to $sha"
    else
        log "Failed to roll back $label checkout to $sha"
        return 1
    fi
}

rollback_guarded_pulls() {
    local failed=false

    rollback_repo_to_sha "allium" "$ALLIUM_REPO_DIR" "${ALLIUM_ROLLBACK_SHA:-}" || failed=true
    rollback_repo_to_sha "allium-deploy" "$DEPLOY_DIR" "${ALLIUM_DEPLOY_ROLLBACK_SHA:-}" || failed=true

    if [[ "$failed" == "true" ]]; then
        return 1
    fi
}

# Record one bounded row per scheduled Stage 2 job. A failure anywhere in the
# generator/publisher/purge job, or a total runtime beyond the scheduler
# interval, breaks the consecutive-build streak even when the route-free
# Worker candidate itself happened to verify successfully.
record_stage2_job_result() {
    local status="$1"
    local started_epoch="$2"
    local started_utc="$3"
    local finished_epoch="${4:-$(date +%s)}"
    local finished_utc="${5:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"

    [[ "$CF_ASSETS_ENABLED" == "true" ]] || return 0

    local duration cadence_ok=true counter=0 counter_tmp
    duration=$((finished_epoch - started_epoch))
    if [[ ! "$CF_ASSETS_MAX_JOB_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
        log "⚠️ Invalid CF_ASSETS_MAX_JOB_SECONDS=$CF_ASSETS_MAX_JOB_SECONDS; using 1800"
        CF_ASSETS_MAX_JOB_SECONDS=1800
    fi

    if ((duration > CF_ASSETS_MAX_JOB_SECONDS)); then
        cadence_ok=false
    fi

    if [[ "$status" -ne 0 || "$cadence_ok" != "true" ]]; then
        mkdir -p "$(dirname "$CF_ASSETS_CONSECUTIVE_FILE")"
        counter_tmp="${CF_ASSETS_CONSECUTIVE_FILE}.tmp.$$"
        printf '0\n' > "$counter_tmp"
        mv "$counter_tmp" "$CF_ASSETS_CONSECUTIVE_FILE"
    fi

    counter=$(cat "$CF_ASSETS_CONSECUTIVE_FILE" 2>/dev/null || printf '0')
    [[ "$counter" =~ ^[0-9]+$ ]] || counter=0

    mkdir -p "$(dirname "$CF_ASSETS_JOB_SUMMARY_FILE")"
    if [[ ! -f "$CF_ASSETS_JOB_SUMMARY_FILE" ]]; then
        printf 'started_utc\tfinished_utc\texit_status\ttotal_duration_seconds\tcadence_ok\tshadow_counter\n' \
            > "$CF_ASSETS_JOB_SUMMARY_FILE"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$started_utc" "$finished_utc" "$status" "$duration" "$cadence_ok" "$counter" \
        >> "$CF_ASSETS_JOB_SUMMARY_FILE"

    log "Stage 2 job result: status=$status total=${duration}s cadence_ok=$cadence_ok shadow_counter=$counter"
}

# JOB_FAILURE_CLASS names the cause of a failure for the heartbeat: allium,
# setup, charts_config, local, storage, cap, main_prepare, main_upload,
# main_promote, charts_prepare, charts_upload, charts_promote,
# route_definitive, route_inconclusive or charts_stale. A Workers failure
# (WORKERS_FAILURE_CLASS) fails the heartbeat also when the job exits 0, as it
# does unless CF_ASSETS_REQUIRED=true: a withheld or failed promotion leaves
# the site on its last version.
record_update_exit() {
    local update_status="$1" class=""

    trap - EXIT
    set +e
    remove_publish_state
    record_stage2_job_result "$update_status" "$UPDATE_STARTED_EPOCH" "$UPDATE_STARTED_UTC"
    if [[ "$update_status" != 0 ]]; then
        class="${JOB_FAILURE_CLASS:-other}"
        log "Job failed: class=$class exit=$update_status"
    elif [[ -n "${WORKERS_FAILURE_CLASS:-}" ]]; then
        class="$WORKERS_FAILURE_CLASS"
        log "Workers failure: class=$class; the job exits 0 (CF_ASSETS_REQUIRED=false)"
    fi
    if [[ -n "$class" ]]; then
        heartbeat /fail "class=$class exit=$update_status"
    else
        heartbeat "" "ok"
    fi
    exit "$update_status"
}

# Run one publisher in the background and record when it finishes, so its
# logged duration is its own even when the job waits for it later. The finish
# time is best-effort: without it the duration falls back to the wait time, and
# it never changes the publisher's exit status.
start_publisher() {
    local name="$1"
    shift
    (
        trap - EXIT
        status=0
        "$@" || status=$?
        if [[ -n "$PUBLISH_STATE_DIR" ]]; then
            date +%s > "$PUBLISH_STATE_DIR/$name.finished" 2>/dev/null || true
        fi
        exit "$status"
    ) &
}

publisher_duration() {
    local finished="" seconds
    if [[ -n "$PUBLISH_STATE_DIR" ]]; then
        finished=$(cat "$PUBLISH_STATE_DIR/$1.finished" 2>/dev/null) || finished=""
    fi
    [[ "$finished" =~ ^[0-9]+$ ]] || finished=$(date +%s)
    seconds=$((finished - UPLOAD_START))
    printf '%dm%02ds' $((seconds / 60)) $((seconds % 60))
}

# failure_class <class> <exit status>: cap for exit status 4, the file-count
# guard of allium-deploy-cfassets.sh (in --generate-only and --upload-only),
# otherwise the class.
failure_class() {
    if [[ "$2" == 4 ]]; then
        printf 'cap\n'
    else
        printf '%s\n' "$1"
    fi
}

# CHARTS_LAYOUT=charts: wait for the charts Worker's upload and verification,
# promote it, then check that production serves that version under /charts/,
# all before the main Worker, whose pages link there, is promoted. Sets
# CF_CHARTS_EXIT and, on a failure, CHARTS_FAILURE_CLASS.
publish_charts_worker() {
    wait "$1" || CF_CHARTS_EXIT=$?
    CF_CHARTS_TIME=$(publisher_duration cfcharts)
    if [[ "$CF_CHARTS_EXIT" != "0" ]]; then
        log "⚠️ Charts Worker upload failed (exit $CF_CHARTS_EXIT, $CF_CHARTS_TIME)"
        CHARTS_FAILURE_CLASS=$(failure_class charts_upload "$CF_CHARTS_EXIT")
        return 0
    fi
    log "✅ Charts Worker upload and verification completed ($CF_CHARTS_TIME)"
    if [[ "$CF_ASSETS_ALLOW_PROMOTION" != "true" ]]; then
        return 0
    fi

    log "🚀 Promoting verified charts Worker version..."
    if "$CF_CHARTS_SCRIPT" --promote; then
        CHARTS_PROMOTED_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
        log "✅ Charts Worker promotion completed successfully"
    else
        CF_CHARTS_EXIT=$?
        CHARTS_FAILURE_CLASS=charts_promote
        log "❌ Charts Worker promotion failed (exit $CF_CHARTS_EXIT)"
        return 0
    fi
    log "🔎 Checking that $SITE_URL/charts/ serves the promoted charts..."
    if "$CF_CHARTS_SCRIPT" --check-route; then
        log "✅ The /charts/ route serves the promoted charts"
    else
        CF_CHARTS_EXIT=$?
        if [[ "$CF_CHARTS_EXIT" == 75 ]]; then
            CHARTS_FAILURE_CLASS=route_inconclusive
            log "⚠️ Could not check that $SITE_URL/charts/ serves the promoted charts (exit 75): network errors, challenges or 403, 429 or 5xx answers"
        else
            CHARTS_FAILURE_CLASS=route_definitive
            log "❌ $SITE_URL/charts/ does not serve the promoted charts (exit $CF_CHARTS_EXIT): the <host>/charts/* route is missing or reaches another Worker or version"
        fi
    fi
}

# A charts Worker failure withholds the main Worker's promotion: the new pages
# may link to charts that production does not serve. Two exceptions, only in
# a build that keeps the promoted layout, where the charts already in
# production serve every page but those of charts new since then: an
# inconclusive route check, and CF_CHARTS_ALLOW_STALE=true. Either one
# promotes, and the job then exits non-zero (JOB_WARN_CLASS). A transition
# build has no exception: only the old pages are certain to work there.
main_may_follow_failed_charts() {
    [[ "$CF_ASSETS_ALLOW_PROMOTION" == "true" ]] || return 1
    if [[ "$CHARTS_TRANSITION" == "true" ]]; then
        if [[ "$CF_CHARTS_ALLOW_STALE" == "true" ]]; then
            log "⚠️ CF_CHARTS_ALLOW_STALE=true does not apply to a chart layout transition build"
        fi
        return 1
    fi
    if [[ "$CHARTS_FAILURE_CLASS" == "route_inconclusive" ]]; then
        log "⚠️ The /charts/ route check was inconclusive: promoting the main Worker; the job will exit non-zero"
        JOB_WARN_CLASS=route_inconclusive
        return 0
    fi
    if [[ "$CF_CHARTS_ALLOW_STALE" == "true" ]]; then
        log "⚠️⚠️ CF_CHARTS_ALLOW_STALE=true: promoting the main Worker although the charts Worker failed (exit $CF_CHARTS_EXIT); charts that production's charts Worker lacks fail until it recovers; the job will exit non-zero"
        JOB_WARN_CLASS=charts_stale
        return 0
    fi
    return 1
}

# The seconds from the main Worker's verified upload to its promotion
# decision: how long it waited for the charts Worker.
note_main_wait_for_charts() {
    local finished=""
    [[ "$CHARTS_LAYOUT" == "charts" && -n "$PUBLISH_STATE_DIR" ]] || return 0
    finished=$(cat "$PUBLISH_STATE_DIR/cfassets.finished" 2>/dev/null) || finished=""
    [[ "$finished" =~ ^[0-9]+$ ]] || return 0
    MAIN_WAIT_FOR_CHARTS_SECONDS=$(( $(date +%s) - finished ))
}

# One row per build that published the charts Worker: the seconds to build
# its stage, when it was promoted and how long the main Worker waited for it
# ("-" where none applies).
record_charts_timing() {
    local row
    row=$(printf '%s\t%s\t%s\t%s' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${CHARTS_STAGE_BUILD_SECONDS:--}" \
        "${CHARTS_PROMOTED_UTC:--}" "${MAIN_WAIT_FOR_CHARTS_SECONDS:--}")
    log "Charts timing: stage ${CHARTS_STAGE_BUILD_SECONDS:--}s, promoted ${CHARTS_PROMOTED_UTC:--}, main Worker waited ${MAIN_WAIT_FOR_CHARTS_SECONDS:--}s"
    mkdir -p "$(dirname "$CF_CHARTS_TIMING_FILE")" || return 1
    if [[ ! -f "$CF_CHARTS_TIMING_FILE" ]]; then
        printf 'timestamp_utc\tstage_build_seconds\tcharts_promoted_utc\tmain_wait_for_charts_seconds\n' \
            > "$CF_CHARTS_TIMING_FILE" || return 1
    fi
    printf '%s\n' "$row" >> "$CF_CHARTS_TIMING_FILE"
}

# A withheld promotion appends a promotion row with the charts Worker's exit
# status, as a failed promotion does, so that the Stage 4 audit's rows stay
# one per verified version.
record_withheld_promotion() {
    local version

    version=$(sed -n 1p "$CF_ASSETS_LAST_VERSION_FILE" 2>/dev/null) || version=""
    [[ "$version" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 0
    mkdir -p "$(dirname "$CF_ASSETS_PROMOTION_SUMMARY_FILE")" || return 1
    if [[ ! -f "$CF_ASSETS_PROMOTION_SUMMARY_FILE" ]]; then
        printf 'timestamp_utc\tversion_id\texit_status\n' > "$CF_ASSETS_PROMOTION_SUMMARY_FILE" || return 1
    fi
    printf '%s\t%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$version" "$1" \
        >> "$CF_ASSETS_PROMOTION_SUMMARY_FILE"
}

# Start every publisher together, then act on them in restore-priority order:
# with CHARTS_LAYOUT=charts the charts Worker first (see
# publish_charts_worker), then the main Workers version, promoted as soon as it
# verifies, then DO Spaces, then R2 (production's STORAGE_ORDER=do,r2,failover).
# A charts Worker failure withholds the main Worker's promotion (see
# main_may_follow_failed_charts). Promotion never depended on the storage
# uploads, so it does not wait for them. Nothing acts between the DO and R2
# waits; their order only sets the log order. Every publisher is waited for
# before the job decides its exit status. WORKERS_FAILURE_CLASS names the
# Workers failure, if any.
publish_in_restore_order() {
    local charts_pid="" cf_pid="" do_pid="" r2_pid=""

    PUBLISH_STATE_DIR=$(mktemp -d 2>/dev/null) || PUBLISH_STATE_DIR=""
    UPLOAD_START=$(date +%s)
    UPLOAD_SUCCESS=false
    CF_ASSETS_EXIT="$CF_ASSETS_PREPARE_EXIT"
    CF_CHARTS_EXIT="${CF_CHARTS_PREPARE_EXIT:-0}"
    WORKERS_FAILURE_CLASS=""
    CHARTS_FAILURE_CLASS=""
    CHARTS_PROMOTED_UTC=""
    MAIN_WAIT_FOR_CHARTS_SECONDS=""
    if [[ "$CF_ASSETS_EXIT" != "0" ]]; then
        WORKERS_FAILURE_CLASS=$(failure_class main_prepare "$CF_ASSETS_EXIT")
    fi
    if [[ "$CF_CHARTS_EXIT" != "0" ]]; then
        CHARTS_FAILURE_CLASS=$(failure_class charts_prepare "$CF_CHARTS_EXIT")
    fi

    if [[ "${CF_CHARTS_PREPARED:-false}" == "true" ]]; then
        log "🚀 Starting charts Worker upload (no route in its config)..."
        start_publisher cfcharts stdbuf -oL "$CF_CHARTS_SCRIPT" --upload-only
        charts_pid=$!
    fi

    if [[ "$CF_ASSETS_PREPARED" == "true" ]]; then
        log "🚀 Starting Cloudflare Workers Assets shadow upload (no production route)..."
        start_publisher cfassets stdbuf -oL "$SCRIPT_DIR/allium-deploy-cfassets.sh" --upload-only
        cf_pid=$!
    fi

    if [[ "$DO_ENABLED" == "true" ]]; then
        log "🚀 Starting DO Spaces upload..."
        start_publisher do-spaces stdbuf -oL "$SCRIPT_DIR/allium-deploy-upload-do.sh" "$OUTPUT_DIR"
        do_pid=$!
    fi

    if [[ "$R2_ENABLED" == "true" ]]; then
        log "🚀 Starting R2 upload..."
        start_publisher r2 stdbuf -oL "$SCRIPT_DIR/allium-deploy-upload-r2.sh" "$OUTPUT_DIR"
        r2_pid=$!
    fi

    if [[ -n "$charts_pid" ]]; then
        publish_charts_worker "$charts_pid"
    fi

    if [[ -n "$cf_pid" ]]; then
        wait "$cf_pid" || CF_ASSETS_EXIT=$?
        CF_ASSETS_TIME=$(publisher_duration cfassets)
        if [[ "$CF_ASSETS_EXIT" == "0" ]]; then
            log "✅ Workers Assets shadow upload and verification completed ($CF_ASSETS_TIME)"
            note_main_wait_for_charts
            if [[ "$CF_CHARTS_EXIT" != "0" ]] && ! main_may_follow_failed_charts; then
                CF_ASSETS_EXIT="$CF_CHARTS_EXIT"
                WORKERS_FAILURE_CLASS="$CHARTS_FAILURE_CLASS"
                if [[ "$CF_ASSETS_ALLOW_PROMOTION" == "true" ]]; then
                    log "❌ Workers Assets promotion withheld: the charts Worker failed (exit $CF_CHARTS_EXIT), and this version's pages link to /charts/"
                    record_withheld_promotion "$CF_CHARTS_EXIT" || log "⚠️ Could not record the withheld promotion"
                else
                    log "❌ The charts Worker failed (exit $CF_CHARTS_EXIT)"
                fi
                # No later --promote may deploy this version: its pages
                # would link to charts that production may not serve.
                rm -f "$CF_ASSETS_LAST_VERSION_FILE" || log "⚠️ Could not remove $CF_ASSETS_LAST_VERSION_FILE"
            elif [[ "$CF_ASSETS_ALLOW_PROMOTION" == "true" ]]; then
                log "🚀 Promoting verified Workers Assets version to production..."
                if promote_verified_cfassets_if_ready "$CF_ASSETS_EXIT"; then
                    log "✅ Workers Assets promotion completed successfully"
                    record_promoted_layout
                    record_live_charts
                    if [[ "$CHARTS_LAYOUT" == "charts" ]] && ! "$CF_CHARTS_SCRIPT" --check-redirects; then
                        log "⚠️ Old chart URLs on $SITE_URL do not redirect to /charts/ (the promotion stands)"
                        heartbeat /log "warn=redirects"
                    fi
                else
                    PROMOTE_EXIT=$?
                    log "❌ Workers Assets promotion failed (exit $PROMOTE_EXIT)"
                    CF_ASSETS_EXIT=$PROMOTE_EXIT
                    WORKERS_FAILURE_CLASS=main_promote
                fi
            fi
        else
            log "⚠️ Workers Assets shadow upload failed (exit $CF_ASSETS_EXIT, $CF_ASSETS_TIME)"
            WORKERS_FAILURE_CLASS=$(failure_class main_upload "$CF_ASSETS_EXIT")
        fi
    fi
    if [[ -n "$charts_pid" ]]; then
        record_charts_timing || log "⚠️ Could not record the charts timing in $CF_CHARTS_TIMING_FILE"
    fi

    if [[ -n "$do_pid" ]]; then
        DO_EXIT=0
        wait "$do_pid" || DO_EXIT=$?
        DO_TIME=$(publisher_duration do-spaces)
        if [[ "$DO_EXIT" == "0" ]]; then
            log "✅ DO Spaces upload completed ($DO_TIME)"
            UPLOAD_SUCCESS=true
        else
            log "⚠️ DO Spaces upload failed (exit $DO_EXIT, $DO_TIME)"
            heartbeat /log "warn=do_upload exit=$DO_EXIT"
        fi
    fi

    if [[ -n "$r2_pid" ]]; then
        R2_EXIT=0
        wait "$r2_pid" || R2_EXIT=$?
        R2_TIME=$(publisher_duration r2)
        if [[ "$R2_EXIT" == "0" ]]; then
            log "✅ R2 upload completed ($R2_TIME)"
            UPLOAD_SUCCESS=true
        else
            log "⚠️ R2 upload failed (exit $R2_EXIT, $R2_TIME)"
        fi
    fi

    remove_publish_state
}

remove_publish_state() {
    if [[ -n "${PUBLISH_STATE_DIR:-}" ]]; then
        rm -rf "$PUBLISH_STATE_DIR"
    fi
    PUBLISH_STATE_DIR=""
}

# One "page:link" line for each PNG link (src or href, with or without a
# query string or fragment) on the output tree's pages that does not fit
# CHARTS_LAYOUT: with charts, a link outside charts/ and static/ (a chart
# left beside its page); with beside, a link into charts/.
chart_link_mismatches() {
    { grep -rHoE --include='*.html' '(src|href)="[^"]*[.]png([?#][^"]*)?"' "$OUTPUT_DIR" || [[ $? == 1 ]]; } |
        awk -v layout="$CHARTS_LAYOUT" '{
            link = $0
            sub(/^.*="/, "", link)
            sub(/"$/, "", link)
            sub(/[?#].*$/, "", link)
            if (layout == "charts") bad = link !~ /(charts|static)\//
            else bad = link ~ /charts\//
            if (bad) print
        }'
}

# The output tree must fit CHARTS_LAYOUT before anything is published. With
# charts, no chart may be beside its page (Allium ran without --chart-layout
# charts): a failure in every build. In either layout the pages' PNG links
# must fit it: a failure in a transition build, otherwise a warning, as the
# old URLs' redirects and the Pages fallback still answer such a link.
check_output_tree() {
    local status=0 root chart mismatches count line examples="" problem=""
    local -a roots=()

    if [[ "$CHARTS_LAYOUT" == "charts" ]]; then
        for root in relay contact; do
            if [[ -d "$OUTPUT_DIR/$root" ]]; then
                roots+=("$root")
            fi
        done
        if (( ${#roots[@]} > 0 )); then
            chart=$(cd "$OUTPUT_DIR" && find "${roots[@]}" -mindepth 2 -maxdepth 2 -type f -name '*.png' -print -quit) ||
                chart="(relay/ and contact/ could not be listed)"
            if [[ -n "$chart" ]]; then
                log "❌ CHARTS_LAYOUT=charts, but the output tree has a chart beside its page: $chart"
                status=1
            fi
        fi
    fi

    if ! mismatches=$(chart_link_mismatches); then
        problem="Could not read the PNG links of the pages in $OUTPUT_DIR"
    elif [[ -n "$mismatches" ]]; then
        count=$(wc -l <<< "$mismatches" | tr -d ' ')
        while IFS= read -r line; do
            examples+=" ${line#"$OUTPUT_DIR"/}"
        done < <(head -n 3 <<< "$mismatches")
        problem="$count PNG links on the pages do not fit CHARTS_LAYOUT=$CHARTS_LAYOUT, e.g.$examples"
    fi
    if [[ -n "$problem" && "$CHARTS_TRANSITION" == "true" ]]; then
        log "❌ $problem"
        status=1
    elif [[ -n "$problem" ]]; then
        log "⚠️ $problem"
    fi
    return "$status"
}

# Checks of the generated tree before any publisher starts: check_output_tree,
# and in a transition build also the Workers preparation, which includes the
# file-count guard (exit status 4). A failure holds
# every publisher, the storage mirrors included, so that the main Worker, the
# charts Worker, DO and R2 all keep their last build.
run_local_gates() {
    local failed=false
    check_output_tree || failed=true
    if [[ "$CHARTS_TRANSITION" == "true" && ( "$CF_ASSETS_PREPARE_EXIT" != 0 || "$CF_CHARTS_PREPARE_EXIT" != 0 ) ]]; then
        log "❌ The Workers preparation failed in a chart layout transition build"
        failed=true
    fi
    if [[ "$failed" == "true" ]]; then
        log "❌ Local checks failed: mirrors held, no publisher started"
        return 1
    fi
}

# Cloudflare CDN purge (runs once after all uploads)
purge_cdn() {
    local site_url="${SITE_URL:-}"
    local pages_purge_url="${PAGES_PURGE_URL:-$site_url}"
    local purge_secret="${PURGE_SECRET:-}"
    local source_dir="$OUTPUT_DIR"
    
    if [[ -z "$purge_secret" ]] || [[ -z "$site_url" ]]; then
        log "ℹ️  Cloudflare CDN purge skipped (PURGE_SECRET or SITE_URL not configured)"
        return 0
    fi

    site_url="${site_url%/}"
    pages_purge_url="${pages_purge_url%/}"
    if [[ "$site_url" != https://* || "$pages_purge_url" != https://* ]]; then
        log "❌ Cloudflare CDN purge requires HTTPS SITE_URL and PAGES_PURGE_URL"
        return 1
    fi
    if ! command -v jq &>/dev/null; then
        log "❌ Cloudflare CDN purge requires jq for safe URL encoding"
        return 1
    fi

    local purge_endpoint="${pages_purge_url}/_purge"
    
    log "🧹 Purging Cloudflare CDN cache..."
    
    # Purge search-index.json first (must be fresh before any page loads)
    log "   Purging search-index.json..."
    local si_purge_response si_purge_http_code
    si_purge_response=$(curl -s -w "\n%{http_code}" -X POST "$purge_endpoint" \
        -H "X-Purge-Secret: ${purge_secret}" \
        -H "Content-Type: application/json" \
        -d "{\"urls\": [\"${site_url}/search-index.json\"]}" 2>&1 || true)
    si_purge_http_code=$(echo "$si_purge_response" | tail -1)
    if [[ "$si_purge_http_code" != "200" ]]; then
        log "   ⚠️  search-index.json purge returned HTTP $si_purge_http_code"
    fi
    
    # Purge Prometheus metrics (must be fresh for scraping)
    log "   Purging Prometheus metrics..."
    local pm_purge_response pm_purge_http_code
    pm_purge_response=$(curl -s -w "\n%{http_code}" -X POST "$purge_endpoint" \
        -H "X-Purge-Secret: ${purge_secret}" \
        -H "Content-Type: application/json" \
        -d "{\"urls\": [\"${site_url}/metrics\"]}" 2>&1 || true)
    pm_purge_http_code=$(echo "$pm_purge_response" | tail -1)
    if [[ "$pm_purge_http_code" != "200" ]]; then
        log "   ⚠️  Prometheus metrics purge returned HTTP $pm_purge_http_code"
    fi
    
    local html_files=()
    if [[ "$PAGES_BULK_PURGE_ENABLED" == "true" ]]; then
        # Find all HTML files and convert to URL paths
        # Cache keys use directory form (foo/) not file form (foo/index.html)
        while IFS= read -r -d '' file; do
            local rel_path="${file#$source_dir/}"
            # Convert index.html paths to directory form for cache key matching
            if [[ "$rel_path" == */index.html ]]; then
                rel_path="${rel_path%index.html}"
            elif [[ "$rel_path" == "index.html" ]]; then
                rel_path=""
            fi
            html_files+=("$rel_path")
        done < <(find "$source_dir" -name "*.html" -type f -print0)
        log "   Found ${#html_files[@]} HTML files to purge"
    else
        # A Cache API delete reaches only the data center that receives it, and
        # pages.dev caches little while a Worker route serves SITE_URL, so the
        # bulk loop rarely deletes anything. Keep the root page: the direct
        # Pages rollback audits hash / and search-index.json from this host.
        html_files=("")
        log "ℹ️  Pages bulk HTML purge disabled (PAGES_BULK_PURGE_ENABLED=false); purging the root page only"
    fi
    
    local total_html=${#html_files[@]}
    
    # Purge in batches of 50
    local batch_size=50
    local progress_interval=2500
    local total_purged=0
    local batch_num=0
    local last_progress=0
    
    for ((i=0; i<total_html; i+=batch_size)); do
        batch_num=$((batch_num + 1))
        local batch=("${html_files[@]:i:batch_size}")
        
        local urls_json
        urls_json=$(jq -cn --arg base "$site_url" --args \
            '$ARGS.positional | map($base + "/" + .)' "${batch[@]}")
        
        local purge_response
        purge_response=$(curl -s -X POST "$purge_endpoint" \
            -H "X-Purge-Secret: ${purge_secret}" \
            -H "Content-Type: application/json" \
            -d "{\"urls\":${urls_json}}" 2>&1)
        
        if echo "$purge_response" | grep -q '"success":true'; then
            local batch_purged
            batch_purged=$(echo "$purge_response" | grep -oE '"purged":[0-9]+' | grep -oE '[0-9]+')
            total_purged=$((total_purged + ${batch_purged:-0}))
        fi
        
        local files_processed=$((i + ${#batch[@]}))
        if (( files_processed - last_progress >= progress_interval )); then
            local percent=$((files_processed * 100 / total_html))
            log "   Progress: $files_processed/$total_html ($percent%) - purged $total_purged"
            last_progress=$files_processed
        fi
    done
    
    log "   ✅ Purged $total_purged of $total_html cached HTML pages"
}

maintain_pages_rollback_cache() {
    if [[ "$PAGES_ROLLBACK_MAINTENANCE_ENABLED" == "true" ]]; then
        purge_cdn
    else
        log "ℹ️  Pages rollback maintenance disabled; skipping Pages purge"
    fi
}

if [[ "${ALLIUM_DEPLOY_TEST_MODE:-}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi

if [[ "$WRANGLER_LOG_PATH" == "$WRANGLER_DEFAULT_LOG_PATH" ]] &&
    ! prepare_null_log_sink "$WRANGLER_LOG_PATH"; then
    log "❌ Could not prepare the bounded Wrangler debug sink"
    exit 1
fi

if ! ALLIUM_UPDATE_LOG_FILE="$ALLIUM_UPDATE_LOG_FILE" \
    ALLIUM_UPDATE_LOG_MAX_BYTES="$ALLIUM_UPDATE_LOG_MAX_BYTES" \
    ALLIUM_UPDATE_LOG_ARCHIVES="$ALLIUM_UPDATE_LOG_ARCHIVES" \
    WRANGLER_LOG_PATH="$WRANGLER_LOG_PATH" \
    WRANGLER_ERROR_LOG_MAX_BYTES="$WRANGLER_ERROR_LOG_MAX_BYTES" \
    WRANGLER_ERROR_LOG_ARCHIVES="$WRANGLER_ERROR_LOG_ARCHIVES" \
    "$SCRIPT_DIR/allium-deploy-maintain-logs.sh"; then
    log "⚠️ Log maintenance failed; continuing the deployment"
fi

export WRANGLER_LOG WRANGLER_LOG_PATH WRANGLER_LOG_SANITIZE

assert_boolean_setting CF_ASSETS_ENABLED "$CF_ASSETS_ENABLED"
assert_boolean_setting CF_ASSETS_REQUIRED "$CF_ASSETS_REQUIRED"
assert_boolean_setting CF_ASSETS_ALLOW_PROMOTION "$CF_ASSETS_ALLOW_PROMOTION"
assert_boolean_setting CF_ASSETS_REQUIRE_FRESH_CHECKOUT "$CF_ASSETS_REQUIRE_FRESH_CHECKOUT"
assert_boolean_setting CF_ASSETS_TOOLCHAIN_AUTO_SYNC "$CF_ASSETS_TOOLCHAIN_AUTO_SYNC"
assert_boolean_setting PAGES_ROLLBACK_MAINTENANCE_ENABLED "$PAGES_ROLLBACK_MAINTENANCE_ENABLED"
assert_boolean_setting PAGES_BULK_PURGE_ENABLED "$PAGES_BULK_PURGE_ENABLED"
assert_boolean_setting CF_CHARTS_ALLOW_STALE "$CF_CHARTS_ALLOW_STALE"
assert_boolean_setting ALLIUM_NO_CHARTS "$ALLIUM_NO_CHARTS"
assert_charts_layout
export_job_settings
check_heartbeat_url

trap 'record_update_exit $?' EXIT
JOB_FAILURE_CLASS=""
JOB_WARN_CLASS=""

log "========================================"
log "Starting metrics update..."
log "Storage order: $STORAGE_ORDER"
heartbeat /start
read_promoted_layout
warn_do_subtree_order

if [[ ! -f "$ALLIUM_DIR/allium.py" ]]; then
    log "❌ Could not locate allium.py under $ALLIUM_CONFIG_DIR or $ALLIUM_DIR"
    JOB_FAILURE_CLASS=allium
    exit 1
fi

# Capture current search-index.json schema version before update (for change detection)
OLD_SCHEMA_VERSION=""
if command -v jq &>/dev/null; then
    OLD_SCHEMA_VERSION=$(run_with_timeout 30 curl -sf "$SITE_URL/search-index.json" 2>/dev/null | jq -r '.meta.version // "unknown"' 2>/dev/null || echo "unknown")
    log "Current search-index schema: v$OLD_SCHEMA_VERSION"
fi

log "Checking guarded auto-pulls..."
guarded_pull_allium_deploy
guarded_pull_allium
sync_workers_toolchain
if ! capture_cfassets_deploy_snapshot; then
    JOB_FAILURE_CLASS=setup
    increment_failures
    exit 1
fi
if ! check_charts_layout_prerequisites; then
    increment_failures
    exit 1
fi

# Start background prune (only if less than 3 consecutive failures)
failures=$(get_failures)
if [ "$failures" -lt 3 ]; then
    log "🧹 Starting background prune (parallel with allium)..."
    stdbuf -oL "$SCRIPT_DIR/allium-deploy-prune.sh" &
    PRUNE_PID=$!
else
    log "⚠️ Skipping prune - $failures consecutive failures detected"
    PRUNE_PID=""
fi

# Step 1: Run allium
log "Running allium..."
cd "$ALLIUM_DIR"
set_allium_arguments
if python3 -u allium.py "${ALLIUM_ARGS[@]}"; then
    log "✅ Allium completed"
else
    log "❌ Allium failed"
    JOB_FAILURE_CLASS=allium
    increment_failures
    ROLLBACK_SUCCESS=true
    rollback_guarded_pulls || ROLLBACK_SUCCESS=false
    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true
    if [[ "$ROLLBACK_SUCCESS" != "true" ]]; then
        log "❌ One or more guarded-pull rollbacks failed - manual checkout repair required"
    fi
    exit 1
fi

if python3 "$SCRIPT_DIR/validate-search-discovery.py" "$OUTPUT_DIR" "$SITE_URL"; then
    log "✅ Search verification and crawler discovery artifacts validated"
else
    log "❌ Search verification or crawler discovery validation failed"
    JOB_FAILURE_CLASS=allium
    increment_failures
    ROLLBACK_SUCCESS=true
    rollback_guarded_pulls || ROLLBACK_SUCCESS=false
    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true
    if [[ "$ROLLBACK_SUCCESS" != "true" ]]; then
        log "❌ One or more guarded-pull rollbacks failed - manual checkout repair required"
    fi
    exit 1
fi

# Check for schema version change and auto-deploy search.js if needed
if command -v jq &>/dev/null && [[ -f "$OUTPUT_DIR/search-index.json" ]]; then
    NEW_SCHEMA_VERSION=$(jq -r '.meta.version // "unknown"' "$OUTPUT_DIR/search-index.json" 2>/dev/null || echo "unknown")
    
    if [[ "$OLD_SCHEMA_VERSION" != "unknown" ]] && [[ "$NEW_SCHEMA_VERSION" != "unknown" ]] && [[ "$OLD_SCHEMA_VERSION" != "$NEW_SCHEMA_VERSION" ]]; then
        log "⚠️  SEARCH-INDEX SCHEMA CHANGED: v$OLD_SCHEMA_VERSION → v$NEW_SCHEMA_VERSION"
        log "⚠️  Auto-deploying search.js to match new search-index schema..."

        deploy_pages_for_schema_change
    elif [[ "$NEW_SCHEMA_VERSION" != "unknown" ]]; then
        log "Search-index schema: v$NEW_SCHEMA_VERSION (unchanged)"
    fi
fi

# Step 2: Prepare the immutable output overlays before any publisher reads the
# tree, check the tree (see run_local_gates), then publish to the Workers
# shadow and the storage backends in parallel, acting on them in
# restore-priority order (see publish_in_restore_order). Repeated Workers
# preparation is idempotent and preserves mtimes. With CHARTS_LAYOUT=charts
# the main Worker's overlay includes its .assetsignore and _redirects, and the
# charts Worker's stage is rebuilt from the tree.
CF_ASSETS_PREPARED=false
CF_ASSETS_PREPARE_EXIT=0
CF_CHARTS_PREPARED=false
CF_CHARTS_PREPARE_EXIT=0
CHARTS_STAGE_BUILD_SECONDS=""

if [[ "$CF_ASSETS_ENABLED" == "true" ]]; then
    log "Preparing Cloudflare Workers Assets overlay and route-free config..."
    if "$SCRIPT_DIR/allium-deploy-cfassets.sh" --generate-only; then
        CF_ASSETS_PREPARED=true
    else
        CF_ASSETS_PREPARE_EXIT=$?
        log "⚠️ Workers Assets preparation failed (exit $CF_ASSETS_PREPARE_EXIT)"
    fi
    if [[ "$CHARTS_LAYOUT" == "charts" && "$ALLIUM_NO_CHARTS" == "true" ]]; then
        log "ℹ️ ALLIUM_NO_CHARTS=true: no charts in this build; the charts Worker keeps its promoted version"
    elif [[ "$CHARTS_LAYOUT" == "charts" ]]; then
        log "Preparing the charts Worker stage and route-free config..."
        stage_started=$(date +%s)
        if "$CF_CHARTS_SCRIPT" --generate-only; then
            CF_CHARTS_PREPARED=true
        else
            CF_CHARTS_PREPARE_EXIT=$?
            log "⚠️ Charts Worker preparation failed (exit $CF_CHARTS_PREPARE_EXIT)"
        fi
        CHARTS_STAGE_BUILD_SECONDS=$(( $(date +%s) - stage_started ))
    fi
fi

if ! run_local_gates; then
    JOB_FAILURE_CLASS=local
    increment_failures
    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true
    exit 1
fi

publish_in_restore_order

# Check if at least one upload succeeded
if [[ "$UPLOAD_SUCCESS" == "true" ]]; then
    log "✅ Storage uploads completed"
else
    log "❌ All uploads failed"
    JOB_FAILURE_CLASS=storage
    increment_failures
    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true
    exit 1
fi


if [[ "$CF_ASSETS_REQUIRED" == "true" && "$CF_ASSETS_EXIT" != "0" ]]; then
    log "❌ Workers Assets is required but its upload or verification failed"
    JOB_FAILURE_CLASS="${WORKERS_FAILURE_CLASS:-main_upload}"
    increment_failures
    [[ -n "${PRUNE_PID:-}" ]] && kill "$PRUNE_PID" 2>/dev/null || true
    exit 1
fi

reset_failures

# Step 3: Keep the direct Pages rollback deployment fresh until Stage 6 moves
# the hostname to a Worker Custom Domain. Stage 6 changes this single gate only
# after the new origin passes the complete health check.
maintain_pages_rollback_cache

# Wait for prune to finish
if [[ -n "${PRUNE_PID:-}" ]]; then
    if ps -p "$PRUNE_PID" > /dev/null 2>&1; then
        log "⏳ Waiting for background prune to finish..."
        wait "$PRUNE_PID" 2>/dev/null || true
    fi
fi

# The main Worker was promoted although its charts are not confirmed (see
# main_may_follow_failed_charts): everything is published, but someone must
# look.
if [[ -n "$JOB_WARN_CLASS" ]]; then
    JOB_FAILURE_CLASS="$JOB_WARN_CLASS"
    log "❌ Published, but the charts Worker needs attention ($JOB_WARN_CLASS)"
    exit 1
fi

log "✅ Done! Site: $SITE_URL"
log "========================================"
