#!/usr/bin/env bash
# The charts-only Workers Static Assets Worker of CHARTS_LAYOUT=charts. Allium
# then writes the chart PNGs to charts/relay/<fingerprint>/ and
# charts/contact/<hash>/, the main Worker drops /charts/ with its
# .assetsignore, and this Worker serves them on the zone route <host>/charts/*.
#
#   --generate-only, --upload-only, --promote
#       As allium-deploy-cfassets.sh, for this Worker (CHARTS_LAYOUT=charts
#       only). Its directory, CF_CHARTS_STAGE_DIR, is rebuilt from the output
#       tree as hard links.
#   --bootstrap-deploy
#       Create the Worker with "wrangler deploy" before the layout changes,
#       from a stage of two files: the _headers and charts/404.html. The first
#       build with CHARTS_LAYOUT=charts uploads the charts. Refuses unless
#       CHARTS_LAYOUT and the last promoted layout are both beside, and
#       refuses a Worker that already has a deployment, before it changes the
#       stage. Runs from an empty environment, as the scheduled job does.
#   --check-route
#       Production (SITE_URL) must serve the stage's build ID and charts under
#       /charts/, among them charts the output tree's pages link to. Exits 75
#       when that could not be checked (see the verifier).
#   --check-bootstrap-route
#       After the bootstrap deployment and the route, before the layout
#       changes: production must serve the bootstrap stage's charts/404.html
#       under /charts/, and its 404 page for a missing chart, from this Worker.
#   --check-redirects
#       Production must redirect old chart URLs to /charts/.
#   --check-config
#       Only check this Worker's settings (CHARTS_LAYOUT=charts): no file is
#       written and no Cloudflare API call is made.
#
# Uploads run allium-deploy-cfassets.sh in its charts profile, with this
# Worker's name, alias, stage, template, verifier and state files: the Workers
# audits pair the main Worker's rows one to one, so charts rows never go into
# its files.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

MODE="${1:-}"
case "$MODE" in
    --generate-only|--upload-only|--promote|--bootstrap-deploy|--check-route|--check-bootstrap-route|--check-redirects|--check-config) ;;
    *)
        echo "Usage: $0 --generate-only|--upload-only|--promote|--bootstrap-deploy|--check-route|--check-bootstrap-route|--check-redirects|--check-config" >&2
        exit 2
        ;;
esac

# An operator runs the bootstrap deployment by hand. Start it again from an
# empty environment, as the scheduler starts the scheduled job, so that nothing
# from an interactive shell (another token, a Wrangler setting) reaches it:
# settings come from config.env and the token from its usual files.
if [[ "$MODE" == "--bootstrap-deploy" && "${ALLIUM_DEPLOY_CLEAN_ENV:-}" != 1 ]]; then
    set_clean_env
    exec "${CLEAN_ENV[@]}" ALLIUM_DEPLOY_CLEAN_ENV=1 "$SCRIPT_DIR/allium-deploy-cfcharts.sh" "$MODE"
fi

# A value from the environment wins over config.env, here and so in
# allium-deploy-cfassets.sh: the update job exports its CHARTS_LAYOUT,
# ALLIUM_NO_CHARTS, CF_CHARTS_WORKER_NAME and CF_ASSETS_ENABLED, and an
# operator may set any of these for one run.
CF_CHARTS_ENV_OVERRIDES=(
    OUTPUT_DIR
    SITE_URL
    CHARTS_LAYOUT
    ALLIUM_NO_CHARTS
    CF_ASSETS_ENABLED
    CF_ASSETS_ALLOW_PROMOTION
    CF_ASSETS_WORKER_NAME
    CF_ASSETS_DIRECTORY
    CF_CHARTS_WORKER_NAME
    CF_CHARTS_PREVIEW_ALIAS
    CF_CHARTS_STAGE_DIR
    CF_CHARTS_TEMPLATE
    CF_CHARTS_CONFIG
    CF_CHARTS_VERIFY_SCRIPT
    CF_CHARTS_CONSECUTIVE_FILE
    CF_CHARTS_LAST_VERSION_FILE
    CF_CHARTS_SUMMARY_FILE
    CF_CHARTS_PROMOTION_SUMMARY_FILE
    CF_CHARTS_UPLOADS_FILE
    CF_CHARTS_WARN_FILES
)
capture_env_overrides "${CF_CHARTS_ENV_OVERRIDES[@]}"

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    # shellcheck disable=SC1091
    source "$DEPLOY_DIR/config.env"
fi

restore_env_overrides "${CF_CHARTS_ENV_OVERRIDES[@]}"

log() {
    printf '[CF-Charts] %s\n' "$1"
}

CHARTS_LAYOUT="${CHARTS_LAYOUT:-beside}"
case "$CHARTS_LAYOUT" in
    beside|charts) ;;
    *) log "invalid CHARTS_LAYOUT=$CHARTS_LAYOUT; expected beside or charts"; exit 2 ;;
esac

# The main Worker's settings, with allium-deploy-cfassets.sh's defaults.
main_worker_name="${CF_ASSETS_WORKER_NAME:-allium-metrics-assets}"
main_directory="${CF_ASSETS_DIRECTORY:-${OUTPUT_DIR:-$HOME/metrics-output}}"
while [[ "$main_directory" == */ && "$main_directory" != / ]]; do
    main_directory="${main_directory%/}"
done

[[ -n "${CF_CHARTS_WORKER_NAME:-}" ]] || {
    log "CF_CHARTS_WORKER_NAME is required for the charts Worker"
    exit 2
}
[[ "$CF_CHARTS_WORKER_NAME" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || {
    log "invalid charts worker name: $CF_CHARTS_WORKER_NAME"
    exit 2
}
[[ "$CF_CHARTS_WORKER_NAME" != "$main_worker_name" ]] || {
    log "CF_CHARTS_WORKER_NAME must name a Worker other than $main_worker_name"
    exit 2
}

# The alias preview host <alias>-<name> is one DNS label.
PREVIEW_ALIAS="${CF_CHARTS_PREVIEW_ALIAS:-allium-charts-candidate}"
(( ${#PREVIEW_ALIAS} + 1 + ${#CF_CHARTS_WORKER_NAME} <= 63 )) || {
    log "CF_CHARTS_PREVIEW_ALIAS and CF_CHARTS_WORKER_NAME together exceed the 63 characters of a preview host label"
    exit 2
}
STAGE_DIR="${CF_CHARTS_STAGE_DIR:-$main_directory-charts-stage}"
VERIFY_SCRIPT="${CF_CHARTS_VERIFY_SCRIPT:-$SCRIPT_DIR/allium-deploy-verify-cfcharts.sh}"

case "$MODE" in
    --generate-only|--upload-only|--promote|--check-config)
        [[ "$CHARTS_LAYOUT" == "charts" ]] || {
            log "builds publish the charts Worker only with CHARTS_LAYOUT=charts (now $CHARTS_LAYOUT); see --bootstrap-deploy"
            exit 2
        }
        if [[ "$MODE" == "--check-config" ]]; then
            log "settings ok: charts Worker $CF_CHARTS_WORKER_NAME, preview alias $PREVIEW_ALIAS"
            exit 0
        fi
        ;;
    --bootstrap-deploy)
        # From the switch on, builds rebuild the stage and the rendered config
        # and publish this Worker by version upload: a bootstrap then could
        # only replace them under a running job.
        marker="${CHARTS_LAYOUT_MARKER_FILE:-$DEPLOY_DIR/logs/charts-layout-promoted}"
        promoted=beside
        if [[ -e "$marker" ]]; then
            promoted=$(cat "$marker" 2>/dev/null) || promoted=unreadable
        fi
        if [[ "$CHARTS_LAYOUT" != beside || "$promoted" != beside ]]; then
            log "refusing bootstrap: CHARTS_LAYOUT=$CHARTS_LAYOUT and the last promoted layout is '$promoted' ($marker); bootstrap only while both are beside"
            exit 1
        fi
        ;;
    --check-route|--check-bootstrap-route|--check-redirects)
        site="${SITE_URL:-}"
        site="${site%/}"
        [[ "$site" =~ ^https://[A-Za-z0-9.-]+$ ]] || {
            log "SITE_URL must be the site's https:// root to check its chart URLs (now '${SITE_URL:-}')"
            exit 2
        }
        case "$MODE" in
            --check-route) exec "$VERIFY_SCRIPT" --route "$site" "$STAGE_DIR" "$main_directory" ;;
            --check-bootstrap-route) exec "$VERIFY_SCRIPT" --route-bootstrap "$site" "$STAGE_DIR" ;;
        esac
        exec "$VERIFY_SCRIPT" --redirects "$site" "$STAGE_DIR"
        ;;
esac

export CHARTS_LAYOUT
export CF_ASSETS_PROFILE=charts
export CF_CHARTS_SOURCE_DIRECTORY="$main_directory"
export CF_ASSETS_WORKER_NAME="$CF_CHARTS_WORKER_NAME"
export CF_ASSETS_PREVIEW_ALIAS="$PREVIEW_ALIAS"
export CF_ASSETS_DIRECTORY="$STAGE_DIR"
export CF_ASSETS_TEMPLATE="${CF_CHARTS_TEMPLATE:-$DEPLOY_DIR/wrangler.charts.toml.template}"
export CF_ASSETS_CONFIG="${CF_CHARTS_CONFIG:-$DEPLOY_DIR/wrangler.charts.toml}"
export CF_ASSETS_VERIFY_SCRIPT="$VERIFY_SCRIPT"
export CF_ASSETS_CONSECUTIVE_FILE="${CF_CHARTS_CONSECUTIVE_FILE:-$DEPLOY_DIR/logs/cfcharts-shadow-consecutive-successes}"
export CF_ASSETS_LAST_VERSION_FILE="${CF_CHARTS_LAST_VERSION_FILE:-$DEPLOY_DIR/logs/cfcharts-last-version}"
export CF_ASSETS_SUMMARY_FILE="${CF_CHARTS_SUMMARY_FILE:-$DEPLOY_DIR/logs/cfcharts-shadow-summary.tsv}"
export CF_ASSETS_PROMOTION_SUMMARY_FILE="${CF_CHARTS_PROMOTION_SUMMARY_FILE:-$DEPLOY_DIR/logs/cfcharts-promotion-summary.tsv}"
export CF_ASSETS_UPLOADS_FILE="${CF_CHARTS_UPLOADS_FILE:-$DEPLOY_DIR/logs/cfcharts-uploads.tsv}"
# Warn well before the per-version file limit: the charts grow with the relays
# and with each chart period kept.
export CF_ASSETS_WARN_FILES="${CF_CHARTS_WARN_FILES:-85000}"

exec "$SCRIPT_DIR/allium-deploy-cfassets.sh" "$MODE"
