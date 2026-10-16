#!/usr/bin/env bash
# The zone route <host>/charts/* that sends chart requests to the charts-only
# Worker of CHARTS_LAYOUT=charts (scripts/allium-deploy-cfcharts.sh). <host> is
# SITE_URL's host.
#
#   status   List the zone's Worker routes.
#   create   Add <host>/charts/* to CF_CHARTS_WORKER_NAME. The zone must have
#            exactly one route before (the site's) and has exactly two after.
#            Prints the new route's ID.
#   delete   Remove that route. Refused while CHARTS_LAYOUT=charts, and while
#            the last promoted main Worker version has that layout (see
#            logs/charts-layout-promoted): its pages link to /charts/.
#
# The API token is read as scripts/allium-deploy-cfassets.sh reads it. It is
# handed to curl on standard input, never on a command line, and never
# printed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
API_BASE="https://api.cloudflare.com/client/v4"

MODE="${1:-}"
case "$MODE" in
    status|create|delete) ;;
    *) echo "Usage: $0 status|create|delete" >&2; exit 2 ;;
esac

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    # shellcheck disable=SC1091
    source "$DEPLOY_DIR/config.env"
fi

log() {
    printf '[CF-Charts-Route] %s\n' "$1"
}

refuse() {
    log "refusing $MODE: $1"
    exit 1
}

CHARTS_LAYOUT="${CHARTS_LAYOUT:-beside}"
CHARTS_LAYOUT_MARKER_FILE="${CHARTS_LAYOUT_MARKER_FILE:-$DEPLOY_DIR/logs/charts-layout-promoted}"
SITE_HOST="${SITE_URL:-}"
SITE_HOST="${SITE_HOST%/}"
SITE_HOST="${SITE_HOST#https://}"
[[ "${SITE_URL:-}" == https://* && "$SITE_HOST" =~ ^[a-z0-9-]+(\.[a-z0-9-]+)+$ ]] || {
    log "SITE_URL must be the site's https:// root (now '${SITE_URL:-}')"
    exit 2
}
CHARTS_PATTERN="$SITE_HOST/charts/*"
if [[ "$MODE" != status ]]; then
    [[ "${CF_CHARTS_WORKER_NAME:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || {
        log "CF_CHARTS_WORKER_NAME must name the charts Worker (now '${CF_CHARTS_WORKER_NAME:-}')"
        exit 2
    }
fi
command -v jq >/dev/null 2>&1 || { log "jq is required"; exit 2; }

for token_file in \
    "$HOME/.config/cloudflare/workers_api_token" \
    "$HOME/.config/cloudflare/api_token"; do
    if [[ -f "$token_file" ]]; then
        # shellcheck disable=SC1090
        source "$token_file"
        break
    fi
done
# The token goes into a curl config line: allow only a token's characters.
[[ "${CLOUDFLARE_API_TOKEN:-}" =~ ^[A-Za-z0-9._-]+$ ]] || {
    log "CLOUDFLARE_API_TOKEN is not configured or malformed"
    exit 2
}

# cf_api <method> <path> [JSON body]: prints the response, or fails unless
# Cloudflare reports success.
cf_api() {
    local method="$1" path="$2" body="${3:-}" response status message
    local -a args=(--silent --show-error --max-time 60 --config - --request "$method"
        --header 'Content-Type: application/json' --write-out '\n%{http_code}')
    if [[ -n "$body" ]]; then
        args+=(--data "$body")
    fi
    response=$(printf 'header = "Authorization: Bearer %s"\n' "$CLOUDFLARE_API_TOKEN" |
        curl "${args[@]}" "$API_BASE$path") || {
        log "could not reach the Cloudflare API for $method $path" >&2
        return 1
    }
    status="${response##*$'\n'}"
    response="${response%$'\n'*}"
    if [[ "$status" != 2* ]] || ! jq -e '.success == true' <<< "$response" >/dev/null 2>&1; then
        message=$(jq -r '[.errors[]?.message] | join("; ")' <<< "$response" 2>/dev/null) || message=""
        log "the Cloudflare API refused $method $path (HTTP $status${message:+: $message})" >&2
        return 1
    fi
    printf '%s\n' "$response"
}

# The zone holding SITE_URL's host: the longest of its parent names that is a
# zone the token can see.
find_zone() {
    local name="$SITE_HOST" zones
    while [[ "$name" == *.* ]]; do
        zones=$(cf_api GET "/zones?name=$name") || return 1
        ZONE_ID=$(jq -r --arg name "$name" '[.result[]? | select(.name == $name) | .id] | if length == 1 then .[0] else empty end' <<< "$zones")
        if [[ -n "$ZONE_ID" ]]; then
            return 0
        fi
        name="${name#*.}"
    done
    log "no zone for $SITE_HOST is visible to the token"
    return 1
}

# Sets ROUTES to the zone's Worker routes (a JSON array) and ROUTE_COUNT.
list_routes() {
    local listing
    listing=$(cf_api GET "/zones/$ZONE_ID/workers/routes") || return 1
    ROUTES=$(jq -c '.result // []' <<< "$listing")
    ROUTE_COUNT=$(jq 'length' <<< "$ROUTES")
}

# The IDs of the routes <host>/charts/* to the charts Worker, one per line.
charts_route_ids() {
    jq -r --arg pattern "$CHARTS_PATTERN" --arg script "${CF_CHARTS_WORKER_NAME:-}" \
        '.[] | select(.pattern == $pattern and .script == $script) | .id' <<< "$ROUTES"
}

show_routes() {
    jq -r '.[] | "route \(.id) \(.pattern) -> \(.script // "(no Worker)")"' <<< "$ROUTES"
    log "$ROUTE_COUNT routes in the zone of $SITE_HOST"
}

find_zone
list_routes

case "$MODE" in
    status)
        show_routes
        ;;
    create)
        show_routes
        (( ROUTE_COUNT == 1 )) || refuse "expected exactly one route (the site's) before adding $CHARTS_PATTERN, found $ROUTE_COUNT"
        [[ "$(jq -r '.[0].pattern' <<< "$ROUTES")" != "$CHARTS_PATTERN" ]] || refuse "$CHARTS_PATTERN already exists"
        created=$(cf_api POST "/zones/$ZONE_ID/workers/routes" \
            "$(jq -cn --arg pattern "$CHARTS_PATTERN" --arg script "$CF_CHARTS_WORKER_NAME" '{pattern: $pattern, script: $script}')")
        route_id=$(jq -r '.result.id // empty' <<< "$created")
        list_routes
        show_routes
        if [[ -z "$route_id" ]] || (( ROUTE_COUNT != 2 )) || [[ "$(charts_route_ids)" != "$route_id" ]]; then
            log "the zone does not hold exactly the site's route and $CHARTS_PATTERN -> $CF_CHARTS_WORKER_NAME (${route_id:-no ID returned}): check it"
            exit 1
        fi
        log "created $CHARTS_PATTERN -> $CF_CHARTS_WORKER_NAME"
        printf 'ROUTE_ID=%s\n' "$route_id"
        ;;
    delete)
        [[ "$CHARTS_LAYOUT" != charts ]] || refuse "CHARTS_LAYOUT=charts: pages link to /charts/"
        promoted=beside
        if [[ -e "$CHARTS_LAYOUT_MARKER_FILE" ]]; then
            promoted=$(cat "$CHARTS_LAYOUT_MARKER_FILE" 2>/dev/null) || promoted=unreadable
        fi
        [[ "$promoted" == beside ]] || refuse "the last promoted main Worker version has the chart layout '$promoted' ($CHARTS_LAYOUT_MARKER_FILE)"
        show_routes
        route_id=$(charts_route_ids)
        if (( ROUTE_COUNT != 2 )) || [[ -z "$route_id" || "$route_id" == *$'\n'* ]]; then
            refuse "expected the site's route and one $CHARTS_PATTERN -> $CF_CHARTS_WORKER_NAME, found $ROUTE_COUNT routes"
        fi
        cf_api DELETE "/zones/$ZONE_ID/workers/routes/$route_id" >/dev/null
        list_routes
        show_routes
        if (( ROUTE_COUNT != 1 )) || [[ -n "$(charts_route_ids)" ]]; then
            log "the zone does not hold exactly the site's route after deleting $route_id: check it"
            exit 1
        fi
        log "deleted $route_id ($CHARTS_PATTERN)"
        ;;
esac
