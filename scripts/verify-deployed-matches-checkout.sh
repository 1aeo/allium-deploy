#!/usr/bin/env bash
# Verify Cloudflare Pages production deployment matches this checkout.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    # shellcheck disable=SC1091
    source "$DEPLOY_DIR/config.env"
fi

PROJECT_NAME="${PAGES_PROJECT_NAME:-1aeo-metrics}"
REMOTE="${VERIFY_REMOTE:-origin}"
BRANCH="${VERIFY_BRANCH:-main}"

cd "$DEPLOY_DIR"

log() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $1"
}

wrangler_bin() {
    if [[ -x "$DEPLOY_DIR/node_modules/.bin/wrangler" ]]; then
        printf '%s\n' "$DEPLOY_DIR/node_modules/.bin/wrangler"
    elif command -v wrangler >/dev/null 2>&1; then
        command -v wrangler
    else
        log "wrangler is required; run pnpm install --frozen-lockfile first" >&2
        return 127
    fi
}

if ! command -v jq >/dev/null 2>&1; then
    log "jq is required to parse wrangler deployment JSON"
    exit 1
fi

sha_matches() {
    local expected="$1"
    local observed="$2"

    [[ -n "$expected" && -n "$observed" ]] || return 1
    if [[ "$expected" == "$observed" ]]; then
        return 0
    fi

    # Wrangler/Cloudflare may return an abbreviated commit. Require at least
    # seven characters before accepting prefix equality.
    if (( ${#observed} >= 7 )) && [[ "$expected" == "$observed"* ]]; then
        return 0
    fi
    if (( ${#expected} >= 7 )) && [[ "$observed" == "$expected"* ]]; then
        return 0
    fi
    return 1
}

log "Fetching $REMOTE $BRANCH..."
if ! run_with_timeout 30 git fetch --quiet "$REMOTE" "$BRANCH"; then
    log "Could not fetch $REMOTE $BRANCH"
    exit 1
fi

LOCAL_HEAD="$(git rev-parse HEAD)"
REMOTE_HEAD="$(git rev-parse "$REMOTE/$BRANCH")"

if [[ "$LOCAL_HEAD" != "$REMOTE_HEAD" ]]; then
    log "Mismatch: local HEAD $LOCAL_HEAD != $REMOTE/$BRANCH $REMOTE_HEAD"
    exit 1
fi

log "Reading latest Pages deployment for $PROJECT_NAME..."
if ! WRANGLER_BIN="$(wrangler_bin)"; then
    exit 1
fi
if ! DEPLOYMENTS_JSON="$(run_with_timeout 30 "$WRANGLER_BIN" pages deployment list \
    --project-name "$PROJECT_NAME" \
    --environment production \
    --json)"; then
    log "Could not list production Pages deployments for $PROJECT_NAME"
    exit 1
fi

DEPLOYED_SHA="$(printf '%s' "$DEPLOYMENTS_JSON" | jq -r '
    def deployments:
      if type == "array" then .
      elif .result then .result
      elif .deployments then .deployments
      else []
      end;
    def normalized($value):
      ($value // "" | tostring | ascii_downcase);
    def deployment_branch($d):
      $d.Branch?
      // $d.deployment_trigger.metadata.branch?
      // $d.source.config.branch?
      // $d.branch?
      // null;
    def deployment_environment($d):
      $d.Environment?
      // $d.environment?
      // $d.deployment_trigger.metadata.environment?
      // $d.source.config.environment?
      // null;
    def deployment_source($d):
      $d.Source?
      // $d.deployment_trigger.metadata.commit_hash?
      // $d.deployment_trigger.metadata.commitHash?
      // $d.source.config.commit_hash?
      // $d.source.config.commitHash?
      // $d.commit_hash?
      // $d.commitHash?
      // empty;
    def deployment_successful($d):
      normalized($d.Status? // $d.latest_stage.status? // $d.status?) == "success";
    (deployments
     | map(select(
         (normalized(deployment_branch(.)) == "production"
          or normalized(deployment_environment(.)) == "production")
         and deployment_successful(.)))
     | .[0] // empty) as $d
    | deployment_source($d)
')"

if [[ -z "$DEPLOYED_SHA" ]]; then
    log "Could not determine deployed commit SHA from wrangler JSON output"
    exit 1
fi

if ! sha_matches "$LOCAL_HEAD" "$DEPLOYED_SHA"; then
    log "Mismatch: deployed commit $DEPLOYED_SHA != local/origin $LOCAL_HEAD"
    exit 1
fi

log "OK: local HEAD, $REMOTE/$BRANCH, and deployed Pages commit match ($LOCAL_HEAD)"
