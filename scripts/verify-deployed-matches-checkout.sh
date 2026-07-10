#!/usr/bin/env bash
# Verify Cloudflare Pages production deployment matches this checkout.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

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

run_wrangler() {
    if command -v wrangler >/dev/null 2>&1; then
        wrangler "$@"
    else
        npx --yes wrangler "$@"
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
git fetch --quiet "$REMOTE" "$BRANCH"

LOCAL_HEAD="$(git rev-parse HEAD)"
REMOTE_HEAD="$(git rev-parse "$REMOTE/$BRANCH")"

if [[ "$LOCAL_HEAD" != "$REMOTE_HEAD" ]]; then
    log "Mismatch: local HEAD $LOCAL_HEAD != $REMOTE/$BRANCH $REMOTE_HEAD"
    exit 1
fi

log "Reading latest Pages deployment for $PROJECT_NAME..."
DEPLOYMENTS_JSON="$(run_wrangler pages deployment list \
    --project-name "$PROJECT_NAME" \
    --json)"

DEPLOYED_SHA="$(printf '%s' "$DEPLOYMENTS_JSON" | jq -r '
    def deployments:
      if type == "array" then .
      elif .result then .result
      elif .deployments then .deployments
      else []
      end;
    (deployments
     | map(select(
         (.deployment_trigger.metadata.branch
          // .source.config.branch
          // .branch
          // .environment
          // "production") == "production"))
     | (.[0] // deployments[0] // {})) as $d
    | ($d.deployment_trigger.metadata.commit_hash
       // $d.deployment_trigger.metadata.commitHash
       // $d.source.config.commit_hash
       // $d.source.config.commitHash
       // $d.commit_hash
       // $d.commitHash
       // empty)
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
