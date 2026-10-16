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

export GIT_AUTHOR_NAME="1aeo"
export GIT_AUTHOR_EMAIL="1aeo@users.noreply.github.com"
export GIT_COMMITTER_NAME="1aeo"
export GIT_COMMITTER_EMAIL="1aeo@users.noreply.github.com"

ORIGIN="$TMP_DIR/origin.git"
CHECKOUT="$TMP_DIR/checkout"
UPSTREAM="$TMP_DIR/upstream"
git init --bare "$ORIGIN" >/dev/null
git clone "$ORIGIN" "$CHECKOUT" >/dev/null 2>&1
git -C "$CHECKOUT" checkout -b main >/dev/null 2>&1
mkdir -p "$CHECKOUT/scripts" "$CHECKOUT/cloudflare-assets"
cp "$ROOT_DIR/scripts/allium-deploy-cfassets.sh" "$CHECKOUT/scripts/"
cp "$ROOT_DIR/scripts/allium-deploy-lib.sh" "$CHECKOUT/scripts/"
cp "$ROOT_DIR/wrangler.assets.toml.template" "$CHECKOUT/"
cp "$ROOT_DIR/cloudflare-assets/_headers" "$CHECKOUT/cloudflare-assets/"
cp "$ROOT_DIR/cloudflare-assets/404.html" "$CHECKOUT/cloudflare-assets/"
git -C "$CHECKOUT" add .
git -C "$CHECKOUT" commit -m "fixture" >/dev/null
git -C "$CHECKOUT" push -u origin main >/dev/null 2>&1
git --git-dir="$ORIGIN" symbolic-ref HEAD refs/heads/main
PINNED_SHA=$(git -C "$CHECKOUT" rev-parse HEAD)

git clone "$ORIGIN" "$UPSTREAM" >/dev/null 2>&1
printf 'advance\n' > "$UPSTREAM/advance.txt"
git -C "$UPSTREAM" add advance.txt
git -C "$UPSTREAM" commit -m "advance origin" >/dev/null
git -C "$UPSTREAM" push origin main >/dev/null 2>&1
ADVANCED_SHA=$(git -C "$UPSTREAM" rev-parse HEAD)

MOCK_BIN="$TMP_DIR/mock-bin"
MOCK_CALLS="$TMP_DIR/wrangler-calls"
mkdir -p "$MOCK_BIN" "$TMP_DIR/output"
printf '<html>root</html>\n' > "$TMP_DIR/output/index.html"
printf '{"meta":{"version":"1.6"},"relays":[]}\n' > "$TMP_DIR/output/search-index.json"
# The quoted lines are the literal body of the generated mock executable.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\n" "$@" >> "$MOCK_WRANGLER_CALLS"' \
    > "$MOCK_BIN/pnpm"
chmod 0755 "$MOCK_BIN/pnpm"

VERSION='54d8785a-390b-4fc2-843d-1794b8491703'
printf '%s\n' "$VERSION" > "$TMP_DIR/last-version"

run_promote() {
    PATH="$MOCK_BIN:$PATH" \
    MOCK_WRANGLER_CALLS="$MOCK_CALLS" \
    CLOUDFLARE_API_TOKEN=test-token \
    CF_ASSETS_REQUIRE_FRESH_CHECKOUT=true \
    CF_ASSETS_EXPECTED_DEPLOY_SHA="${1-}" \
    CF_ASSETS_ALLOW_PROMOTION=true \
    CF_ASSETS_LAST_VERSION_FILE="$TMP_DIR/last-version" \
    CF_ASSETS_PROMOTION_SUMMARY_FILE="$TMP_DIR/promotion-summary.tsv" \
    CF_ASSETS_CONFIG="$TMP_DIR/wrangler.assets.toml" \
    CF_ASSETS_DIRECTORY="$TMP_DIR/output" \
    WRANGLER_LOG_PATH="$TMP_DIR/wrangler.log" \
        "$CHECKOUT/scripts/allium-deploy-cfassets.sh" --promote
}

run_promote "$PINNED_SHA" >/dev/null
[[ -s "$MOCK_CALLS" ]] || fail "pinned checkout did not invoke Wrangler"
pass "pinned checkout remains deployable when origin advances mid-job"

: > "$MOCK_CALLS"
if run_promote "$ADVANCED_SHA" >/dev/null 2>&1; then
    fail "checkout accepted a different pinned SHA"
fi
[[ ! -s "$MOCK_CALLS" ]] || fail "mismatched pin invoked Wrangler"
pass "mismatched pinned SHA fails closed"

: > "$MOCK_CALLS"
if run_promote "" >/dev/null 2>&1; then
    fail "manual unpinned promotion accepted a stale checkout"
fi
[[ ! -s "$MOCK_CALLS" ]] || fail "stale unpinned checkout invoked Wrangler"
pass "manual unpinned promotion still requires current origin/main"

printf 'dirty\n' > "$CHECKOUT/untracked.txt"
: > "$MOCK_CALLS"
if run_promote "$PINNED_SHA" >/dev/null 2>&1; then
    fail "pinned promotion accepted a dirty checkout"
fi
[[ ! -s "$MOCK_CALLS" ]] || fail "dirty pinned checkout invoked Wrangler"
pass "pinned promotion still rejects working-tree changes"
