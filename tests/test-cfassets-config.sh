#!/usr/bin/env bash

set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

mkdir -p "$TMP_DIR/output/nested"
printf '<html>root</html>\n' > "$TMP_DIR/output/index.html"
printf '<html>nested</html>\n' > "$TMP_DIR/output/nested/index.html"
printf '{"meta":{"version":"1.6"},"relays":[]}\n' > "$TMP_DIR/output/search-index.json"

CF_ASSETS_REQUIRE_FRESH_CHECKOUT=false \
CF_ASSETS_WORKER_NAME=allium-shadow-test \
CF_ASSETS_PREVIEW_ALIAS=allium-test \
CF_ASSETS_CONFIG="$TMP_DIR/wrangler.assets.toml" \
OUTPUT_DIR="$TMP_DIR/output" \
    "$REPO_DIR/scripts/allium-deploy-cfassets.sh" --generate-only >/dev/null

[[ -f "$TMP_DIR/wrangler.assets.toml" ]] || fail "generated config exists"
grep -q 'name = "allium-shadow-test"' "$TMP_DIR/wrangler.assets.toml" || fail "worker name generated"
grep -q "directory = \"$TMP_DIR/output\"" "$TMP_DIR/wrangler.assets.toml" || fail "assets directory generated"
grep -q 'run_worker_first = \[ "/search", "/search/\*" \]' "$TMP_DIR/wrangler.assets.toml" || fail "search-only worker-first routes generated"
grep -q 'not_found_handling = "404-page"' "$TMP_DIR/wrangler.assets.toml" || fail "static 404 mode generated"
if grep -Eq '(^|[[:space:]])routes?[[:space:]]*=|custom_domain[[:space:]]*=' "$TMP_DIR/wrangler.assets.toml"; then
    fail "shadow config contains production routing"
fi
grep -q 'X-Robots-Tag: noindex, nofollow' "$TMP_DIR/output/_headers" || fail "preview noindex headers installed"
grep -q 'The requested Allium metrics page does not exist' "$TMP_DIR/output/404.html" || fail "custom 404 installed"
pass "route-free shadow config and headers are generated"

touch "$TMP_DIR/overlay-preparation-marker"
sleep 1
CF_ASSETS_REQUIRE_FRESH_CHECKOUT=false \
CF_ASSETS_WORKER_NAME=allium-shadow-test \
CF_ASSETS_PREVIEW_ALIAS=allium-test \
CF_ASSETS_CONFIG="$TMP_DIR/wrangler.assets.toml" \
OUTPUT_DIR="$TMP_DIR/output" \
    "$REPO_DIR/scripts/allium-deploy-cfassets.sh" --generate-only >/dev/null
[[ ! "$TMP_DIR/output/_headers" -nt "$TMP_DIR/overlay-preparation-marker" ]] || \
    fail "unchanged headers overlay was rewritten"
[[ ! "$TMP_DIR/output/404.html" -nt "$TMP_DIR/overlay-preparation-marker" ]] || \
    fail "unchanged 404 overlay was rewritten"
pass "repeated overlay preparation is idempotent"

mkdir -p "$TMP_DIR/explicit-output"
printf '<html>explicit root</html>\n' > "$TMP_DIR/explicit-output/index.html"
printf '{"meta":{"version":"1.6"},"relays":[]}\n' > "$TMP_DIR/explicit-output/search-index.json"

CF_ASSETS_REQUIRE_FRESH_CHECKOUT=false \
CF_ASSETS_WORKER_NAME=allium-shadow-test \
CF_ASSETS_PREVIEW_ALIAS=allium-test \
CF_ASSETS_CONFIG="$TMP_DIR/wrangler.explicit.toml" \
CF_ASSETS_DIRECTORY="$TMP_DIR/explicit-output" \
OUTPUT_DIR="$TMP_DIR/output" \
    "$REPO_DIR/scripts/allium-deploy-cfassets.sh" --generate-only >/dev/null

grep -q "directory = \"$TMP_DIR/explicit-output\"" "$TMP_DIR/wrangler.explicit.toml" || \
    fail "explicit assets directory did not override OUTPUT_DIR"
grep -q 'X-Robots-Tag: noindex, nofollow' "$TMP_DIR/explicit-output/_headers" || \
    fail "headers were not installed in explicit assets directory"
pass "explicit assets directory overrides the production output default"

set +e
CF_ASSETS_REQUIRE_FRESH_CHECKOUT=false \
CF_ASSETS_ALLOW_PROMOTION=false \
CF_ASSETS_CONFIG="$TMP_DIR/wrangler.assets.toml" \
OUTPUT_DIR="$TMP_DIR/output" \
    "$REPO_DIR/scripts/allium-deploy-cfassets.sh" --promote >/dev/null 2>&1
status=$?
set -e
[[ "$status" -eq 3 ]] || fail "promotion guard returned $status instead of 3"
pass "promotion is refused while Stage 3 is disabled"
