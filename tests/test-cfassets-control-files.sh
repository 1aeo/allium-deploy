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

# Run a copy of the deploy script with a fake config.env, so a deployed
# config.env in this checkout can never point the test at a real output tree.
DEPLOY_DIR="$TMP_DIR/deploy"
OUTPUT_DIR="$TMP_DIR/output"
MOCK_BIN="$TMP_DIR/mock-bin"
SEEN_FILE="$TMP_DIR/control-files-seen-by-wrangler"
FINGERPRINT='DB1629B59707F744A0C7933E56B6802786FFC317'
VERSION_ID='12345678-1234-4234-8234-123456789abc'
VERSION_PREVIEW='https://12345678-allium-shadow-test.test.workers.dev'
mkdir -p "$DEPLOY_DIR/scripts" "$DEPLOY_DIR/cloudflare-assets" "$MOCK_BIN" "$TMP_DIR/home" \
    "$OUTPUT_DIR/nested" "$OUTPUT_DIR/static" "$OUTPUT_DIR/relay/$FINGERPRINT"
cp "$REPO_DIR/scripts/allium-deploy-cfassets.sh" "$REPO_DIR/scripts/allium-deploy-lib.sh" "$DEPLOY_DIR/scripts/"
cp "$REPO_DIR/wrangler.assets.toml.template" "$DEPLOY_DIR/"
cp "$REPO_DIR/cloudflare-assets/_headers" "$REPO_DIR/cloudflare-assets/404.html" "$DEPLOY_DIR/cloudflare-assets/"
cat > "$DEPLOY_DIR/config.env" <<EOF
OUTPUT_DIR="$OUTPUT_DIR"
CF_ASSETS_ENABLED=true
CF_ASSETS_REQUIRE_FRESH_CHECKOUT=false
CF_ASSETS_WORKER_NAME=allium-shadow-test
CF_ASSETS_PREVIEW_ALIAS=allium-test
CF_ASSETS_VERIFY_SCRIPT="$MOCK_BIN/verify"
CF_ASSETS_UPLOAD_MAX_ATTEMPTS=1
CF_ASSETS_UPLOAD_RETRY_DELAY=0
WRANGLER_LOG_PATH="$TMP_DIR/wrangler-debug.log"
EOF

printf '<html>root</html>\n' > "$OUTPUT_DIR/index.html"
printf '<html>nested</html>\n' > "$OUTPUT_DIR/nested/index.html"
printf '{"meta":{"version":"1.6"},"relays":[]}\n' > "$OUTPUT_DIR/search-index.json"
printf 'png bandwidth\n' > "$OUTPUT_DIR/relay/$FINGERPRINT/bandwidth-1m.png"
# Only the root files are read as configuration; a nested one is an asset.
printf 'ordinary nested asset\n' > "$OUTPUT_DIR/static/_redirects"

# Wrangler fixture: records which root control files exist when the upload
# reads the tree, then reports one structured version.
cat > "$MOCK_BIN/pnpm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for name in .assetsignore _redirects; do
    if [[ -e "$MOCK_ASSETS_DIR/$name" || -L "$MOCK_ASSETS_DIR/$name" ]]; then
        printf '%s\n' "$name" >> "$MOCK_SEEN_FILE"
    fi
done
printf '{"type":"version-upload","version":1,"version_id":"%s","preview_url":"%s"}\n' \
    "$MOCK_VERSION_ID" "$MOCK_VERSION_PREVIEW" >> "$WRANGLER_OUTPUT_FILE_PATH"
EOF
printf '#!/usr/bin/env bash\nexit 0\n' > "$MOCK_BIN/verify"
# Keep the test portable on macOS, where BSD du does not implement -b.
cat > "$MOCK_BIN/du" <<'EOF'
#!/usr/bin/env bash
printf '4096\t%s\n' "${@: -1}"
EOF
chmod 0755 "$MOCK_BIN/pnpm" "$MOCK_BIN/verify" "$MOCK_BIN/du"

# run_cfassets <mode>: sets RUN_OUTPUT and RUN_STATUS. The environment holds
# only PATH, HOME and the fixtures' variables, so the assets directory and
# every other setting come from the fake config.env, as in production.
run_cfassets() {
    set +e
    RUN_OUTPUT=$(env -i \
        HOME="$TMP_DIR/home" \
        PATH="$MOCK_BIN:$PATH" \
        CLOUDFLARE_API_TOKEN=test-token \
        MOCK_ASSETS_DIR="$OUTPUT_DIR" \
        MOCK_SEEN_FILE="$SEEN_FILE" \
        MOCK_VERSION_ID="$VERSION_ID" \
        MOCK_VERSION_PREVIEW="$VERSION_PREVIEW" \
        "$DEPLOY_DIR/scripts/allium-deploy-cfassets.sh" "$1" 2>&1)
    RUN_STATUS=$?
    set -e
}

# write_stale_control_files: what reverted deploy code could leave behind.
write_stale_control_files() {
    printf '%s\n' '/relay/*/*.png' '/contact/*/*.png' > "$OUTPUT_DIR/.assetsignore"
    printf '%s\n' '/relay/:fp/:name.png /charts/relay/:fp/:name.png 302' > "$OUTPUT_DIR/_redirects"
}

run_cfassets --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "generation of a clean tree exited $RUN_STATUS: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" != *'removed stale'* ]] || fail "a clean tree logged a removal: $RUN_OUTPUT"
cp "$DEPLOY_DIR/wrangler.assets.toml" "$TMP_DIR/clean-config.toml"
pass "a tree without control files generates without removing anything"

write_stale_control_files
run_cfassets --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "generation with stale control files exited $RUN_STATUS: $RUN_OUTPUT"
[[ ! -e "$OUTPUT_DIR/.assetsignore" ]] || fail "stale .assetsignore survived generation"
[[ ! -e "$OUTPUT_DIR/_redirects" ]] || fail "stale _redirects survived generation"
[[ "$RUN_OUTPUT" == *"removed stale .assetsignore from $OUTPUT_DIR"* ]] || fail "removing .assetsignore was not logged: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *"removed stale _redirects from $OUTPUT_DIR"* ]] || fail "removing _redirects was not logged: $RUN_OUTPUT"
[[ -f "$OUTPUT_DIR/static/_redirects" ]] || fail "a nested asset named _redirects was removed"
[[ -f "$OUTPUT_DIR/relay/$FINGERPRINT/bandwidth-1m.png" ]] || fail "a chart was removed"
cmp -s "$TMP_DIR/clean-config.toml" "$DEPLOY_DIR/wrangler.assets.toml" \
    || fail "the rendered config changed while removing stale control files"
pass "stale root .assetsignore and _redirects in OUTPUT_DIR are removed and logged"

printf 'outside the tree\n' > "$TMP_DIR/link-target"
ln -s "$TMP_DIR/link-target" "$OUTPUT_DIR/.assetsignore"
ln -s "$TMP_DIR/missing-target" "$OUTPUT_DIR/_redirects"
run_cfassets --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "generation with control-file symlinks exited $RUN_STATUS: $RUN_OUTPUT"
[[ ! -L "$OUTPUT_DIR/.assetsignore" && ! -L "$OUTPUT_DIR/_redirects" ]] || fail "a control-file symlink survived generation"
[[ -f "$TMP_DIR/link-target" ]] || fail "removing a symlink deleted its target"
pass "control-file symlinks, including dangling ones, are removed without touching their targets"

mkdir "$OUTPUT_DIR/_redirects"
run_cfassets --generate-only
[[ "$RUN_STATUS" != 0 ]] || fail "a _redirects directory was accepted"
[[ "$RUN_OUTPUT" == *"could not remove stale _redirects from $OUTPUT_DIR"* ]] || fail "the failed removal was not logged: $RUN_OUTPUT"
rmdir "$OUTPUT_DIR/_redirects"
pass "a control file that cannot be removed fails generation closed"

# The upload regenerates the overlay itself, so Wrangler never reads a stale
# control file even when the separate preparation step did not run.
write_stale_control_files
: > "$SEEN_FILE"
run_cfassets --upload-only
[[ "$RUN_STATUS" == 0 ]] || fail "upload with stale control files exited $RUN_STATUS: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *'removed stale .assetsignore'* && "$RUN_OUTPUT" == *'removed stale _redirects'* ]] \
    || fail "the upload did not log the removals: $RUN_OUTPUT"
[[ ! -s "$SEEN_FILE" ]] || fail "Wrangler read stale control files: $(tr '\n' ' ' < "$SEEN_FILE")"
[[ "$(cat "$DEPLOY_DIR/logs/cfassets-last-version")" == "$VERSION_ID" ]] || fail "the upload did not record its version"
pass "an upload removes stale control files before Wrangler reads the tree"
