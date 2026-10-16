#!/usr/bin/env bash
# CHARTS_LAYOUT on the main Worker's side: beside (the default) generates and
# uploads exactly as before and removes a charts/ tree that layout does not
# use; charts refuses a tree that is not in that layout, installs the
# deploy-owned .assetsignore and _redirects, which switching back removes,
# requires both or neither, leaves the rendered config unchanged and drops
# charts/ from the file-count guard and the upload summary. Also: the mirrors
# never copy the control files, the rendered configs are gitignored, Allium's
# arguments, the job's settings snapshot and its checks before Allium runs.
# Copies of the scripts run in a temporary deploy directory with a fake
# config.env and a Wrangler fixture.

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

DEPLOY_DIR="$TMP_DIR/deploy"
OUTPUT_DIR="$TMP_DIR/output"
MOCK_BIN="$TMP_DIR/mock-bin"
EVENTS="$TMP_DIR/events"
FP='DB1629B59707F744A0C7933E56B6802786FFC317'
mkdir -p "$DEPLOY_DIR/scripts" "$DEPLOY_DIR/cloudflare-assets" "$MOCK_BIN" "$TMP_DIR/home" \
    "$OUTPUT_DIR/relay/$FP" "$OUTPUT_DIR/static"
cp "$REPO_DIR/scripts/allium-deploy-cfassets.sh" "$REPO_DIR/scripts/allium-deploy-lib.sh" "$DEPLOY_DIR/scripts/"
cp "$REPO_DIR/wrangler.assets.toml.template" "$DEPLOY_DIR/"
cp "$REPO_DIR/cloudflare-assets/_headers" "$REPO_DIR/cloudflare-assets/404.html" \
    "$REPO_DIR/cloudflare-assets/.assetsignore.charts" "$REPO_DIR/cloudflare-assets/_redirects.charts" \
    "$DEPLOY_DIR/cloudflare-assets/"

printf '<html>root</html>\n' > "$OUTPUT_DIR/index.html"
printf '<html>relay</html>\n' > "$OUTPUT_DIR/relay/$FP/index.html"
printf '{"meta":{"version":"1.6"},"relays":[]}\n' > "$OUTPUT_DIR/search-index.json"
printf 'ordinary nested asset\n' > "$OUTPUT_DIR/static/_redirects"

# use_layout <beside|charts>: the relay's two charts where Allium writes them
# in that layout, next to the page or below charts/.
use_layout() {
    local dir="$OUTPUT_DIR/relay/$FP"
    rm -rf "$OUTPUT_DIR/charts" "$dir"/*.png
    [[ "$1" == beside ]] || dir="$OUTPUT_DIR/charts/relay/$FP"
    mkdir -p "$dir"
    printf 'png bandwidth\n' > "$dir/bandwidth-1m.png"
    printf 'png uptime\n' > "$dir/uptime-6m.png"
}
use_layout beside

# Wrangler fixture: records which root control files exist and how many files
# the tree holds when the upload reads it, then reports one version.
cat > "$MOCK_BIN/pnpm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$3 $4" != "versions upload" ]]; then
    printf 'wrangler %s %s\n' "$3" "$4" >> "$MOCK_EVENTS"
    exit 0
fi
seen=""
for name in .assetsignore _redirects; do
    if [[ -e "$MOCK_ASSETS_DIR/$name" ]]; then
        seen+=" $name"
    fi
done
printf 'upload control:%s\n' "${seen:- none}" >> "$MOCK_EVENTS"
printf '{"type":"version-upload","version":1,"version_id":"12345678-1234-4234-8234-123456789abc","preview_url":"https://12345678-allium-main-test.test.workers.dev"}\n' \
    >> "$WRANGLER_OUTPUT_FILE_PATH"
EOF
cat > "$MOCK_BIN/verify" <<'EOF'
#!/usr/bin/env bash
printf 'verify layout=%s%s\n' "${CHARTS_LAYOUT:-unset}" "${ALLIUM_NO_CHARTS:+ no_charts=$ALLIUM_NO_CHARTS}" >> "$MOCK_EVENTS"
EOF
# Keep the test portable on macOS, where BSD du does not implement -b.
cat > "$MOCK_BIN/du" <<'EOF'
#!/usr/bin/env bash
printf '4096\t%s\n' "${@: -1}"
EOF
# install shim: MOCK_SKIP_INSTALL names a file it pretends to install.
REAL_INSTALL=$(command -v install)
cat > "$MOCK_BIN/install" <<EOF
#!/usr/bin/env bash
if [[ -n "\${MOCK_SKIP_INSTALL:-}" && "\${*: -1}" == */"\$MOCK_SKIP_INSTALL" ]]; then
    exit 0
fi
exec "$REAL_INSTALL" "\$@"
EOF
chmod 0755 "$MOCK_BIN"/*

# write_config [extra config.env lines...]
write_config() {
    {
        printf 'OUTPUT_DIR="%s"\n' "$OUTPUT_DIR"
        printf 'CF_ASSETS_VERIFY_SCRIPT="%s"\n' "$MOCK_BIN/verify"
        printf 'WRANGLER_LOG_PATH="%s"\n' "$TMP_DIR/wrangler-debug.log"
        printf '%s\n' \
            CF_ASSETS_ENABLED=true \
            CF_ASSETS_REQUIRE_FRESH_CHECKOUT=false \
            CF_ASSETS_WORKER_NAME=allium-main-test \
            CF_ASSETS_PREVIEW_ALIAS=allium-test \
            CF_ASSETS_UPLOAD_MAX_ATTEMPTS=1
        printf '%s\n' "$@"
    } > "$DEPLOY_DIR/config.env"
}

# run_cfassets <mode> [NAME=value...]: sets RUN_OUTPUT and RUN_STATUS.
run_cfassets() {
    local mode="$1"
    shift
    set +e
    RUN_OUTPUT=$(env -i HOME="$TMP_DIR/home" PATH="$MOCK_BIN:$PATH" CLOUDFLARE_API_TOKEN=test-token \
        MOCK_ASSETS_DIR="$OUTPUT_DIR" MOCK_EVENTS="$EVENTS" "$@" \
        "$DEPLOY_DIR/scripts/allium-deploy-cfassets.sh" "$mode" 2>&1)
    RUN_STATUS=$?
    set -e
}

CONFIG="$DEPLOY_DIR/wrangler.assets.toml"
IGNORE_FILE="$OUTPUT_DIR/.assetsignore"
REDIRECTS_FILE="$OUTPUT_DIR/_redirects"
sed -e 's|{{CF_ASSETS_WORKER_NAME}}|allium-main-test|g' \
    -e 's|{{CF_ASSETS_COMPATIBILITY_DATE}}|2026-07-26|g' \
    -e "s|{{CF_ASSETS_DIRECTORY}}|$OUTPUT_DIR|g" \
    "$REPO_DIR/wrangler.assets.toml.template" > "$TMP_DIR/expected.toml"

# beside, set or not: the template rendered unchanged, no control file, and
# the generation logs exactly what it logged before.
for setting in '' CHARTS_LAYOUT=beside; do
    write_config "$setting"
    run_cfassets --generate-only
    [[ "$RUN_STATUS" == 0 ]] || fail "generation with '$setting' exited $RUN_STATUS: $RUN_OUTPUT"
    cmp -s "$TMP_DIR/expected.toml" "$CONFIG" || fail "'$setting' did not render the template unchanged"
    [[ ! -e "$IGNORE_FILE" && ! -e "$REDIRECTS_FILE" ]] || fail "'$setting' wrote a control file"
    [[ "$RUN_OUTPUT" == $'[CF-Assets] generated route-free config: '"$CONFIG"$'\n[CF-Assets] generate-only complete; no Cloudflare API call was made' ]] \
        || fail "'$setting' logged something new: $RUN_OUTPUT"
done
: > "$EVENTS"
run_cfassets --upload-only
[[ "$RUN_STATUS" == 0 && "$(cat "$EVENTS")" == $'upload control: none\nverify layout=beside no_charts=false' ]] \
    || fail "a beside upload: $RUN_STATUS $(cat "$EVENTS") $RUN_OUTPUT"
pass "with CHARTS_LAYOUT=beside the config, the tree and the log are as before, and the upload sees no control file"

# The update job of the previous release runs these scripts once, in the run
# that pulls them: it exports none of the chart layout settings, and its
# config.env has none. Its three calls work as before: no control file, no
# charts stage, the beside verifier and one promotion.
write_config CF_ASSETS_ALLOW_PROMOTION=true
rm -rf "$DEPLOY_DIR/logs"
: > "$EVENTS"
for mode in --generate-only --upload-only --promote; do
    run_cfassets "$mode" WRANGLER_LOG=error WRANGLER_LOG_PATH="$TMP_DIR/wrangler-debug.log" WRANGLER_LOG_SANITIZE=true
    [[ "$RUN_STATUS" == 0 ]] || fail "the previous update job's $mode exited $RUN_STATUS: $RUN_OUTPUT"
done
[[ "$(cat "$EVENTS")" == $'upload control: none\nverify layout=beside no_charts=false\nwrangler versions deploy' ]] \
    || fail "the previous update job's calls: $(cat "$EVENTS")"
[[ ! -e "$IGNORE_FILE" && ! -e "$REDIRECTS_FILE" && ! -e "$OUTPUT_DIR-charts-stage" && ! -e "$DEPLOY_DIR/logs/charts-layout-promoted" ]] \
    || fail "the previous update job's calls wrote chart layout files"
[[ "$(tail -n 1 "$DEPLOY_DIR/logs/cfassets-promotion-summary.tsv" | cut -f3)" == 0 ]] || fail "the previous update job's promotion was not recorded"
pass "the previous release's update job, which exports no chart layout setting, generates, uploads and promotes as before"

# charts needs a tree in that layout: a chart beside its page (Allium ran
# without --chart-layout charts, for example in a job that started before the
# switch), or no chart below charts/, stops the generation before any control
# file or upload.
write_config CHARTS_LAYOUT=charts
for tree in beside none; do
    use_layout beside
    [[ "$tree" == beside ]] || rm "$OUTPUT_DIR/relay/$FP"/*.png
    : > "$EVENTS"
    run_cfassets --upload-only
    [[ "$RUN_STATUS" == 1 && ! -s "$EVENTS" && ! -e "$IGNORE_FILE" && ! -e "$REDIRECTS_FILE" ]] \
        || fail "a $tree tree passed the charts layout: $RUN_STATUS $(cat "$EVENTS") $RUN_OUTPUT"
done
[[ "$RUN_OUTPUT" == *"refusing config: CHARTS_LAYOUT=charts, but $OUTPUT_DIR has no chart PNG below charts/relay or charts/contact"* ]] \
    || fail "a tree without charts was not explained: $RUN_OUTPUT"
use_layout beside
run_cfassets --promote CF_ASSETS_ALLOW_PROMOTION=true
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"refusing config: CHARTS_LAYOUT=charts, but $OUTPUT_DIR/relay/$FP/"*".png is beside its page"* ]] \
    || fail "a beside tree was promoted in the charts layout: $RUN_STATUS $RUN_OUTPUT"
use_layout charts
mkdir -p "$OUTPUT_DIR/relay/$FP/sub"
printf 'not a chart\n' > "$OUTPUT_DIR/relay/$FP/sub/deep.png"
printf 'not a chart\n' > "$OUTPUT_DIR/relay/top.png"
run_cfassets --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "PNGs that are not charts beside the pages were refused: $RUN_OUTPUT"
rm -r "$OUTPUT_DIR/relay/$FP/sub" "$OUTPUT_DIR/relay/top.png"
# Allium with --no-charts (ALLIUM_NO_CHARTS=true, which the job exports)
# writes no chart: the tree needs none below charts/, still none beside the
# pages, and the verifier is told.
rm -r "$OUTPUT_DIR/charts"
: > "$EVENTS"
run_cfassets --upload-only ALLIUM_NO_CHARTS=true
[[ "$RUN_STATUS" == 0 && "$(cat "$EVENTS")" == $'upload control: .assetsignore _redirects\nverify layout=charts no_charts=true' ]] \
    || fail "a charts tree without charts and ALLIUM_NO_CHARTS=true: $RUN_STATUS $(cat "$EVENTS") $RUN_OUTPUT"
use_layout beside
run_cfassets --generate-only ALLIUM_NO_CHARTS=true
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'is beside its page'* ]] || fail "ALLIUM_NO_CHARTS=true let a chart beside its page through: $RUN_OUTPUT"
run_cfassets --generate-only ALLIUM_NO_CHARTS=maybe
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'invalid ALLIUM_NO_CHARTS=maybe'* ]] || fail "an invalid ALLIUM_NO_CHARTS was accepted: $RUN_OUTPUT"
use_layout charts
pass "the charts layout refuses a tree with charts beside their pages or, unless ALLIUM_NO_CHARTS=true, none below charts/"

# charts: both control files, byte for byte the tracked sources; the same
# rendered config.
rm -f "$IGNORE_FILE" "$REDIRECTS_FILE"
run_cfassets --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "charts generation exited $RUN_STATUS: $RUN_OUTPUT"
cmp -s "$REPO_DIR/cloudflare-assets/.assetsignore.charts" "$IGNORE_FILE" || fail "unexpected .assetsignore: $(cat "$IGNORE_FILE" 2>/dev/null)"
cmp -s "$REPO_DIR/cloudflare-assets/_redirects.charts" "$REDIRECTS_FILE" || fail "unexpected _redirects: $(cat "$REDIRECTS_FILE" 2>/dev/null)"
cmp -s "$TMP_DIR/expected.toml" "$CONFIG" || fail "the charts layout changed the rendered config: $(diff "$TMP_DIR/expected.toml" "$CONFIG")"
[[ "$RUN_OUTPUT" != *'removed stale'* ]] || fail "the charts layout removed its own control files: $RUN_OUTPUT"
[[ "$(grep -v '^#' "$IGNORE_FILE")" == '/charts/' ]] || fail ".assetsignore drops more than /charts/"
[[ "$(grep -v '^#' "$REDIRECTS_FILE")" == $'/relay/:fp/:name.png /charts/relay/:fp/:name.png 302\n/contact/:hash/:name.png /charts/contact/:hash/:name.png 302' ]] \
    || fail "_redirects holds other rules: $(grep -v '^#' "$REDIRECTS_FILE")"
: > "$EVENTS"
run_cfassets --upload-only
[[ "$RUN_STATUS" == 0 && "$(cat "$EVENTS")" == $'upload control: .assetsignore _redirects\nverify layout=charts no_charts=false' ]] \
    || fail "a charts upload: $RUN_STATUS $(cat "$EVENTS") $RUN_OUTPUT"
touch "$TMP_DIR/marker"
sleep 1
run_cfassets --generate-only
[[ ! "$IGNORE_FILE" -nt "$TMP_DIR/marker" && ! "$REDIRECTS_FILE" -nt "$TMP_DIR/marker" ]] || fail "unchanged control files were rewritten"
pass "with CHARTS_LAYOUT=charts the deploy writes .assetsignore (/charts/) and the two _redirects rules, keeps the config, and tells the verifier"

# The job's exported layout wins over config.env, as for every override.
write_config CHARTS_LAYOUT=beside
run_cfassets --generate-only CHARTS_LAYOUT=charts
[[ "$RUN_STATUS" == 0 && -f "$IGNORE_FILE" && -f "$REDIRECTS_FILE" ]] || fail "an exported CHARTS_LAYOUT did not win over config.env"
pass "an exported CHARTS_LAYOUT overrides config.env, so one job uses one layout"

# Edited, symlinked or missing control files are replaced; a directory fails.
write_config CHARTS_LAYOUT=charts
printf '/everything\n' > "$IGNORE_FILE"
printf 'outside the tree\n' > "$TMP_DIR/link-target"
rm "$REDIRECTS_FILE"
ln -s "$TMP_DIR/link-target" "$REDIRECTS_FILE"
run_cfassets --generate-only
[[ "$RUN_STATUS" == 0 && ! -L "$REDIRECTS_FILE" ]] || fail "edited or linked control files were not replaced: $RUN_OUTPUT"
cmp -s "$REPO_DIR/cloudflare-assets/.assetsignore.charts" "$IGNORE_FILE" || fail "an edited .assetsignore survived"
cmp -s "$REPO_DIR/cloudflare-assets/_redirects.charts" "$REDIRECTS_FILE" || fail "a linked _redirects survived"
[[ "$(cat "$TMP_DIR/link-target")" == 'outside the tree' ]] || fail "a symlink target was written through"
rm "$REDIRECTS_FILE"
mkdir "$REDIRECTS_FILE"
run_cfassets --generate-only
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"could not replace $REDIRECTS_FILE"* ]] || fail "a _redirects directory was accepted: $RUN_OUTPUT"
rmdir "$REDIRECTS_FILE"
pass "edited or symlinked control files are replaced without writing through, and a directory fails closed"

# Both or neither: a control file that did not get installed stops the
# generation before any upload.
for skipped in .assetsignore _redirects; do
    rm -f "$IGNORE_FILE" "$REDIRECTS_FILE"
    : > "$EVENTS"
    run_cfassets --upload-only MOCK_SKIP_INSTALL="$skipped"
    [[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"refusing config: $OUTPUT_DIR/$skipped is not the CHARTS_LAYOUT=charts $skipped"* ]] \
        || fail "a missing $skipped was accepted: $RUN_STATUS $RUN_OUTPUT"
    [[ ! -s "$EVENTS" ]] || fail "Wrangler ran without $skipped"
done
run_cfassets --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "regeneration exited $RUN_STATUS"
pass "the charts layout requires both control files before an upload"

# Switching back to beside removes both control files, logged, and leaves
# nested names. An Allium without --chart-layout writes the charts beside the
# pages but leaves charts/relay and charts/contact: they go too, and charts/
# with them once it is empty.
use_layout beside
mkdir -p "$OUTPUT_DIR/charts/relay/$FP" "$OUTPUT_DIR/charts/contact/c1"
printf 'old\n' > "$OUTPUT_DIR/charts/relay/$FP/bandwidth-1m.png"
printf 'old\n' > "$OUTPUT_DIR/charts/contact/c1/bandwidth-1y.png"
write_config CHARTS_LAYOUT=beside
run_cfassets --generate-only
[[ "$RUN_STATUS" == 0 && ! -e "$IGNORE_FILE" && ! -e "$REDIRECTS_FILE" ]] || fail "switching back left a control file: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *"removed stale .assetsignore from $OUTPUT_DIR: CHARTS_LAYOUT=beside does not use it"* \
    && "$RUN_OUTPUT" == *"removed stale _redirects from $OUTPUT_DIR: CHARTS_LAYOUT=beside does not use it"* ]] \
    || fail "the removals were not logged: $RUN_OUTPUT"
[[ ! -e "$OUTPUT_DIR/charts" && -f "$OUTPUT_DIR/relay/$FP/bandwidth-1m.png" ]] || fail "switching back kept the charts/ tree or lost a chart"
for kind in relay contact; do
    [[ "$RUN_OUTPUT" == *"removed the leftover charts/$kind from $OUTPUT_DIR: CHARTS_LAYOUT=beside does not use it"* ]] \
        || fail "the removal of charts/$kind was not logged: $RUN_OUTPUT"
done
[[ -f "$OUTPUT_DIR/static/_redirects" ]] || fail "a nested _redirects was removed"
cmp -s "$TMP_DIR/expected.toml" "$CONFIG" || fail "switching back changed the config"
mkdir -p "$OUTPUT_DIR/charts/relay/$FP"
printf 'old\n' > "$OUTPUT_DIR/charts/relay/$FP/bandwidth-1m.png"
printf 'not Allium\n' > "$OUTPUT_DIR/charts/notes.txt"
run_cfassets --generate-only
[[ "$RUN_STATUS" == 0 && ! -e "$OUTPUT_DIR/charts/relay" && -f "$OUTPUT_DIR/charts/notes.txt" ]] \
    || fail "the leftover removal went beyond charts/relay and charts/contact: $RUN_OUTPUT"
rm -r "$OUTPUT_DIR/charts"
mkdir -p "$TMP_DIR/elsewhere/relay"
printf 'keep\n' > "$TMP_DIR/elsewhere/relay/kept.png"
ln -s "$TMP_DIR/elsewhere" "$OUTPUT_DIR/charts"
run_cfassets --generate-only
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"refusing config: $OUTPUT_DIR/charts is a symbolic link"* && -f "$TMP_DIR/elsewhere/relay/kept.png" ]] \
    || fail "a symbolic link charts/ was followed or accepted: $RUN_STATUS $RUN_OUTPUT"
rm "$OUTPUT_DIR/charts"
write_config CHARTS_LAYOUT=split
run_cfassets --generate-only
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'invalid CHARTS_LAYOUT=split'* ]] || fail "an invalid layout was accepted: $RUN_OUTPUT"
pass "switching back to beside removes both control files and a leftover charts/relay and charts/contact, and an invalid layout is refused"

# File-count guard, in the preparation and before the upload. The main Worker
# uploads every file but the root control files; with the charts layout also
# not charts/. 404.html and the nested _redirects count.
for case in \
    'CHARTS_LAYOUT=beside|7|; CHARTS_LAYOUT=charts moves' \
    'CHARTS_LAYOUT=charts|5|'; do
    IFS='|' read -r layout count hint <<< "$case"
    use_layout "${layout#CHARTS_LAYOUT=}"
    write_config "$layout" "CF_ASSETS_MAX_FILES=$((count - 1))"
    # The preparation refuses already, and that breaks the streak.
    mkdir -p "$DEPLOY_DIR/logs"
    printf '5\n' > "$DEPLOY_DIR/logs/cfassets-shadow-consecutive-successes"
    run_cfassets --generate-only
    [[ "$RUN_STATUS" == 4 && "$RUN_OUTPUT" == *"refusing upload: $count files exceed the limit of $((count - 1)) files per Worker version$hint"* ]] \
        || fail "$layout: the preparation accepted $count files over the limit: $RUN_STATUS $RUN_OUTPUT"
    [[ "$(cat "$DEPLOY_DIR/logs/cfassets-shadow-consecutive-successes")" == 0 ]] || fail "$layout: a refused preparation kept the streak"
    : > "$EVENTS"
    run_cfassets --upload-only
    [[ "$RUN_STATUS" == 4 && "$RUN_OUTPUT" == *"refusing upload: $count files exceed the limit of $((count - 1)) files per Worker version$hint"* ]] \
        || fail "$layout: $count files over the limit: $RUN_STATUS $RUN_OUTPUT"
    [[ ! -s "$EVENTS" ]] || fail "$layout: the guard did not stop the upload"
    write_config "$layout" "CF_ASSETS_MAX_FILES=$count" "CF_ASSETS_WARN_FILES=$count"
    run_cfassets --upload-only
    [[ "$RUN_STATUS" == 0 && "$RUN_OUTPUT" == *"warning: $count files approach the limit of $count"* ]] \
        || fail "$layout: no warning at the limit: $RUN_STATUS $RUN_OUTPUT"
    IFS=$'\t' read -r _ worker _ status files _ <<< "$(tail -n 1 "$DEPLOY_DIR/logs/cfassets-uploads.tsv")"
    [[ "$worker $status $files" == "allium-main-test 0 $count" ]] || fail "$layout: unexpected upload summary row"
    # The shadow summary's file_count is the same count.
    [[ "$(tail -n 1 "$DEPLOY_DIR/logs/cfassets-shadow-summary.tsv" | cut -f4)" == "$count" ]] \
        || fail "$layout: the shadow summary does not count the version's $count files: $(tail -n 1 "$DEPLOY_DIR/logs/cfassets-shadow-summary.tsv")"
done
use_layout beside
write_config CF_ASSETS_WARN_FILES=many
run_cfassets --generate-only
[[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'invalid CF_ASSETS_WARN_FILES=many'* ]] || fail "an invalid warning level was accepted"
write_config
run_cfassets --upload-only
[[ "$RUN_STATUS" == 0 && "$RUN_OUTPUT" != *'approach the limit'* ]] || fail "the default warning level fired for 7 files"
# The default warning level: 98000 files, or 60000 for the main Worker in the
# charts layout, which leaves the charts to the other Worker. Here the main
# Worker uploads 60000 files in either layout.
mkdir -p "$OUTPUT_DIR/many"
(cd "$OUTPUT_DIR/many" && seq 1 59995 | xargs touch)
for layout in beside charts; do
    use_layout "$layout"
    write_config "CHARTS_LAYOUT=$layout"
    run_cfassets --generate-only
    [[ "$RUN_STATUS" == 0 ]] || fail "$layout generation with 60000 files: $RUN_OUTPUT"
    run_cfassets --upload-only
    [[ "$RUN_STATUS" == 0 ]] || fail "$layout upload of 60000 files: $RUN_OUTPUT"
    if [[ "$layout" == charts ]]; then
        [[ "$RUN_OUTPUT" == *'warning: 60000 files approach the limit of 100000'* ]] || fail "the charts layout's main Worker did not warn at 60000 files: $RUN_OUTPUT"
    else
        [[ "$RUN_OUTPUT" != *'approach the limit'* ]] || fail "the beside layout warned below 98000 files: $RUN_OUTPUT"
    fi
done
rm -r "$OUTPUT_DIR/many"
use_layout beside
pass "the file-count guard and the shadow summary count what Wrangler uploads in either layout; the guard warns near the limit (by default 98000 files, 60000 for the main Worker in the charts layout) and refuses above it, already when the version is prepared"

# Mirrors: the root files the charts layout adds are exactly the two control
# files, and the DO and R2 syncs, the R2 size check and the Stage 4 size check
# exclude both.
write_config CHARTS_LAYOUT=beside
run_cfassets --generate-only
root_beside=$(cd "$OUTPUT_DIR" && find . -mindepth 1 -maxdepth 1 -type f | LC_ALL=C sort)
use_layout charts
write_config CHARTS_LAYOUT=charts
run_cfassets --generate-only
root_charts=$(cd "$OUTPUT_DIR" && find . -mindepth 1 -maxdepth 1 -type f | LC_ALL=C sort)
added=$(LC_ALL=C comm -13 <(printf '%s\n' "$root_beside") <(printf '%s\n' "$root_charts"))
[[ "$added" == $'./.assetsignore\n./_redirects' ]] || fail "the charts layout added unexpected root files: $added"
rclone_options=$(
    # shellcheck source=../scripts/allium-deploy-upload-common.sh
    source "$REPO_DIR/scripts/allium-deploy-upload-common.sh"
    TRANSFERS=4 CHECKERS=8 BUFFER_SIZE=16M S3_CONCURRENCY=2 S3_CHUNK=8M
    TPS_LIMIT=120 TPS_LIMIT_BURST=1 S3_DISABLE_HTTP2=false RCLONE_FAST_LIST=false
    build_rclone_opts
)
for name in .assetsignore _redirects; do
    [[ " $rclone_options " == *" --exclude=/$name "* ]] || fail "the DO and R2 syncs would mirror $name: $rclone_options"
    grep -Fq -- "--exclude \"/$name\"" "$REPO_DIR/scripts/allium-deploy-upload-r2.sh" || fail "the R2 size check would count $name"
    grep -Fq -- "--exclude '/$name'" "$REPO_DIR/scripts/run-stage4-24h-acceptance.sh" || fail "the Stage 4 size check would count $name"
done
pass "the mirrors exclude both root control files the charts layout adds"

# The main and charts uploads run together, and each requires a checkout
# without unignored files while the other may be rendering its config.
git init -q "$TMP_DIR/checkout"
cp "$REPO_DIR/.gitignore" "$TMP_DIR/checkout/"
for name in wrangler.assets.toml wrangler.charts.toml wrangler.assets.toml.tmp wrangler.charts.toml.tmp; do
    git -C "$TMP_DIR/checkout" check-ignore -q "$name" || fail "$name is not gitignored"
done
for name in wrangler.assets.toml.template wrangler.charts.toml.template; do
    ! git -C "$TMP_DIR/checkout" check-ignore -q "$name" || fail "$name is gitignored"
done
pass "the rendered Worker configs and their temporary renderings never make the checkout unclean"

# allium-deploy-update.sh: Allium's arguments, the job's snapshot and its
# checks before Allium runs.
export ALLIUM_DEPLOY_TEST_MODE=1
allium_arguments() (
    # shellcheck source=../scripts/allium-deploy-update.sh
    source "$REPO_DIR/scripts/allium-deploy-update.sh"
    CHARTS_LAYOUT="$1"
    OUTPUT_DIR=/out
    SITE_URL=https://metrics.example.org
    set_allium_arguments
    printf '%s\n' "${ALLIUM_ARGS[*]}"
)
[[ "$(allium_arguments beside)" == '--out /out --base-url https://metrics.example.org --progress' ]] \
    || fail "beside changed Allium's arguments: $(allium_arguments beside)"
[[ "$(allium_arguments charts)" == '--out /out --base-url https://metrics.example.org --progress --chart-layout charts --chart-format png' ]] \
    || fail "charts did not ask Allium for the charts layout and PNG charts: $(allium_arguments charts)"
[[ "$(ALLIUM_NO_CHARTS=true allium_arguments beside)" == '--out /out --base-url https://metrics.example.org --progress --no-charts' \
    && "$(ALLIUM_NO_CHARTS=true allium_arguments charts)" == *' --chart-layout charts --chart-format png --no-charts' ]] \
    || fail "ALLIUM_NO_CHARTS=true did not ask Allium for no charts"
# The snapshot leaves CF_ASSETS_ALLOW_PROMOTION out: each --promote reads it
# from config.env again (see tests/test-cfcharts-publish.sh).
snapshot=$(
    # shellcheck source=../scripts/allium-deploy-update.sh
    source "$REPO_DIR/scripts/allium-deploy-update.sh"
    CHARTS_LAYOUT=charts CF_CHARTS_WORKER_NAME=allium-charts-test CF_ASSETS_ENABLED=true CF_ASSETS_ALLOW_PROMOTION=true
    CF_CHARTS_ALLOW_STALE=true
    export_job_settings
    env | grep -E '^(CHARTS_LAYOUT|ALLIUM_NO_CHARTS|CF_CHARTS_WORKER_NAME|CF_ASSETS_ENABLED|CF_ASSETS_ALLOW_PROMOTION|CF_CHARTS_ALLOW_STALE)=' | LC_ALL=C sort
)
[[ "$snapshot" == $'ALLIUM_NO_CHARTS=false\nCF_ASSETS_ENABLED=true\nCF_CHARTS_WORKER_NAME=allium-charts-test\nCHARTS_LAYOUT=charts' ]] \
    || fail "the job did not export exactly its layout settings: $snapshot"
update_script=$(<"$REPO_DIR/scripts/allium-deploy-update.sh")
[[ "$update_script" == *$'\nassert_charts_layout\nexport_job_settings\ncheck_heartbeat_url\n\ntrap \'record_update_exit $?\' EXIT\n'* ]] \
    || fail "the job does not check and export its settings before it starts"
(
    # shellcheck source=../scripts/allium-deploy-update.sh
    source "$REPO_DIR/scripts/allium-deploy-update.sh"
    CHARTS_LAYOUT=both
    ! assert_charts_layout >/dev/null
) || fail "the job accepted CHARTS_LAYOUT=both"
pass "the job passes the charts layout to Allium with PNG charts, refuses an invalid layout, and exports its settings to the child scripts"

# The checks before Allium runs, with CHARTS_LAYOUT=charts: the charts Worker's
# settings (allium-deploy-cfcharts.sh --check-config), then an Allium with
# --chart-layout. An Allium pulled by this job without it, or whose --help
# fails, is set back for the build, with a heartbeat warning; one that was not
# pulled stops the job. The log says which of the two it was.
ALLIUM_GIT="$TMP_DIR/allium-repo"
mkdir -p "$ALLIUM_GIT"
git -C "$ALLIUM_GIT" init -q
commit_allium() {
    printf 'print("usage: allium.py [--out OUTPUT_DIR]%s")\n' "$1" > "$ALLIUM_GIT/allium.py"
    git -C "$ALLIUM_GIT" add allium.py
    git -C "$ALLIUM_GIT" -c user.name=test -c user.email=test@example.org commit -qm "$2"
    git -C "$ALLIUM_GIT" rev-parse HEAD
}
WITH_LAYOUT=$(commit_allium ' [--chart-layout {beside,charts}]' with)
WITHOUT_LAYOUT=$(commit_allium '' without)
# An Allium whose --help fails, as after a broken import.
printf 'import sys\nsys.exit("Traceback (most recent call last):\\nImportError: cannot import name x")\n' > "$ALLIUM_GIT/allium.py"
git -C "$ALLIUM_GIT" add allium.py
git -C "$ALLIUM_GIT" -c user.name=test -c user.email=test@example.org commit -qm broken
BROKEN=$(git -C "$ALLIUM_GIT" rev-parse HEAD)
cat > "$MOCK_BIN/cfcharts" <<EOF
#!/usr/bin/env bash
printf 'cfcharts %s\n' "\$1" >> "$EVENTS"
exit "\${MOCK_CHARTS_CONFIG_EXIT:-0}"
EOF
chmod 0755 "$MOCK_BIN/cfcharts"
# The heartbeat's curl, in its own directory: records the URL from its config
# and the body.
mkdir -p "$TMP_DIR/heartbeat-bin"
cat > "$TMP_DIR/heartbeat-bin/curl" <<EOF
#!/usr/bin/env bash
url=\$(sed -n 's/^url = "\(.*\)"\$/\1/p')
while (( \$# )); do
    [[ "\$1" != --data-raw ]] || printf 'ping %s %s\n' "\$url" "\$2" >> "$EVENTS"
    shift
done
EOF
chmod 0755 "$TMP_DIR/heartbeat-bin/curl"

# prerequisites <layout> <checked-out Allium> <rollback SHA or -> [NAME=value...]:
# prints the result, the Allium checkout, ALLIUM_ROLLBACK_SHA after the check
# and the failure class, then its log.
prerequisites() (
    # shellcheck source=../scripts/allium-deploy-update.sh
    source "$REPO_DIR/scripts/allium-deploy-update.sh"
    PATH="$TMP_DIR/heartbeat-bin:$PATH"
    ALLIUM_REPO_DIR="$ALLIUM_GIT"
    ALLIUM_DIR="$ALLIUM_GIT"
    CF_CHARTS_SCRIPT="$MOCK_BIN/cfcharts"
    CF_ASSETS_ENABLED=true
    CHARTS_LAYOUT="$1"
    JOB_FAILURE_CLASS=""
    git -C "$ALLIUM_GIT" reset -q --hard "$2"
    unset ALLIUM_ROLLBACK_SHA
    [[ "$3" == - ]] || export ALLIUM_ROLLBACK_SHA="$3"
    shift 3
    for assignment in "$@"; do
        # shellcheck disable=SC2163 # export the NAME=value pair as given
        export "$assignment"
        printf -v "${assignment%%=*}" '%s' "${assignment#*=}"
    done
    status=0
    check_charts_layout_prerequisites > "$TMP_DIR/prerequisites.log" 2>&1 || status=$?
    printf '%s %s %s %s\n' "$status" "$(git -C "$ALLIUM_GIT" rev-parse HEAD)" "${ALLIUM_ROLLBACK_SHA:-unset}" "${JOB_FAILURE_CLASS:-none}"
    cat "$TMP_DIR/prerequisites.log"
)

: > "$EVENTS"
result=$(prerequisites charts "$WITHOUT_LAYOUT" "$WITH_LAYOUT")
[[ "${result%%$'\n'*}" == "0 $WITH_LAYOUT unset none" ]] || fail "a pulled Allium without --chart-layout was kept: $result"
[[ "$result" == *"The pulled Allium $WITHOUT_LAYOUT cannot build CHARTS_LAYOUT=charts (it has no --chart-layout); building with $WITH_LAYOUT"* \
    && "$result" == *"Rolled back allium checkout to $WITH_LAYOUT"* ]] || fail "setting the pulled Allium back was not logged: $result"
[[ "$(cat "$EVENTS")" == 'cfcharts --check-config' ]] || fail "the charts Worker's settings were not checked first, or a heartbeat was sent without HEALTHCHECK_URL: $(cat "$EVENTS")"
# With the heartbeat on, holding Allium back is a warning there.
: > "$EVENTS"
result=$(prerequisites charts "$WITHOUT_LAYOUT" "$WITH_LAYOUT" HEALTHCHECK_URL=https://hc.example/check)
[[ "${result%%$'\n'*}" == "0 $WITH_LAYOUT unset none" && "$(cat "$EVENTS")" == "cfcharts --check-config"$'\n'"ping https://hc.example/check/log warn=allium_held sha=$WITHOUT_LAYOUT" ]] \
    || fail "holding a pulled Allium back was not a heartbeat warning: $(cat "$EVENTS")"
# An Allium whose --help fails is held back too, and the log shows why.
result=$(prerequisites charts "$BROKEN" "$WITH_LAYOUT")
[[ "${result%%$'\n'*}" == "0 $WITH_LAYOUT unset none" \
    && "$result" == *"The pulled Allium $BROKEN cannot build CHARTS_LAYOUT=charts (python3 allium.py --help failed (exit 1): "*'ImportError: cannot import name x'* \
    && "$result" != *'has no --chart-layout'* ]] || fail "a failing --help was not explained: $result"
result=$(prerequisites charts "$BROKEN" -)
[[ "${result%%$'\n'*}" == "1 $BROKEN unset allium" && "$result" == *'Allium cannot build CHARTS_LAYOUT=charts (python3 allium.py --help failed (exit 1): '*'ImportError'* ]] \
    || fail "a checked-out Allium whose --help fails did not stop the job with its reason: $result"
result=$(prerequisites charts "$WITHOUT_LAYOUT" -)
[[ "${result%%$'\n'*}" == "1 $WITHOUT_LAYOUT unset allium" && "$result" == *'Allium cannot build CHARTS_LAYOUT=charts (it has no --chart-layout): restore an Allium that has --chart-layout, or set CHARTS_LAYOUT=beside'* ]] \
    || fail "an Allium without --chart-layout that was not pulled did not stop the job: $result"
result=$(prerequisites charts "$WITH_LAYOUT" "$WITHOUT_LAYOUT")
[[ "${result%%$'\n'*}" == "0 $WITH_LAYOUT $WITHOUT_LAYOUT none" && "$result" != *'Rolled back'* ]] \
    || fail "an Allium with --chart-layout was set back: $result"
result=$(prerequisites charts "$WITHOUT_LAYOUT" "$WITH_LAYOUT" MOCK_CHARTS_CONFIG_EXIT=2)
[[ "${result%%$'\n'*}" == "1 $WITHOUT_LAYOUT $WITH_LAYOUT charts_config" && "$result" == *"CHARTS_LAYOUT=charts: the charts Worker's settings are invalid"* ]] \
    || fail "invalid charts Worker settings did not stop the job before Allium: $result"
: > "$EVENTS"
result=$(prerequisites charts "$WITH_LAYOUT" - CF_ASSETS_ENABLED=false)
[[ "${result%%$'\n'*}" == "0 $WITH_LAYOUT unset none" && ! -s "$EVENTS" ]] || fail "the charts Worker's settings were checked with Workers disabled: $result"
result=$(prerequisites beside "$WITHOUT_LAYOUT" "$WITH_LAYOUT")
[[ "$result" == "0 $WITHOUT_LAYOUT $WITH_LAYOUT none" && ! -s "$EVENTS" ]] || fail "the beside layout checked or changed Allium: $result"
[[ "$update_script" == *$'\nif ! capture_cfassets_deploy_snapshot; then\n    JOB_FAILURE_CLASS=setup\n    increment_failures\n    exit 1\nfi\nif ! check_charts_layout_prerequisites; then\n    increment_failures\n    exit 1\nfi\n'* ]] \
    || fail "the job does not check the charts layout's prerequisites right after the pulls and the snapshot"
pass "with CHARTS_LAYOUT=charts the job checks the charts Worker's settings and Allium's --chart-layout before Allium runs, and sets a pulled Allium without it back with a heartbeat warning"
