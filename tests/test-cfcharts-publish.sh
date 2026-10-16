#!/usr/bin/env bash
# The charts-only Worker of CHARTS_LAYOUT=charts: the wrapper's guards and its
# settings check, the hard-link stage with its build ID, its _headers with the
# marker header and its partition check, the file-count guard, the upload,
# verification and promotion with the charts Worker's own state files and
# upload summary, one configuration per update job for both Workers with a
# promotion switch that still stops them, the two-file bootstrap deployment
# and its refusals, and the production checks the wrapper hands to the
# verifier. Copies of the scripts run in a temporary deploy directory with a
# fake config.env, a Wrangler fixture and fixture verifiers.

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
STAGE_DIR="$TMP_DIR/charts-stage"
MOCK_BIN="$TMP_DIR/mock-bin"
EVENTS="$TMP_DIR/events"
FP='DB1629B59707F744A0C7933E56B6802786FFC317'
CONTACT='0123456789abcdef0123456789abcdef'
mkdir -p "$DEPLOY_DIR/scripts" "$DEPLOY_DIR/cloudflare-assets" "$MOCK_BIN" "$TMP_DIR/home/.config/cloudflare"
cp "$REPO_DIR/scripts/allium-deploy-cfassets.sh" "$REPO_DIR/scripts/allium-deploy-cfcharts.sh" \
    "$REPO_DIR/scripts/allium-deploy-lib.sh" "$DEPLOY_DIR/scripts/"
cp "$REPO_DIR/wrangler.assets.toml.template" "$REPO_DIR/wrangler.charts.toml.template" "$DEPLOY_DIR/"
cp "$REPO_DIR/cloudflare-assets/_headers" "$REPO_DIR/cloudflare-assets/404.html" \
    "$REPO_DIR/cloudflare-assets/.assetsignore.charts" "$REPO_DIR/cloudflare-assets/_redirects.charts" \
    "$DEPLOY_DIR/cloudflare-assets/"
printf 'CLOUDFLARE_API_TOKEN=file-token\n' > "$TMP_DIR/home/.config/cloudflare/workers_api_token"

put() {
    mkdir -p "$(dirname "$OUTPUT_DIR/$1")"
    printf '%s\n' "${2:-$1}" > "$OUTPUT_DIR/$1"
}

# The output tree in the charts layout. The main Worker uploads the pages,
# the static files (a nested _redirects is an ordinary asset) and the 404 page
# the overlay adds; the charts Worker the three charts.
for file in index.html search-index.json "relay/$FP/index.html" "contact/$CONTACT/index.html" \
    static/images/flags/exit.png static/nested/_redirects; do
    put "$file"
done
CHARTS="charts/relay/$FP/bandwidth-1m.png charts/relay/$FP/uptime-6m.png charts/contact/$CONTACT/bandwidth-1y.png"
for chart in $CHARTS; do
    put "$chart"
done

# Wrangler fixture. It records each call with the Worker it names, the
# WRANGLER_LOG it got and whether the shell variable LEAK reached it.
# versions upload reports a new version and prints the info-level upload lines
# when WRANGLER_LOG=info; deployments list answers as the file
# mock-deployments says; a deployment writes the file that mock-leave-file
# names, if any. Its own paths are fixed here, because the bootstrap
# deployment runs from an empty environment.
cat > "$MOCK_BIN/pnpm" <<EOF
#!/usr/bin/env bash
MOCK_EVENTS="$EVENTS"
MOCK_COUNT="$TMP_DIR/count"
MOCK_DEPLOYMENTS=\$(cat "$TMP_DIR/mock-deployments" 2>/dev/null || printf missing)
MOCK_LEAVE_FILE=\$(cat "$TMP_DIR/mock-leave-file" 2>/dev/null || true)
EOF
cat >> "$MOCK_BIN/pnpm" <<'EOF'
set -euo pipefail
shift 2
config=""
previous=""
for arg in "$@"; do
    [[ "$previous" != --config ]] || config="$arg"
    previous="$arg"
done
name=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$config")
leak="${LEAK:-none}"
next_id() {
    count=$(( $(cat "$MOCK_COUNT" 2>/dev/null || printf 0) + 1 ))
    printf '%s\n' "$count" > "$MOCK_COUNT"
    printf '%08x-1234-4234-8234-123456789abc' "$count"
}
info_lines() {
    if [[ "${WRANGLER_LOG:-}" == info ]]; then
        printf '🌀 Found 2 new or modified static assets to upload. Proceeding with upload...\n'
        printf '+ /charts/relay/x.png\n'
        printf 'Uploaded 1 of 2 assets\n'
        printf 'Uploaded 2 of 2 assets\n'
    fi
}
case "$1 $2" in
    "versions upload")
        id=$(next_id)
        printf 'upload %s %s log=%s\n' "$name" "$id" "${WRANGLER_LOG:-}" >> "$MOCK_EVENTS"
        info_lines
        printf '{"type":"version-upload","version":1,"version_id":"%s","preview_url":"https://%s-%s.test.workers.dev"}\n' \
            "$id" "${id:0:8}" "$name" >> "$WRANGLER_OUTPUT_FILE_PATH"
        ;;
    "versions deploy")
        printf 'deploy %s %s\n' "$name" "${3%@100%}" >> "$MOCK_EVENTS"
        ;;
    "deployments list")
        printf 'list %s log=%s leak=%s token=%s\n' "$name" "${WRANGLER_LOG:-}" "$leak" "${CLOUDFLARE_API_TOKEN:-}" >> "$MOCK_EVENTS"
        case "$MOCK_DEPLOYMENTS" in
            missing)
                printf '✘ [ERROR] A request to the Cloudflare API failed.\n\n  This Worker does not exist on your account. [code: 10007]\n' >&2
                exit 1
                ;;
            none) printf '[]\n' ;;
            one) printf '[\n  {"id": "d1", "versions": [{"version_id": "v1", "percentage": 100}]}\n]\n' ;;
            garbage) printf 'not a listing\n' ;;
            error) printf '✘ [ERROR] fetch failed\n' >&2; exit 1 ;;
        esac
        ;;
    "deploy --config")
        [[ -z "${MOCK_LEAVE_FILE:-}" ]] || printf 'left\n' > "$MOCK_LEAVE_FILE"
        id=$(next_id)
        printf 'bootstrap %s %s log=%s leak=%s token=%s\n' "$name" "$id" "${WRANGLER_LOG:-}" "$leak" "${CLOUDFLARE_API_TOKEN:-}" >> "$MOCK_EVENTS"
        info_lines
        printf '{"type":"deploy","version":1,"version_id":"%s"}\n' "$id" >> "$WRANGLER_OUTPUT_FILE_PATH"
        ;;
    *) printf 'unexpected wrangler call: %s\n' "$*" >&2; exit 64 ;;
esac
EOF
cat > "$MOCK_BIN/verify-main" <<'EOF'
#!/usr/bin/env bash
printf 'verify-main %s %s layout=%s\n' "$1" "$2" "${CHARTS_LAYOUT:-unset}" >> "$MOCK_EVENTS"
EOF
cat > "$MOCK_BIN/verify-charts" <<'EOF'
#!/usr/bin/env bash
printf 'verify-charts %s\n' "$*" >> "$MOCK_EVENTS"
exit "${MOCK_CHARTS_VERIFY_EXIT:-0}"
EOF
# Keep the test portable on macOS, where BSD du does not implement -b.
cat > "$MOCK_BIN/du" <<'EOF'
#!/usr/bin/env bash
printf '4096\t%s\n' "${@: -1}"
EOF
# stat shim: MOCK_OTHER_FS names a directory that reports another device.
REAL_STAT=$(command -v stat)
cat > "$MOCK_BIN/stat" <<EOF
#!/usr/bin/env bash
if [[ -n "\${MOCK_OTHER_FS:-}" && "\${*: -1}" == "\$MOCK_OTHER_FS" && "\$*" == *%d* ]]; then
    printf '999999\n'
    exit 0
fi
exec "$REAL_STAT" "\$@"
EOF
chmod 0755 "$MOCK_BIN"/*

# write_config [extra config.env lines...]: the charts layout unless a line
# sets another.
write_config() {
    {
        printf 'OUTPUT_DIR="%s"\n' "$OUTPUT_DIR"
        printf 'CF_CHARTS_STAGE_DIR="%s"\n' "$STAGE_DIR"
        printf 'CF_ASSETS_VERIFY_SCRIPT="%s"\n' "$MOCK_BIN/verify-main"
        printf 'CF_CHARTS_VERIFY_SCRIPT="%s"\n' "$MOCK_BIN/verify-charts"
        printf '%s\n' \
            SITE_URL=https://metrics.example.org \
            CHARTS_LAYOUT=charts \
            CF_ASSETS_ENABLED=true \
            CF_ASSETS_ALLOW_PROMOTION=true \
            CF_ASSETS_REQUIRE_FRESH_CHECKOUT=false \
            CF_ASSETS_WORKER_NAME=allium-main-test \
            CF_ASSETS_PREVIEW_ALIAS=allium-test \
            CF_ASSETS_UPLOAD_MAX_ATTEMPTS=1 \
            CF_CHARTS_WORKER_NAME=allium-charts-test \
            WRANGLER_LOG=info
        printf '%s\n' "$@"
    } > "$DEPLOY_DIR/config.env"
}

# run_script <script> <mode> [NAME=value...]: sets RUN_OUTPUT and RUN_STATUS.
# Settings come from the fake config.env; the extra pairs model the update
# job's or an operator's environment.
run_script() {
    local script="$1" mode="$2"
    shift 2
    set +e
    RUN_OUTPUT=$(env -i HOME="$TMP_DIR/home" PATH="$MOCK_BIN:$PATH" \
        MOCK_EVENTS="$EVENTS" MOCK_COUNT="$TMP_DIR/count" "$@" \
        "$DEPLOY_DIR/scripts/$script" "$mode" 2>&1)
    RUN_STATUS=$?
    set -e
}

events() {
    cat "$EVENTS" 2>/dev/null || true
}

LOGS="$DEPLOY_DIR/logs"
STAGE_PATH="$(cd "$TMP_DIR" && pwd -P)/charts-stage"

# The wrapper's guards: builds publish the charts Worker only in the charts
# layout, and it needs a name of its own.
write_config CHARTS_LAYOUT=beside
for mode in --generate-only --upload-only --promote --check-config; do
    run_script allium-deploy-cfcharts.sh "$mode"
    [[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'builds publish the charts Worker only with CHARTS_LAYOUT=charts'* ]] \
        || fail "$mode with CHARTS_LAYOUT=beside: $RUN_STATUS $RUN_OUTPUT"
done
for case in \
    'CF_CHARTS_WORKER_NAME=|CF_CHARTS_WORKER_NAME is required' \
    'CF_CHARTS_WORKER_NAME=allium-main-test|must name a Worker other than allium-main-test' \
    'CF_CHARTS_WORKER_NAME=Charts_Worker|invalid charts worker name' \
    'CHARTS_LAYOUT=split|invalid CHARTS_LAYOUT=split' \
    'CF_CHARTS_WORKER_NAME=allium-charts-0123456789-0123456789-0123|exceed the 63 characters'; do
    write_config "${case%%|*}"
    for mode in --generate-only --check-config; do
        run_script allium-deploy-cfcharts.sh "$mode"
        [[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *"${case#*|}"* ]] || fail "'${case%%|*}' was not refused by $mode: $RUN_STATUS $RUN_OUTPUT"
    done
done
run_script allium-deploy-cfcharts.sh --sometimes
[[ "$RUN_STATUS" == 2 ]] || fail "an unknown mode was accepted"
write_config
run_script allium-deploy-cfcharts.sh --check-config
[[ "$RUN_STATUS" == 0 && "$RUN_OUTPUT" == '[CF-Charts] settings ok: charts Worker allium-charts-test, preview alias allium-charts-candidate' ]] \
    || fail "valid settings failed the check: $RUN_STATUS $RUN_OUTPUT"
[[ ! -e "$STAGE_DIR" && -z "$(events)" ]] || fail "a refused run or the settings check wrote a stage or called Wrangler"
pass "the wrapper refuses build modes outside the charts layout, a missing, shared or invalid name, and an invalid layout; --check-config checks only these"

# The stage: hard links to the charts, the main Worker's _headers and its 404
# page as charts/404.html; the partition holds.
write_config
run_script allium-deploy-cfassets.sh --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "main generation exited $RUN_STATUS: $RUN_OUTPUT"
run_script allium-deploy-cfcharts.sh --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "charts generation exited $RUN_STATUS: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *'[CF-Charts] partition ok: main Worker 7 + charts Worker 3 = 10 files'* ]] \
    || fail "the partition was not checked as expected: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *'[CF-Charts] charts per period: 1m=1 1y=1 6m=1'$'\n'* ]] || fail "the charts per period were not logged: $RUN_OUTPUT"
staged=$(cd "$STAGE_DIR" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
[[ "$staged" == "$(printf '%s\n' _headers charts/404.html charts/build-id.txt $CHARTS | LC_ALL=C sort)" ]] || fail "unexpected stage contents: $staged"
build_id=$(cat "$STAGE_DIR/charts/build-id.txt")
[[ "$build_id" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\ [0-9]+-[0-9]+$ ]] || fail "unexpected build ID: $build_id"
for chart in $CHARTS; do
    [[ "$STAGE_DIR/$chart" -ef "$OUTPUT_DIR/$chart" ]] || fail "$chart is not a hard link to the output file"
done
# The stage's _headers is the main Worker's with one line more, the marker,
# inside its one /* rule: a second /* rule would replace the first, and with
# it the security headers.
[[ "$(diff "$REPO_DIR/cloudflare-assets/_headers" "$STAGE_DIR/_headers" | grep -c '^[<>]')" == 1 ]] \
    || fail "the stage _headers differs from the main one by more than a line: $(diff "$REPO_DIR/cloudflare-assets/_headers" "$STAGE_DIR/_headers")"
rule=$(awk '/^[^ #]/ { in_rule = ($0 == "/*") } in_rule && /^  / { print substr($0, 3) }' "$STAGE_DIR/_headers")
for header in 'X-Allium-Origin: charts' 'X-Content-Type-Options: nosniff' 'X-Frame-Options: DENY' \
    'Referrer-Policy: strict-origin-when-cross-origin' "Content-Security-Policy: default-src 'self'"; do
    [[ "$rule" == *"$header"* ]] || fail "the stage's /* rule lacks '$header': $rule"
done
[[ -z "$(grep -E '^[^ #]' "$STAGE_DIR/_headers" | sort | uniq -d)" ]] || fail "a path has two rules in the stage _headers"
[[ "$(grep -c 'X-Allium-Origin' "$STAGE_DIR/_headers")" == 1 && "$(grep -c 'X-Allium-Origin' "$REPO_DIR/cloudflare-assets/_headers")" == 0 ]] \
    || fail "the marker is not in the stage _headers only, once"
cmp -s "$REPO_DIR/cloudflare-assets/404.html" "$STAGE_DIR/charts/404.html" || fail "charts/404.html is not cloudflare-assets/404.html"
[[ ! -e "$STAGE_DIR.next" && ! -e "$STAGE_DIR.old" ]] || fail "the stage build left a temporary tree"
sed -e 's|{{CF_ASSETS_WORKER_NAME}}|allium-charts-test|g' \
    -e 's|{{CF_ASSETS_COMPATIBILITY_DATE}}|2026-07-26|g' \
    -e "s|{{CF_ASSETS_DIRECTORY}}|$STAGE_PATH|g" \
    "$REPO_DIR/wrangler.charts.toml.template" > "$TMP_DIR/expected-charts.toml"
cmp -s "$TMP_DIR/expected-charts.toml" "$DEPLOY_DIR/wrangler.charts.toml" \
    || fail "unexpected charts config: $(diff "$TMP_DIR/expected-charts.toml" "$DEPLOY_DIR/wrangler.charts.toml")"
charts_config=$(grep -v '^#' "$DEPLOY_DIR/wrangler.charts.toml")
for absent in 'main =' 'binding' 'run_worker_first' 'services' 'route' 'custom_domain'; do
    [[ "$charts_config" != *"$absent"* ]] || fail "the charts config contains '$absent'"
done
for present in 'not_found_handling = "404-page"' 'html_handling = "none"' 'preview_urls = true' 'workers_dev = true'; do
    grep -Fqx -- "$present" "$DEPLOY_DIR/wrangler.charts.toml" || fail "the charts config lacks '$present'"
done
grep -Fq 'compatibility_date = "2026-07-26"' "$DEPLOY_DIR/wrangler.assets.toml" \
    || fail "the main and charts configs do not share the compatibility date"
# A main _headers without exactly one /* rule cannot carry the marker in it:
# the stage is not rebuilt.
cp "$DEPLOY_DIR/cloudflare-assets/_headers" "$TMP_DIR/headers.orig"
rm -rf "$TMP_DIR/stage-before"
cp -R "$STAGE_DIR" "$TMP_DIR/stage-before"
for variant in twice none; do
    if [[ "$variant" == twice ]]; then
        { cat "$TMP_DIR/headers.orig"; printf '\n/*\n  X-Extra: 1\n'; } > "$DEPLOY_DIR/cloudflare-assets/_headers"
    else
        sed 's|^/\*$|/index.html|' "$TMP_DIR/headers.orig" > "$DEPLOY_DIR/cloudflare-assets/_headers"
    fi
    run_script allium-deploy-cfcharts.sh --generate-only
    [[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'must have exactly one /* rule'* ]] || fail "a main _headers with the /* rule $variant was accepted: $RUN_STATUS $RUN_OUTPUT"
    diff -r "$TMP_DIR/stage-before" "$STAGE_DIR" >/dev/null || fail "a main _headers with the /* rule $variant changed the stage"
    [[ ! -e "$STAGE_DIR.next" && ! -e "$STAGE_DIR.old" ]] || fail "a main _headers with the /* rule $variant left a temporary stage"
done
cp "$TMP_DIR/headers.orig" "$DEPLOY_DIR/cloudflare-assets/_headers"
pass "the charts stage hard-links the charts below charts/, adds the main _headers with the marker in its /* rule and charts/404.html, logs the charts per period, and its config is assets-only and route-free; a main _headers without exactly one /* rule stops it"

# The stage is rebuilt every time: removed charts go, new ones come.
rm "$OUTPUT_DIR/charts/relay/$FP/uptime-6m.png"
put "charts/relay/$FP/uptime-1y.png"
run_script allium-deploy-cfcharts.sh --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "rebuilding the stage exited $RUN_STATUS: $RUN_OUTPUT"
[[ ! -e "$STAGE_DIR/charts/relay/$FP/uptime-6m.png" && "$STAGE_DIR/charts/relay/$FP/uptime-1y.png" -ef "$OUTPUT_DIR/charts/relay/$FP/uptime-1y.png" ]] \
    || fail "the rebuilt stage does not mirror the output's charts"
[[ "$(cat "$STAGE_DIR/charts/build-id.txt")" != "$build_id" ]] || fail "the rebuilt stage kept the previous build ID"
CHARTS="charts/relay/$FP/bandwidth-1m.png charts/relay/$FP/uptime-1y.png charts/contact/$CONTACT/bandwidth-1y.png"

# While a main version is live, the charts its pages link stay in later charts
# versions even when the build dropped them (its promotion may still fail),
# hard-linked from the previous stage; the partition counts them apart.
mkdir -p "$LOGS"
printf '%s\n' $CHARTS charts/relay/GONE/bandwidth-1m.png > "$LOGS/cfcharts-live-charts"
ln "$STAGE_DIR/charts/relay/$FP/uptime-1y.png" "$TMP_DIR/live-chart-ref"
rm "$OUTPUT_DIR/charts/relay/$FP/uptime-1y.png"
run_script allium-deploy-cfcharts.sh --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "a stage keeping a live chart exited $RUN_STATUS: $RUN_OUTPUT"
[[ "$STAGE_DIR/charts/relay/$FP/uptime-1y.png" -ef "$TMP_DIR/live-chart-ref" ]] || fail "the live pages' dropped chart was not kept from the previous stage"
[[ "$RUN_OUTPUT" == *'kept 1 charts that the live main Worker version links but this build no longer has'* ]] || fail "the kept chart was not logged: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *'warning: 1 charts that the live main Worker version links are in neither this build nor the previous stage'* ]] \
    || fail "a live chart in neither tree was not reported: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *'partition ok: main Worker 7 + charts Worker 2 = 9 files (the charts Worker also keeps 1 for the live pages)'* ]] \
    || fail "the partition did not count the kept chart apart: $RUN_OUTPUT"
[[ ! -e "$STAGE_DIR/charts/relay/GONE/bandwidth-1m.png" ]] || fail "a chart in neither tree appeared in the stage"
# Without a live list, a dropped chart goes.
rm "$LOGS/cfcharts-live-charts" "$TMP_DIR/live-chart-ref"
run_script allium-deploy-cfcharts.sh --generate-only
[[ "$RUN_STATUS" == 0 && ! -e "$STAGE_DIR/charts/relay/$FP/uptime-1y.png" ]] || fail "a dropped chart stayed without a live list: $RUN_STATUS $RUN_OUTPUT"
[[ "$RUN_OUTPUT" != *'kept'* && "$RUN_OUTPUT" != *'also keeps'* ]] || fail "nothing kept was still logged: $RUN_OUTPUT"
put "charts/relay/$FP/uptime-1y.png"
run_script allium-deploy-cfcharts.sh --generate-only
[[ "$RUN_STATUS" == 0 ]] || fail "restoring the stage exited $RUN_STATUS: $RUN_OUTPUT"
pass "the charts stage keeps the charts the live main Worker version links, hard-linked from the previous stage, and counts them apart in the partition"
pass "the stage is rebuilt from the output tree on every run, with a new build ID"

# Files that the main Worker's .assetsignore (/charts/, ignoring case) drops
# but the stage does not take fail the partition check. A differently cased
# charts/ directory exists only on a case-sensitive filesystem.
odd_files=("charts/relay/$FP/notes.txt" "charts/relay/$FP/upper.PNG")
touch "$TMP_DIR/case-probe"
case_sensitive=false
if [[ ! -e "$TMP_DIR/CASE-PROBE" ]]; then
    case_sensitive=true
    odd_files+=("Charts/relay/$FP/bandwidth-1m.png")
fi
for odd in "${odd_files[@]}"; do
    put "$odd"
    run_script allium-deploy-cfcharts.sh --generate-only
    [[ "$RUN_STATUS" == 1 ]] || fail "$odd did not fail the partition check: $RUN_STATUS $RUN_OUTPUT"
    [[ "$RUN_OUTPUT" == *'partition check failed: the main Worker uploads 7 and the charts stage holds 3 of the 11 files'* ]] \
        || fail "the broken partition ($odd) was not explained: $RUN_OUTPUT"
    [[ "$RUN_OUTPUT" == *"served by neither Worker: $odd"* ]] || fail "$odd was not named: $RUN_OUTPUT"
    rm "$OUTPUT_DIR/$odd"
done
if [[ "$case_sensitive" == true ]]; then
    rm -r "$OUTPUT_DIR/Charts"
fi
ln -s bandwidth-1m.png "$OUTPUT_DIR/charts/relay/$FP/linked.png"
run_script allium-deploy-cfcharts.sh --generate-only
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"served by neither Worker: charts/relay/$FP/linked.png"* ]] \
    || fail "a symbolic link below charts/ passed the partition check: $RUN_STATUS $RUN_OUTPUT"
rm "$OUTPUT_DIR/charts/relay/$FP/linked.png"
pass "a file below charts/ that the stage does not take (not a regular *.png, or a differently cased charts/) fails the partition check"

# The stage directory must be absolute, outside the output tree, on the same
# filesystem, and never a directory that holds anything else.
mkdir -p "$TMP_DIR/not-a-stage/charts"
printf 'keep me\n' > "$TMP_DIR/not-a-stage/notes.txt"
for case in \
    "$OUTPUT_DIR/charts-stage|must be outside the assets directory" \
    "$TMP_DIR|must be outside the assets directory" \
    "relative/stage|must be an absolute path" \
    "$TMP_DIR/missing/stage|the parent of the charts stage directory does not exist" \
    "$TMP_DIR/not-a-stage|a charts stage never holds $(cd "$TMP_DIR" && pwd -P)/not-a-stage/notes.txt"; do
    write_config "CF_CHARTS_STAGE_DIR=\"${case%%|*}\""
    run_script allium-deploy-cfcharts.sh --generate-only
    [[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"${case#*|}"* ]] || fail "stage ${case%%|*} was accepted or not explained: $RUN_STATUS $RUN_OUTPUT"
done
[[ "$(cat "$TMP_DIR/not-a-stage/notes.txt")" == 'keep me' && ! -e "$OUTPUT_DIR/charts-stage" ]] \
    || fail "a refused stage directory was changed"
write_config
run_script allium-deploy-cfcharts.sh --generate-only MOCK_OTHER_FS="$(cd "$TMP_DIR" && pwd -P)"
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'must be on the same filesystem as'* ]] \
    || fail "a stage on another filesystem was accepted: $RUN_OUTPUT"
pass "a stage inside the output tree, relative, on another filesystem or replacing a foreign directory is refused"

# Without charts the charts Worker has nothing to publish: fail loudly.
mv "$OUTPUT_DIR/charts" "$TMP_DIR/charts-aside"
run_script allium-deploy-cfcharts.sh --generate-only
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'no chart PNG to publish from'* ]] || fail "an empty stage was accepted: $RUN_STATUS $RUN_OUTPUT"
mv "$TMP_DIR/charts-aside" "$OUTPUT_DIR/charts"
pass "an output tree without charts fails the charts Worker's preparation"

# File-count guard: the charts Worker counts its charts, charts/404.html and
# the build ID. It warns from CF_CHARTS_WARN_FILES, not the main Worker's
# CF_ASSETS_WARN_FILES.
write_config CF_ASSETS_MAX_FILES=4
run_script allium-deploy-cfcharts.sh --generate-only
[[ "$RUN_STATUS" == 4 && "$RUN_OUTPUT" == *'refusing upload: 5 files exceed the limit of 4 files per Worker version'* ]] \
    || fail "the charts preparation accepted 5 files over a limit of 4: $RUN_STATUS $RUN_OUTPUT"
[[ ! -e "$STAGE_DIR.next" && ! -e "$STAGE_DIR.old" ]] || fail "a refused preparation left a temporary stage"
: > "$EVENTS"
run_script allium-deploy-cfcharts.sh --upload-only
[[ "$RUN_STATUS" == 4 && "$RUN_OUTPUT" == *'refusing upload: 5 files exceed the limit of 4 files per Worker version'* ]] \
    || fail "the charts guard did not refuse 5 files over a limit of 4: $RUN_STATUS $RUN_OUTPUT"
[[ -z "$(events)" ]] || fail "the guard did not stop the upload: $(events)"
write_config CF_ASSETS_MAX_FILES=5 CF_ASSETS_WARN_FILES=5
run_script allium-deploy-cfcharts.sh --upload-only
[[ "$RUN_STATUS" == 0 && "$RUN_OUTPUT" != *'approach the limit'* ]] \
    || fail "the main Worker's warning level applied to the charts Worker: $RUN_STATUS $RUN_OUTPUT"
write_config CF_ASSETS_MAX_FILES=5 CF_CHARTS_WARN_FILES=5
run_script allium-deploy-cfcharts.sh --upload-only
[[ "$RUN_STATUS" == 0 && "$RUN_OUTPUT" == *'warning: 5 files approach the limit of 5 files per Worker version'* ]] \
    || fail "the charts guard did not warn at the limit: $RUN_STATUS $RUN_OUTPUT"
# shellcheck disable=SC2016 # a literal line of the script
grep -Fq 'export CF_ASSETS_WARN_FILES="${CF_CHARTS_WARN_FILES:-85000}"' "$REPO_DIR/scripts/allium-deploy-cfcharts.sh" \
    || fail "the charts Worker's default warning level is not 85000 files"
pass "the file-count guard counts the charts Worker's upload, warns from its own level (85000 by default) and refuses above the limit, already when the stage is prepared"

# Upload: verified against the stage and the output tree, recorded in the
# charts Worker's own state files, with a row in its upload summary.
rm -rf "$LOGS"
write_config
: > "$EVENTS"
run_script allium-deploy-cfcharts.sh --upload-only
[[ "$RUN_STATUS" == 0 ]] || fail "the charts upload exited $RUN_STATUS: $RUN_OUTPUT"
CHARTS_VERSION=$(cat "$LOGS/cfcharts-last-version")
CHARTS_PREVIEW="https://${CHARTS_VERSION:0:8}-allium-charts-test.test.workers.dev"
[[ "$(events)" == "upload allium-charts-test $CHARTS_VERSION log=info"$'\n'"verify-charts $CHARTS_PREVIEW $STAGE_PATH $OUTPUT_DIR" ]] \
    || fail "unexpected charts upload: $(events)"
for state in cfcharts-shadow-summary.tsv cfcharts-shadow-consecutive-successes cfcharts-uploads.tsv; do
    [[ -s "$LOGS/$state" ]] || fail "the charts upload did not write $state"
done
for state in cfassets-shadow-summary.tsv cfassets-shadow-consecutive-successes cfassets-last-version cfassets-promotion-summary.tsv cfassets-uploads.tsv; do
    [[ ! -e "$LOGS/$state" ]] || fail "the charts Worker wrote the main Worker's $state"
done
row=$(tail -n 1 "$LOGS/cfcharts-uploads.tsv")
IFS=$'\t' read -r _ worker version status files asked uploaded transfer total <<< "$row"
[[ "$worker $version $status $files $asked $uploaded" == "allium-charts-test $CHARTS_VERSION 0 5 2 2" ]] \
    || fail "unexpected charts upload summary: $row"
[[ "$transfer" =~ ^[0-9]+$ && "$total" =~ ^[0-9]+$ ]] || fail "the upload summary has no durations: $row"
[[ "$(head -n 1 "$LOGS/cfcharts-uploads.tsv")" == $'timestamp_utc\tworker\tversion_id\texit_status\tfiles\tasked\tuploaded\ttransfer_seconds\ttotal_seconds' ]] \
    || fail "unexpected upload summary header"
[[ "$RUN_OUTPUT" == *'[CF-Charts] upload summary: files=5 asked=2 uploaded=2 transfer='* ]] || fail "the upload summary was not logged: $RUN_OUTPUT"
[[ "$(tail -n 1 "$LOGS/cfcharts-shadow-summary.tsv" | cut -f4)" == 5 ]] || fail "the charts shadow summary does not count the version's 5 files"

# Unchanged charts upload again (no skip), and a hidden log level leaves the
# Wrangler-reported columns unknown.
write_config WRANGLER_LOG=error
run_script allium-deploy-cfcharts.sh --upload-only
[[ "$RUN_STATUS" == 0 ]] || fail "a repeated charts upload exited $RUN_STATUS"
IFS=$'\t' read -r _ _ _ _ files asked uploaded transfer _ <<< "$(tail -n 1 "$LOGS/cfcharts-uploads.tsv")"
[[ "$files $asked $uploaded $transfer" == '5 - - -' ]] || fail "a hidden Wrangler log did not leave the columns unknown"
[[ "$(grep -c '^upload allium-charts-test' "$EVENTS")" == 2 ]] || fail "unchanged charts were not uploaded again"
CHARTS_VERSION=$(cat "$LOGS/cfcharts-last-version")

# A failed verification records nothing as verified.
write_config
run_script allium-deploy-cfcharts.sh --upload-only MOCK_CHARTS_VERIFY_EXIT=1
[[ "$RUN_STATUS" == 1 && "$(cat "$LOGS/cfcharts-last-version")" == "$CHARTS_VERSION" ]] \
    || fail "a failed charts verification exited $RUN_STATUS or replaced the verified version"
[[ "$(cat "$LOGS/cfcharts-shadow-consecutive-successes")" == 0 ]] || fail "a failed charts verification kept its streak"
pass "a charts upload is verified with the stage and output tree, every run uploads, and only the charts Worker's state files and upload summary are written"

# Promotion deploys the last verified charts version and leaves the stage, which
# the route check compares with production, as it was.
stage_inode=$(ls -i "$STAGE_DIR/charts/relay/$FP/bandwidth-1m.png" | awk '{print $1}')
build_id=$(cat "$STAGE_DIR/charts/build-id.txt")
printf 'changed after the upload\n' > "$OUTPUT_DIR/charts/relay/$FP/bandwidth-1m.png.tmp"
mv "$OUTPUT_DIR/charts/relay/$FP/bandwidth-1m.png.tmp" "$OUTPUT_DIR/charts/relay/$FP/bandwidth-1m.png"
: > "$EVENTS"
run_script allium-deploy-cfcharts.sh --promote
[[ "$RUN_STATUS" == 0 && "$(events)" == "deploy allium-charts-test $CHARTS_VERSION" ]] || fail "charts promotion: $RUN_STATUS $(events) $RUN_OUTPUT"
[[ "$(ls -i "$STAGE_DIR/charts/relay/$FP/bandwidth-1m.png" | awk '{print $1}')" == "$stage_inode" \
    && "$(cat "$STAGE_DIR/charts/build-id.txt")" == "$build_id" ]] \
    || fail "the promotion rebuilt the stage"
[[ "$(tail -n 1 "$LOGS/cfcharts-promotion-summary.tsv" | cut -f2,3)" == "$CHARTS_VERSION"$'\t0' ]] || fail "the charts promotion row is wrong"
[[ ! -e "$LOGS/cfassets-promotion-summary.tsv" ]] || fail "the charts promotion wrote the main Worker's promotion summary"
write_config CF_ASSETS_ALLOW_PROMOTION=false
run_script allium-deploy-cfcharts.sh --promote
[[ "$RUN_STATUS" == 3 ]] || fail "charts promotion ran with promotion disabled"
pass "charts promotion deploys the verified version with its own summary, follows CF_ASSETS_ALLOW_PROMOTION and keeps the stage"

# One configuration per update job: the job exports its CHARTS_LAYOUT,
# CF_CHARTS_WORKER_NAME and CF_ASSETS_ENABLED, which win over config.env
# edited while it runs, for both Workers. CF_ASSETS_ALLOW_PROMOTION is not
# exported: setting it to false in config.env stops the running job's
# promotions of both Workers.
mapfile -t JOB_ENV < <(
    export ALLIUM_DEPLOY_TEST_MODE=1
    # shellcheck source=../scripts/allium-deploy-update.sh
    source "$REPO_DIR/scripts/allium-deploy-update.sh"
    CHARTS_LAYOUT=charts CF_CHARTS_WORKER_NAME=allium-charts-test CF_ASSETS_ENABLED=true CF_ASSETS_ALLOW_PROMOTION=true
    export_job_settings
    env | grep -E '^(CHARTS_|CF_|ALLIUM_NO_CHARTS=)' | LC_ALL=C sort
)
[[ "${JOB_ENV[*]}" == 'ALLIUM_NO_CHARTS=false CF_ASSETS_ENABLED=true CF_CHARTS_WORKER_NAME=allium-charts-test CHARTS_LAYOUT=charts' ]] \
    || fail "unexpected job settings: ${JOB_ENV[*]}"
write_config
run_script allium-deploy-cfassets.sh --upload-only "${JOB_ENV[@]}"
[[ "$RUN_STATUS" == 0 ]] || fail "the main upload exited $RUN_STATUS: $RUN_OUTPUT"
write_config CF_ASSETS_ALLOW_PROMOTION=false
for script in allium-deploy-cfcharts.sh allium-deploy-cfassets.sh; do
    : > "$EVENTS"
    run_script "$script" --promote "${JOB_ENV[@]}"
    [[ "$RUN_STATUS" == 3 && "$RUN_OUTPUT" == *'promotion is disabled'* && -z "$(events)" ]] \
        || fail "$script promoted after config.env disabled promotion: $RUN_STATUS $(events) $RUN_OUTPUT"
done
write_config CF_ASSETS_ENABLED=false CHARTS_LAYOUT=beside CF_CHARTS_WORKER_NAME=allium-other-test
for case in 'allium-deploy-cfcharts.sh|allium-charts-test|verify-charts https://' 'allium-deploy-cfassets.sh|allium-main-test|verify-main https://'; do
    IFS='|' read -r script worker verifier <<< "$case"
    : > "$EVENTS"
    run_script "$script" --upload-only "${JOB_ENV[@]}"
    [[ "$RUN_STATUS" == 0 && "$(sed -n 1p "$EVENTS")" == "upload $worker "* && "$(sed -n 2p "$EVENTS")" == "$verifier"* ]] \
        || fail "$script did not upload with the job's settings: $RUN_STATUS $(events) $RUN_OUTPUT"
done
[[ "$(sed -n 2p "$EVENTS")" == *' layout=charts' && -f "$OUTPUT_DIR/.assetsignore" ]] || fail "the main Worker did not keep the job's layout: $(events)"
pass "both Workers keep the update job's layout, name and CF_ASSETS_ENABLED, and CF_ASSETS_ALLOW_PROMOTION=false in config.env stops a running job's promotions"

# The production checks: the wrapper hands SITE_URL and the stage to the
# verifier.
write_config
: > "$EVENTS"
run_script allium-deploy-cfcharts.sh --check-route
[[ "$RUN_STATUS" == 0 && "$(events)" == "verify-charts --route https://metrics.example.org $STAGE_DIR $OUTPUT_DIR" ]] \
    || fail "the route check: $RUN_STATUS $(events)"
: > "$EVENTS"
run_script allium-deploy-cfcharts.sh --check-route MOCK_CHARTS_VERIFY_EXIT=75
[[ "$RUN_STATUS" == 75 ]] || fail "the route check did not pass on the verifier's inconclusive exit: $RUN_STATUS"
: > "$EVENTS"
run_script allium-deploy-cfcharts.sh --check-redirects MOCK_CHARTS_VERIFY_EXIT=1
[[ "$RUN_STATUS" == 1 && "$(events)" == "verify-charts --redirects https://metrics.example.org $STAGE_DIR" ]] \
    || fail "the redirect check: $RUN_STATUS $(events)"
# Before the switch, the bootstrap form checks the bootstrap stage's 404 page.
write_config CHARTS_LAYOUT=beside
: > "$EVENTS"
run_script allium-deploy-cfcharts.sh --check-bootstrap-route MOCK_CHARTS_VERIFY_EXIT=75
[[ "$RUN_STATUS" == 75 && "$(events)" == "verify-charts --route-bootstrap https://metrics.example.org $STAGE_DIR" ]] \
    || fail "the bootstrap route check: $RUN_STATUS $(events)"
for site in '' http://metrics.example.org 'https://metrics.example.org/sub'; do
    write_config "SITE_URL=$site"
    for mode in --check-route --check-bootstrap-route; do
        : > "$EVENTS"
        run_script allium-deploy-cfcharts.sh "$mode"
        [[ "$RUN_STATUS" == 2 && "$RUN_OUTPUT" == *'SITE_URL must be'* && -z "$(events)" ]] || fail "SITE_URL '$site' was accepted by $mode"
    done
done
pass "the route, bootstrap route and redirect checks run the verifier on SITE_URL with the stage (and the output tree for the route), keep its exit status, and need an https site root"

# Bootstrap deployment, before the layout changes: from an empty environment,
# only for a Worker without a deployment, with the same toolchain, token files
# and route-free config, and a stage of two files, the _headers and
# charts/404.html, whatever the output tree holds. Wrangler's upload counts
# are logged whatever WRANGLER_LOG says.
write_config CHARTS_LAYOUT=beside WRANGLER_LOG=error
: > "$EVENTS"
printf missing > "$TMP_DIR/mock-deployments"
run_script allium-deploy-cfcharts.sh --bootstrap-deploy LEAK=yes CLOUDFLARE_API_TOKEN=shell-token
[[ "$RUN_STATUS" == 0 ]] || fail "the bootstrap deployment exited $RUN_STATUS: $RUN_OUTPUT"
mapfile -t calls < "$EVENTS"
[[ "${#calls[@]}" == 2 && "${calls[0]}" == 'list allium-charts-test log=log leak=none token=file-token' \
    && "${calls[1]}" == 'bootstrap allium-charts-test '*' log=info leak=none token=file-token' ]] \
    || fail "unexpected bootstrap calls: $(events)"
[[ "$RUN_OUTPUT" == *"bootstrap deployment complete: allium-charts-test serves version"*'with no route'* ]] \
    || fail "the bootstrap deployment was not logged: $RUN_OUTPUT"
[[ "$RUN_OUTPUT" == *'Found 2 new or modified static assets'* && "$RUN_OUTPUT" == *'[CF-Charts] upload summary: files=1 asked=2 uploaded=2 '* ]] \
    || fail "the bootstrap upload counts were not logged: $RUN_OUTPUT"
[[ "$(cut -f2 "$LOGS/cfcharts-uploads.tsv" | tail -n 1)" == allium-charts-test ]] || fail "the bootstrap upload was not summarized"
staged=$(cd "$STAGE_DIR" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
[[ "$staged" == $'_headers\ncharts/404.html' && "$(grep -c 'X-Allium-Origin: charts' "$STAGE_DIR/_headers")" == 1 ]] \
    || fail "the bootstrap stage is not the marked _headers and charts/404.html: $staged"
: > "$EVENTS"
printf none > "$TMP_DIR/mock-deployments"
run_script allium-deploy-cfcharts.sh --bootstrap-deploy
[[ "$RUN_STATUS" == 0 && "$(grep -c '^bootstrap ' "$EVENTS")" == 1 ]] || fail "a Worker without deployments was not bootstrapped"
for case in \
    'one|allium-charts-test already has a deployment' \
    'garbage|could not read the deployments' \
    'error|could not list the deployments'; do
    : > "$EVENTS"
    printf '%s' "${case%%|*}" > "$TMP_DIR/mock-deployments"
    run_script allium-deploy-cfcharts.sh --bootstrap-deploy
    [[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"refusing bootstrap: ${case#*|}"* ]] || fail "deployments '${case%%|*}' were not refused: $RUN_STATUS $RUN_OUTPUT"
    ! grep -q '^bootstrap ' "$EVENTS" || fail "deployments '${case%%|*}' still deployed"
done
# A refused bootstrap leaves a stage that a build made as it was: refused in
# the charts layout, or once the last promoted layout is not beside, before
# any Wrangler call; for a Worker that has a deployment, before the stage.
write_config
run_script allium-deploy-cfcharts.sh --generate-only
[[ "$RUN_STATUS" == 0 && -f "$STAGE_DIR/charts/build-id.txt" ]] || fail "the charts stage was not built: $RUN_STATUS $RUN_OUTPUT"
rm -rf "$TMP_DIR/stage-before"
cp -R "$STAGE_DIR" "$TMP_DIR/stage-before"
for case in \
    'CHARTS_LAYOUT=charts||refusing bootstrap: CHARTS_LAYOUT=charts and the last promoted layout is '"'beside'" \
    'CHARTS_LAYOUT=beside|charts|refusing bootstrap: CHARTS_LAYOUT=beside and the last promoted layout is '"'charts'" \
    'CHARTS_LAYOUT=beside|garbage|the last promoted layout is '"'garbage'" \
    'CHARTS_LAYOUT=beside|beside|refusing bootstrap: allium-charts-test already has a deployment'; do
    IFS='|' read -r layout promoted expected <<< "$case"
    write_config "$layout"
    rm -f "$LOGS/charts-layout-promoted"
    [[ -z "$promoted" ]] || { mkdir -p "$LOGS"; printf '%s\n' "$promoted" > "$LOGS/charts-layout-promoted"; }
    printf one > "$TMP_DIR/mock-deployments"
    : > "$EVENTS"
    run_script allium-deploy-cfcharts.sh --bootstrap-deploy
    [[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *"$expected"* ]] || fail "'$layout' with the marker '$promoted' was not refused: $RUN_STATUS $RUN_OUTPUT"
    ! grep -q '^bootstrap ' "$EVENTS" || fail "'$layout' with the marker '$promoted' deployed"
    [[ "$promoted" == beside || -z "$(events)" ]] || fail "'$layout' with the marker '$promoted' called Wrangler: $(events)"
    diff -r "$TMP_DIR/stage-before" "$STAGE_DIR" >/dev/null || fail "a refused bootstrap ('$layout', marker '$promoted') changed the stage"
done
rm -f "$LOGS/charts-layout-promoted"
write_config CHARTS_LAYOUT=beside
cp "$DEPLOY_DIR/wrangler.charts.toml.template" "$TMP_DIR/charts-template.orig"
printf missing > "$TMP_DIR/mock-deployments"
# Each way TOML can give the Worker a route or custom domain, after
# workers_dev or at the end, is refused before any Wrangler call.
for route in \
    'routes = [ "metrics.example.org/charts/*" ]' \
    'route = "metrics.example.org/charts/*"' \
    'route.pattern = "metrics.example.org/charts/*"' \
    '[[routes]]|pattern = "metrics.example.org/charts/*"|zone_name = "example.org"' \
    '[[ routes ]]|pattern = "metrics.example.org/charts/*"|custom_domain = true' \
    '[route]|pattern = "metrics.example.org/charts/*"'; do
    if [[ "$route" == '['* ]]; then
        { cat "$TMP_DIR/charts-template.orig"; printf '\n'; tr '|' '\n' <<< "$route"; } > "$DEPLOY_DIR/wrangler.charts.toml.template"
    else
        awk -v route="$route" '{ print } /^workers_dev = true$/ { print route }' \
            "$TMP_DIR/charts-template.orig" > "$DEPLOY_DIR/wrangler.charts.toml.template"
    fi
    : > "$EVENTS"
    run_script allium-deploy-cfcharts.sh --bootstrap-deploy
    [[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'refusing shadow config containing a route or custom domain'* && -z "$(events)" ]] \
        || fail "a charts config with '$route' was bootstrapped: $RUN_STATUS $RUN_OUTPUT"
done
# A comment that names routes is not a route.
{ cat "$TMP_DIR/charts-template.orig"; printf '# no routes. route = none; [[routes]] stay out\n'; } > "$DEPLOY_DIR/wrangler.charts.toml.template"
: > "$EVENTS"
run_script allium-deploy-cfcharts.sh --bootstrap-deploy
[[ "$RUN_STATUS" == 0 ]] || fail "a comment about routes was refused: $RUN_STATUS $RUN_OUTPUT"
cp "$TMP_DIR/charts-template.orig" "$DEPLOY_DIR/wrangler.charts.toml.template"

# The scheduled job refuses a checkout with unignored files, so the bootstrap
# fails when the deployment left one. Here the checkout is a clone of a local
# main branch, as on the build server.
git init -q --bare "$TMP_DIR/origin.git"
git -C "$DEPLOY_DIR" init -q
cp "$REPO_DIR/.gitignore" "$DEPLOY_DIR/"
git -C "$DEPLOY_DIR" add -A
git -C "$DEPLOY_DIR" -c user.name=test -c user.email=test@example.org commit -qm fixture
git -C "$DEPLOY_DIR" branch -M main
git -C "$DEPLOY_DIR" remote add origin "$TMP_DIR/origin.git"
git -C "$DEPLOY_DIR" push -q origin main
write_config CHARTS_LAYOUT=beside CF_ASSETS_REQUIRE_FRESH_CHECKOUT=true
[[ -z "$(git -C "$DEPLOY_DIR" status --porcelain --untracked-files=normal)" ]] || fail "the fixture checkout is not clean"
printf missing > "$TMP_DIR/mock-deployments"
run_script allium-deploy-cfcharts.sh --bootstrap-deploy
[[ "$RUN_STATUS" == 0 ]] || fail "a bootstrap that left the checkout clean failed: $RUN_STATUS $RUN_OUTPUT"
printf '%s' "$DEPLOY_DIR/left-behind.txt" > "$TMP_DIR/mock-leave-file"
run_script allium-deploy-cfcharts.sh --bootstrap-deploy
rm -f "$TMP_DIR/mock-leave-file"
[[ "$RUN_STATUS" == 1 && "$RUN_OUTPUT" == *'the checkout is not clean after the deployment'* && "$RUN_OUTPUT" == *'left-behind.txt'* ]] \
    || fail "a bootstrap that left a file in the checkout passed: $RUN_STATUS $RUN_OUTPUT"
rm -f "$DEPLOY_DIR/left-behind.txt"
pass "--bootstrap-deploy stages only the marked _headers and charts/404.html, runs from an empty environment, deploys only a Worker without a deployment while both layouts are beside, leaves the stage alone when it refuses, refuses routes and fails when it leaves the checkout unclean"
