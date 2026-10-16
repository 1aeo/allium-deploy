#!/usr/bin/env bash
# Verify the charts-only Worker of CHARTS_LAYOUT=charts against its stage.
#
#   <preview-url> <stage-dir> [<output-dir>]
#       The charts Worker's preview after an upload. charts/build-id.txt must
#       be the stage's build ID. With the output tree, the sample starts with
#       charts this build's pages link to: up to two from each of the pages of
#       the stage's first relay, first contact, a relay picked by the
#       preview's version and the first top-level page that links to a chart
#       (a vanity-domain page, one level deep); a page that links to no chart,
#       or to a chart the stage lacks, fails. Then charts from the stage: the
#       first relay chart, the largest, the first contact chart and a few
#       picked by the version. Each must be a 200 image/png equal to its stage
#       file, with nosniff and the preview's noindex; a repeat of the first
#       with its ETag must get 304; a missing chart must get the 404 page
#       charts/404.html. An empty stage fails.
#   --route <site-url> <stage-dir> [<output-dir>]
#       Production, after the charts Worker's promotion:
#       <site-url>/charts/build-id.txt must be the stage's build ID, a new
#       value in every stage, which proves that the <host>/charts/* route
#       reaches the version uploaded from this stage. Then the charts the
#       pages link to, sampled as above but without the version's pick, and
#       the stage's first relay chart, largest and first contact chart, under
#       <site-url>/charts/, must each be a 200 image/png equal to its stage
#       file, without X-Robots-Tag; a missing chart must get the 404 page.
#   --route-bootstrap <site-url> <stage-dir>
#       Production, after the bootstrap deployment (a stage of _headers and
#       charts/404.html) and the route, before the layout changes:
#       <site-url>/charts/404.html must be a 200 text/html equal to the
#       stage's, and a missing chart must get it as the 404 page, both
#       without X-Robots-Tag. The main Worker answers both with its own 404.
#   --redirects <site-url> <stage-dir>
#       Production, after the main Worker's promotion: the old URLs of the
#       first relay chart and the first contact chart must get a 302 to their
#       /charts/ paths.
#
# Every answer of the charts Worker (the build ID, charts, the 404 page) must
# carry the marker header X-Allium-Origin: charts from its _headers: the main
# Worker's 404 page is byte for byte the same, but has no marker.
#
# Redirects are never followed. Check sets are retried as in
# allium-deploy-verify-cfassets.sh; the production checks need one pass, which
# shows what the location that answered serves. Exit status: 0 passed; 1
# failed; 2 bad arguments or stage. --route and --route-bootstrap exit 75
# instead of 1 when the failures were inconclusive: network errors,
# Cloudflare challenges (cf-mitigated) and 403, 429 or 5xx answers, which do
# not show what production serves. A wrong answer in any attempt (404, wrong
# type or bytes, another build ID, no marker, X-Robots-Tag) makes it 1.

set -euo pipefail

CHECK=preview
case "${1:-}" in
    --route) CHECK=route; shift ;;
    --route-bootstrap) CHECK=bootstrap; shift ;;
    --redirects) CHECK=redirects; shift ;;
esac
BASE_URL="${1:-}"
STAGE_DIR="${2:-}"
OUTPUT_TREE="${3:-}"
REQUIRED_PASSES="${CF_ASSETS_VERIFY_ATTEMPTS:-3}"
MAX_ATTEMPTS="${CF_ASSETS_VERIFY_MAX_ATTEMPTS:-12}"
RETRY_DELAY="${CF_ASSETS_VERIFY_RETRY_DELAY:-10}"
CURL_TIMEOUT="${CF_ASSETS_VERIFY_CURL_TIMEOUT:-60}"
SEEDED_SAMPLES=3
REFS_PER_PAGE=2
MISSING_CHART_PATH='/charts/relay/__allium_cfcharts_missing_probe__/bandwidth-1m.png'
# Written into every stage by allium-deploy-cfassets.sh.
BUILD_ID_PATH='charts/build-id.txt'
# Added to the stage's _headers by allium-deploy-cfassets.sh.
ORIGIN_HEADER='x-allium-origin'
ORIGIN_VALUE='charts'
EXIT_INCONCLUSIVE=75

if [[ -z "$BASE_URL" || -z "$STAGE_DIR" || ( "$CHECK" =~ ^(redirects|bootstrap)$ && -n "$OUTPUT_TREE" ) ]]; then
    echo "Usage: $0 <preview-url> <stage-dir> [<output-dir>] | --route <site-url> <stage-dir> [<output-dir>] | --route-bootstrap <site-url> <stage-dir> | --redirects <site-url> <stage-dir>" >&2
    exit 2
fi
if [[ "$CHECK" != preview ]]; then
    REQUIRED_PASSES=1
fi

BASE_URL="${BASE_URL%/}"
for dir_var in STAGE_DIR OUTPUT_TREE; do
    while [[ "${!dir_var}" == */ && "${!dir_var}" != / ]]; do
        printf -v "$dir_var" '%s' "${!dir_var%/}"
    done
done
[[ -d "$STAGE_DIR" ]] || { echo "Stage directory not found: $STAGE_DIR" >&2; exit 2; }
[[ -z "$OUTPUT_TREE" || -d "$OUTPUT_TREE" ]] || { echo "Output directory not found: $OUTPUT_TREE" >&2; exit 2; }

for required in curl sha256sum find sort awk tr grep sed; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "Required command not found: $required" >&2
        exit 2
    fi
done

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

log() {
    printf '[CF-Charts-Verify] %s\n' "$1"
}

lower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# header_value <headers file> <lower-case name>: the first value, after the
# colon and any whitespace (HTTP allows none), without CR.
header_value() {
    awk -v name="$2" '{
        gsub(/\r/, "")
        i = index($0, ":")
        if (i > 1 && tolower(substr($0, 1, i - 1)) == name) {
            value = substr($0, i + 1)
            sub(/^[ \t]+/, "", value)
            print value
            exit
        }
    }' "$1"
}

# media_type_is <header value> <type>: the media type, compared without
# regard to case, is <type>, optionally followed by parameters.
media_type_is() {
    [[ "$(lower "$1")" =~ ^$2[[:space:]]*(\;.*)?$ ]]
}

sha256_of() {
    sha256sum "$1" | awk '{print $1}'
}

# One "size<TAB>path" record per staged chart, the path relative to the stage:
# regular files named *.png two levels below charts/relay or charts/contact.
# GNU find prints sizes itself; BSD find has no -printf, so stat each file.
# Paths with a newline are skipped.
chart_records() {
    local root chart
    local -a roots=()

    for root in charts/relay charts/contact; do
        if [[ -d "$STAGE_DIR/$root" ]]; then
            roots+=("$root")
        fi
    done
    (( ${#roots[@]} > 0 )) || return 0

    if [[ "$(find "$STAGE_DIR" -maxdepth 0 -printf '%s' 2>/dev/null)" =~ ^[0-9]+$ ]]; then
        (cd "$STAGE_DIR" && find "${roots[@]}" -mindepth 2 -maxdepth 2 -type f -name '*.png' ! -path $'*\n*' -printf '%s\t%p\n')
    else
        (cd "$STAGE_DIR" && find "${roots[@]}" -mindepth 2 -maxdepth 2 -type f -name '*.png' ! -path $'*\n*' -print) |
            while IFS= read -r chart; do
                printf '%s\t%s\n' "$(stat -c '%s' "$STAGE_DIR/$chart" 2>/dev/null || stat -f '%z' "$STAGE_DIR/$chart")" "$chart"
            done
    fi
}

# select_samples <seed> <seeded picks> <with largest: 0|1>: read "size<TAB>path"
# records sorted by path and print one path per line: the first relay chart
# (else the first chart), the largest (the first of equal sizes), the first
# contact chart, then picks from a Park-Miller sequence seeded by <seed>. A path
# is printed once.
select_samples() {
    awk -F '\t' -v seed="$1" -v seeded="$2" -v with_largest="$3" '
        function pick(i) {
            if (!(i in picked)) {
                picked[i] = 1
                print path[i]
            }
        }
        {
            size[NR] = $1 + 0
            path[NR] = substr($0, length($1) + 2)
        }
        END {
            if (NR == 0) exit
            first = 1
            for (i = 1; i <= NR; i++) if (path[i] ~ /^charts\/relay\//) { first = i; break }
            pick(first)
            if (with_largest) {
                largest = 1
                for (i = 2; i <= NR; i++) if (size[i] > size[largest]) largest = i
                pick(largest)
            }
            for (i = 1; i <= NR; i++) if (path[i] ~ /^charts\/contact\//) { pick(i); break }
            state = seed % 2147483647
            if (state == 0) state = 1
            for (n = 0; n < seeded; n++) {
                state = (state * 48271) % 2147483647
                pick(state % NR + 1)
            }
        }
    '
}

# resolve_ref <page directory> <src>: the path below the site root that a
# relative or root-relative src of a page in that directory names, without
# query or fragment; nothing for other URLs or a path above the root.
resolve_ref() {
    local dir="$1" ref="$2" path part
    local -a parts=() out=()

    ref="${ref%%[?#]*}"
    case "$ref" in
        ''|*:*|//*) return 0 ;;
        /*) path="${ref#/}" ;;
        *) path="$dir/$ref" ;;
    esac
    IFS=/ read -r -a parts <<< "$path"
    for part in "${parts[@]}"; do
        case "$part" in
            ''|.) ;;
            ..)
                (( ${#out[@]} > 0 )) || return 0
                out=("${out[@]:0:${#out[@]}-1}")
                ;;
            *) out+=("$part") ;;
        esac
    done
    (( ${#out[@]} > 0 )) || return 0
    (IFS=/; printf '%s\n' "${out[*]}")
}

# page_chart_refs <page>: the first REFS_PER_PAGE distinct charts, below
# charts/, that the page's src attributes name.
page_chart_refs() {
    local page="$1" ref
    { grep -o 'src="[^"]*"' "$OUTPUT_TREE/$page" || true; } |
        sed -e 's/^src="//' -e 's/"$//' |
        while IFS= read -r ref; do
            resolve_ref "${page%/*}" "$ref"
        done |
        awk -v limit="$REFS_PER_PAGE" '/^charts\/.*\.png$/ && !seen[$0]++ && ++n <= limit'
}

# top_level_chart_page: the first <dir>/index.html of the output tree that
# links to a chart below charts/ (a vanity-domain page), or nothing.
top_level_chart_page() {
    local status=0 found
    local -a pages=()

    shopt -s nullglob
    pages=("$OUTPUT_TREE"/*/index.html)
    shopt -u nullglob
    (( ${#pages[@]} > 0 )) || return 0
    found=$(grep -l -E 'src="[^"]*charts/(relay|contact)/' "${pages[@]}") || status=$?
    (( status <= 1 )) || return 1
    found="${found%%$'\n'*}"
    [[ -z "$found" ]] || printf '%s\n' "${found#"$OUTPUT_TREE"/}"
}

# html_samples <records> <seed> <with the version's pick: 0|1>: the charts
# that this build's pages link to (see the top of this file).
html_samples() {
    local records="$1" seed="$2" page ref refs total=0
    local -a pages=()

    pages+=("$(awk -F '\t' '$2 ~ /^charts\/relay\// { split($2, p, "/"); print "relay/" p[3] "/index.html"; exit }' <<< "$records")")
    pages+=("$(awk -F '\t' '$2 ~ /^charts\/contact\// { split($2, p, "/"); print "contact/" p[3] "/index.html"; exit }' <<< "$records")")
    if [[ "$3" == 1 ]]; then
        pages+=("$(awk -F '\t' -v seed="$seed" '
            $2 ~ /^charts\/relay\// { split($2, p, "/"); if (!(p[3] in seen)) { seen[p[3]] = 1; relay[++n] = p[3] } }
            END { if (n) print "relay/" relay[seed % n + 1] "/index.html" }
        ' <<< "$records")")
    fi
    page=$(top_level_chart_page) || {
        echo "Could not read the top-level pages of $OUTPUT_TREE" >&2
        return 1
    }
    pages+=("$page")

    for page in "${pages[@]}"; do
        [[ -n "$page" ]] || continue
        [[ -f "$OUTPUT_TREE/$page" ]] || {
            echo "The stage holds charts for $page, which $OUTPUT_TREE lacks" >&2
            return 1
        }
        refs=$(page_chart_refs "$page") || {
            echo "Could not read the chart links of $OUTPUT_TREE/$page" >&2
            return 1
        }
        while IFS= read -r ref; do
            [[ -n "$ref" ]] || continue
            [[ -f "$STAGE_DIR/$ref" ]] || {
                echo "$OUTPUT_TREE/$page links to /$ref, which the stage lacks" >&2
                return 1
            }
            printf '%s\n' "$ref"
            total=$((total + 1))
        done <<< "$refs"
    done
    (( total > 0 )) || {
        echo "The pages of the stage's charts link to no chart below charts/ in $OUTPUT_TREE" >&2
        return 1
    }
}

# fetch <url path> [extra curl arguments...]: sets STATUS; the response headers
# and body go to $TMP_DIR/response.headers and $TMP_DIR/response.body. A
# network error, a Cloudflare challenge and a 403, 429 or 5xx answer fail as
# inconclusive (FAILURE_KIND): they do not show what the Worker serves.
fetch() {
    local url_path="$1" mitigated
    shift
    STATUS=""
    : > "$TMP_DIR/response.headers"
    if ! STATUS=$(curl --silent --show-error --max-time "$CURL_TIMEOUT" "$@" \
        --dump-header "$TMP_DIR/response.headers" --output "$TMP_DIR/response.body" \
        --write-out '%{http_code}' "$BASE_URL$url_path"); then
        log "transient curl/network error for $BASE_URL$url_path"
        FAILURE_KIND=inconclusive
        return 1
    fi
    mitigated=$(header_value "$TMP_DIR/response.headers" cf-mitigated)
    if [[ -n "$mitigated" || "$STATUS" == 403 || "$STATUS" == 429 || "$STATUS" == 5[0-9][0-9] ]]; then
        log "inconclusive: HTTP $STATUS${mitigated:+ (cf-mitigated: $mitigated)} for $BASE_URL$url_path"
        FAILURE_KIND=inconclusive
        return 1
    fi
}

# check_charts_answer <check> <url path>: the answer carries the charts
# Worker's marker header; production sends no X-Robots-Tag.
check_charts_answer() {
    local origin robots
    origin=$(header_value "$TMP_DIR/response.headers" "$ORIGIN_HEADER")
    [[ "$(lower "$origin")" == "$ORIGIN_VALUE" ]] || {
        log "$1 failed: no X-Allium-Origin: $ORIGIN_VALUE for $2 (another Worker answered)"
        return 1
    }
    if [[ "$CHECK" == route || "$CHECK" == bootstrap ]]; then
        robots=$(header_value "$TMP_DIR/response.headers" x-robots-tag)
        [[ -z "$robots" ]] || { log "$1 failed: production sends X-Robots-Tag '$robots' for $2"; return 1; }
    fi
}

check_chart() {
    local relative="$1" url_path="/$1" content_type nosniff robots etag

    fetch "$url_path" || return 1
    [[ "$STATUS" == "200" ]] || { log "chart failed: HTTP $STATUS for $url_path"; return 1; }
    content_type=$(header_value "$TMP_DIR/response.headers" content-type)
    media_type_is "$content_type" image/png || {
        log "chart failed: unexpected Content-Type '$content_type' for $url_path"
        return 1
    }
    nosniff=$(header_value "$TMP_DIR/response.headers" x-content-type-options)
    [[ "$(lower "$nosniff")" == "nosniff" ]] || {
        log "chart failed: no X-Content-Type-Options: nosniff for $url_path"
        return 1
    }
    check_charts_answer chart "$url_path" || return 1
    if [[ "$CHECK" == preview ]]; then
        # Version URLs carry Cloudflare's own noindex value, workers.dev the
        # one from _headers: accept any value with noindex.
        robots=$(header_value "$TMP_DIR/response.headers" x-robots-tag)
        [[ "$(lower "$robots")" == *noindex* ]] || {
            log "chart failed: the preview is missing noindex for $url_path"
            return 1
        }
    fi
    [[ "$(sha256_of "$TMP_DIR/response.body")" == "$(sha256_of "$STAGE_DIR/$relative")" ]] || {
        log "chart failed: SHA-256 mismatch for $url_path"
        return 1
    }
    if [[ -z "$FIRST_ETAG" ]]; then
        etag=$(header_value "$TMP_DIR/response.headers" etag)
        [[ -n "$etag" || "$CHECK" != preview ]] || { log "chart failed: no ETag for $url_path"; return 1; }
        FIRST_ETAG="$etag"
        FIRST_PATH="$url_path"
    fi
    log "chart ok: $BASE_URL$url_path"
}

check_not_modified() {
    fetch "$FIRST_PATH" --header "If-None-Match: $FIRST_ETAG" || return 1
    [[ "$STATUS" == "304" ]] || {
        log "conditional request failed: HTTP $STATUS instead of 304 for $FIRST_PATH"
        return 1
    }
}

check_missing_chart() {
    local content_type

    fetch "$MISSING_CHART_PATH" || return 1
    [[ "$STATUS" == "404" ]] || {
        log "missing chart failed: HTTP $STATUS instead of 404"
        return 1
    }
    content_type=$(header_value "$TMP_DIR/response.headers" content-type)
    media_type_is "$content_type" text/html || {
        log "missing chart failed: unexpected Content-Type '$content_type'"
        return 1
    }
    [[ "$(sha256_of "$TMP_DIR/response.body")" == "$(sha256_of "$STAGE_DIR/charts/404.html")" ]] || {
        log "missing chart failed: the body is not charts/404.html"
        return 1
    }
    check_charts_answer "missing chart" "$MISSING_CHART_PATH" || return 1
    log "missing chart ok: 404 page for $MISSING_CHART_PATH"
}

# The bootstrap version serves its 404 page as a file too.
check_404_page() {
    local content_type

    fetch /charts/404.html || return 1
    [[ "$STATUS" == "200" ]] || { log "404 page failed: HTTP $STATUS for /charts/404.html"; return 1; }
    content_type=$(header_value "$TMP_DIR/response.headers" content-type)
    media_type_is "$content_type" text/html || {
        log "404 page failed: unexpected Content-Type '$content_type' for /charts/404.html"
        return 1
    }
    [[ "$(sha256_of "$TMP_DIR/response.body")" == "$(sha256_of "$STAGE_DIR/charts/404.html")" ]] || {
        log "404 page failed: /charts/404.html is not the stage's charts/404.html"
        return 1
    }
    check_charts_answer "404 page" /charts/404.html || return 1
    log "404 page ok: /charts/404.html"
}

# The stage's build ID differs from every other stage's: only the version
# uploaded from this stage serves it.
check_build_id() {
    fetch "/$BUILD_ID_PATH" || return 1
    [[ "$STATUS" == "200" ]] || { log "build ID failed: HTTP $STATUS for /$BUILD_ID_PATH"; return 1; }
    [[ "$(sha256_of "$TMP_DIR/response.body")" == "$(sha256_of "$STAGE_DIR/$BUILD_ID_PATH")" ]] || {
        log "build ID failed: $BASE_URL/$BUILD_ID_PATH is not this stage's build ID, $(<"$STAGE_DIR/$BUILD_ID_PATH")"
        return 1
    }
    check_charts_answer "build ID" "/$BUILD_ID_PATH" || return 1
    log "build ID ok: $(<"$STAGE_DIR/$BUILD_ID_PATH")"
}

# The main Worker's _redirects sends /relay/<fingerprint>/<name>.png and
# /contact/<hash>/<name>.png to the same path below /charts/.
check_redirect() {
    local relative="$1" old_path="/${1#charts/}" location

    fetch "$old_path" || return 1
    location=$(header_value "$TMP_DIR/response.headers" location)
    [[ "$STATUS" == "302" ]] || { log "redirect failed: HTTP $STATUS for $old_path"; return 1; }
    [[ "$location" == "/$relative" || "$location" == "$BASE_URL/$relative" ]] || {
        log "redirect failed: $old_path redirects to '$location', not /$relative"
        return 1
    }
    log "redirect ok: $BASE_URL$old_path -> /$relative"
}

# One check set. A failure leaves FAILURE_KIND at definitive unless fetch
# found it inconclusive.
run_check_set() {
    local sample

    FIRST_ETAG=""
    FIRST_PATH=""
    FAILURE_KIND=definitive
    if [[ "$CHECK" == bootstrap ]]; then
        check_404_page || return 1
    elif [[ "$CHECK" != redirects ]]; then
        check_build_id || return 1
    fi
    for sample in "${SAMPLES[@]}"; do
        if [[ "$CHECK" == redirects ]]; then
            check_redirect "$sample" || return 1
        else
            check_chart "$sample" || return 1
        fi
    done
    if [[ "$CHECK" == preview ]]; then
        check_not_modified || return 1
        log "conditional check ok: 304 for $FIRST_PATH"
    fi
    if [[ "$CHECK" != redirects ]]; then
        check_missing_chart || return 1
    fi
}

[[ "$REQUIRED_PASSES" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid required pass count: $REQUIRED_PASSES" >&2; exit 2; }
[[ "$MAX_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid max attempt count: $MAX_ATTEMPTS" >&2; exit 2; }
(( MAX_ATTEMPTS >= REQUIRED_PASSES )) || { echo "Max attempts must be at least required passes" >&2; exit 2; }

RECORDS=$(chart_records | LC_ALL=C sort -t $'\t' -k2) || {
    echo "Could not list the chart PNGs under $STAGE_DIR" >&2
    exit 2
}
if [[ -z "$RECORDS" && "$CHECK" != bootstrap ]]; then
    echo "No chart PNG to verify under $STAGE_DIR (charts/relay/*/*.png or charts/contact/*/*.png)" >&2
    exit 2
fi
if [[ "$CHECK" != redirects && ! -f "$STAGE_DIR/charts/404.html" ]]; then
    echo "The stage has no charts/404.html: $STAGE_DIR" >&2
    exit 2
fi
if [[ "$CHECK" =~ ^(preview|route)$ && ! -f "$STAGE_DIR/$BUILD_ID_PATH" ]]; then
    echo "The stage has no $BUILD_ID_PATH: $STAGE_DIR" >&2
    exit 2
fi

SAMPLES=()
SAMPLE_LIST=""
case "$CHECK" in
    preview)
        # A preview URL starts with the first eight hex digits of its version.
        preview_host="${BASE_URL#*://}"
        preview_host="${preview_host%%/*}"
        version_prefix="${preview_host%%-*}"
        if [[ "$version_prefix" =~ ^[0-9a-f]{8}$ ]]; then
            SEED=$((16#$version_prefix))
        else
            SEED=$(printf '%s' "$BASE_URL" | cksum | awk '{print $1}')
        fi
        if [[ -n "$OUTPUT_TREE" ]]; then
            SAMPLE_LIST=$(html_samples "$RECORDS" "$SEED" 1) || exit 2
        fi
        SAMPLE_LIST+=$'\n'$(select_samples "$SEED" "$SEEDED_SAMPLES" 1 <<< "$RECORDS")
        ;;
    route)
        if [[ -n "$OUTPUT_TREE" ]]; then
            SAMPLE_LIST=$(html_samples "$RECORDS" 1 0) || exit 2
        fi
        SAMPLE_LIST+=$'\n'$(select_samples 1 0 1 <<< "$RECORDS")
        ;;
    redirects) SAMPLE_LIST=$(select_samples 1 0 0 <<< "$RECORDS") ;;
esac
while IFS= read -r sample; do
    SAMPLES+=("$sample")
done < <(awk 'NF && !seen[$0]++' <<< "$SAMPLE_LIST")
if [[ "$CHECK" == bootstrap ]]; then
    log "bootstrap route check: the 404 page of $STAGE_DIR for $BASE_URL"
else
    log "$CHECK check: sampled ${#SAMPLES[@]} of $(wc -l <<< "$RECORDS" | tr -d ' ') charts in $STAGE_DIR for $BASE_URL"
fi

consecutive=0
definitive_failure=false
for ((attempt=1; attempt<=MAX_ATTEMPTS; attempt++)); do
    log "verification attempt $attempt/$MAX_ATTEMPTS; consecutive=$consecutive/$REQUIRED_PASSES for $BASE_URL"
    if run_check_set; then
        consecutive=$((consecutive + 1))
        if (( consecutive >= REQUIRED_PASSES )); then
            log "all chart checks passed $REQUIRED_PASSES consecutive times for $BASE_URL"
            exit 0
        fi
    else
        consecutive=0
        [[ "$FAILURE_KIND" == inconclusive ]] || definitive_failure=true
        log "attempt $attempt did not pass ($FAILURE_KIND); waiting ${RETRY_DELAY}s for a bounded transient retry"
    fi

    if (( attempt < MAX_ATTEMPTS )); then
        sleep "$RETRY_DELAY"
    fi
done

log "verification failed: $REQUIRED_PASSES consecutive passes were not reached in $MAX_ATTEMPTS attempts"
case "$CHECK" in
    route|bootstrap)
        if [[ "$definitive_failure" == false ]]; then
            log "inconclusive: every failed attempt met a network error, a Cloudflare challenge or a 403, 429 or 5xx answer, so what $BASE_URL/charts/ serves is unknown"
            exit "$EXIT_INCONCLUSIVE"
        fi
        log "$BASE_URL/charts/ does not serve this stage: the <host>/charts/* route is missing or reaches another Worker or version"
        ;;
    redirects) log "$BASE_URL does not redirect old chart URLs to /charts/: the promoted main Worker version lacks the CHARTS_LAYOUT=charts _redirects" ;;
esac
exit 1
