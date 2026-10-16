#!/usr/bin/env bash
# Upload and verify an immutable Allium Workers Static Assets version. Optional
# promotion is a separate, guarded action that accepts only the last version
# written after successful preview verification.
#
# CF_ASSETS_PROFILE, which only the caller sets, selects the Worker: main (the
# default) serves the site; charts is the charts-only Worker of
# CHARTS_LAYOUT=charts, run by scripts/allium-deploy-cfcharts.sh with its own
# name, staged directory, template, verifier and state files.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

CF_ASSETS_PROFILE="${CF_ASSETS_PROFILE:-main}"
case "$CF_ASSETS_PROFILE" in
    main|charts) ;;
    *) echo "Invalid CF_ASSETS_PROFILE=$CF_ASSETS_PROFILE; expected main or charts" >&2; exit 2 ;;
esac
SELECTED_PROFILE="$CF_ASSETS_PROFILE"

MODE="${1:---upload-only}"
case "$MODE" in
    --upload-only|--generate-only|--promote) ;;
    --bootstrap-deploy) [[ "$CF_ASSETS_PROFILE" == "charts" ]] || MODE=invalid ;;
    *) MODE=invalid ;;
esac
if [[ "$MODE" == invalid ]]; then
    echo "Usage: $0 [--upload-only|--generate-only|--promote]" >&2
    exit 2
fi

CF_ASSETS_ENV_OVERRIDES=(
    OUTPUT_DIR
    CHARTS_LAYOUT
    ALLIUM_NO_CHARTS
    CF_ASSETS_ENABLED
    CF_ASSETS_ALLOW_PROMOTION
    CF_ASSETS_WORKER_NAME
    CF_ASSETS_PREVIEW_ALIAS
    CF_ASSETS_COMPATIBILITY_DATE
    CF_ASSETS_DIRECTORY
    CF_ASSETS_TEMPLATE
    CF_ASSETS_CONFIG
    CF_ASSETS_HEADERS_SOURCE
    CF_ASSETS_404_SOURCE
    CF_ASSETS_VERIFY_SCRIPT
    CF_ASSETS_CONSECUTIVE_FILE
    CF_ASSETS_LAST_VERSION_FILE
    CF_ASSETS_SUMMARY_FILE
    CF_ASSETS_PROMOTION_SUMMARY_FILE
    CF_ASSETS_REQUIRE_FRESH_CHECKOUT
    CF_ASSETS_EXPECTED_DEPLOY_SHA
    CF_ASSETS_VERIFY_ATTEMPTS
    CF_ASSETS_VERIFY_MAX_ATTEMPTS
    CF_ASSETS_VERIFY_RETRY_DELAY
    CF_ASSETS_VERIFY_CURL_TIMEOUT
    CF_ASSETS_UPLOAD_MAX_ATTEMPTS
    CF_ASSETS_UPLOAD_RETRY_DELAY
    CF_ASSETS_UPLOADS_FILE
    CF_ASSETS_MAX_FILES
    CF_ASSETS_WARN_FILES
    CF_CHARTS_SOURCE_DIRECTORY
    CF_CHARTS_LIVE_LIST
    WRANGLER_LOG
    WRANGLER_LOG_PATH
    WRANGLER_LOG_SANITIZE
)
capture_env_overrides "${CF_ASSETS_ENV_OVERRIDES[@]}"

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    # shellcheck disable=SC1091
    source "$DEPLOY_DIR/config.env"
fi

restore_env_overrides "${CF_ASSETS_ENV_OVERRIDES[@]}"
CF_ASSETS_PROFILE="$SELECTED_PROFILE"

CHARTS_LAYOUT="${CHARTS_LAYOUT:-beside}"
# Allium ran with --no-charts: the tree has no chart.
ALLIUM_NO_CHARTS="${ALLIUM_NO_CHARTS:-false}"
CF_ASSETS_ENABLED="${CF_ASSETS_ENABLED:-false}"
CF_ASSETS_ALLOW_PROMOTION="${CF_ASSETS_ALLOW_PROMOTION:-false}"
CF_ASSETS_WORKER_NAME="${CF_ASSETS_WORKER_NAME:-allium-metrics-assets}"
CF_ASSETS_PREVIEW_ALIAS="${CF_ASSETS_PREVIEW_ALIAS:-allium-candidate}"
CF_ASSETS_COMPATIBILITY_DATE="${CF_ASSETS_COMPATIBILITY_DATE:-2026-07-26}"
CF_ASSETS_DIRECTORY="${CF_ASSETS_DIRECTORY:-${OUTPUT_DIR:-$HOME/metrics-output}}"
CF_ASSETS_TEMPLATE="${CF_ASSETS_TEMPLATE:-$DEPLOY_DIR/wrangler.assets.toml.template}"
CF_ASSETS_CONFIG="${CF_ASSETS_CONFIG:-$DEPLOY_DIR/wrangler.assets.toml}"
CF_ASSETS_HEADERS_SOURCE="${CF_ASSETS_HEADERS_SOURCE:-$DEPLOY_DIR/cloudflare-assets/_headers}"
CF_ASSETS_404_SOURCE="${CF_ASSETS_404_SOURCE:-$DEPLOY_DIR/cloudflare-assets/404.html}"
CF_ASSETS_VERIFY_SCRIPT="${CF_ASSETS_VERIFY_SCRIPT:-$SCRIPT_DIR/allium-deploy-verify-cfassets.sh}"
CF_ASSETS_CONSECUTIVE_FILE="${CF_ASSETS_CONSECUTIVE_FILE:-$DEPLOY_DIR/logs/cfassets-shadow-consecutive-successes}"
CF_ASSETS_LAST_VERSION_FILE="${CF_ASSETS_LAST_VERSION_FILE:-$DEPLOY_DIR/logs/cfassets-last-version}"
CF_ASSETS_SUMMARY_FILE="${CF_ASSETS_SUMMARY_FILE:-$DEPLOY_DIR/logs/cfassets-shadow-summary.tsv}"
CF_ASSETS_PROMOTION_SUMMARY_FILE="${CF_ASSETS_PROMOTION_SUMMARY_FILE:-$DEPLOY_DIR/logs/cfassets-promotion-summary.tsv}"
CF_ASSETS_UPLOADS_FILE="${CF_ASSETS_UPLOADS_FILE:-$DEPLOY_DIR/logs/cfassets-uploads.tsv}"
CF_ASSETS_MAX_FILES="${CF_ASSETS_MAX_FILES:-100000}"
# The warning level. The main Worker's version holds about a third of the
# files once the charts move to their own Worker, so warn much earlier then;
# allium-deploy-cfcharts.sh sets the charts Worker's level.
if [[ -z "${CF_ASSETS_WARN_FILES:-}" && "$CF_ASSETS_PROFILE" == "main" && "$CHARTS_LAYOUT" == "charts" ]]; then
    CF_ASSETS_WARN_FILES=60000
fi
CF_ASSETS_WARN_FILES="${CF_ASSETS_WARN_FILES:-98000}"
# The main Worker's assets directory, which the charts profile stages from.
CF_CHARTS_SOURCE_DIRECTORY="${CF_CHARTS_SOURCE_DIRECTORY:-}"
# The charts that the live main Worker version's pages link, one charts/...
# path per line, written by the update job after each main promotion in the
# charts layout (see keep_live_charts).
CF_CHARTS_LIVE_LIST="${CF_CHARTS_LIVE_LIST:-$DEPLOY_DIR/logs/cfcharts-live-charts}"
# CHARTS_LAYOUT=charts: the main Worker's root .assetsignore and _redirects,
# each from <name>.charts here.
CHARTS_CONTROL_SOURCES="$DEPLOY_DIR/cloudflare-assets"
# The charts stage's build ID, a new value in every stage: the charts verifier
# fetches it to prove which version a URL serves.
CHARTS_BUILD_ID=charts/build-id.txt
# Every answer of the charts Worker carries this header, which the charts
# verifier requires: its 404 page is byte for byte the main Worker's.
CHARTS_ORIGIN_HEADER='X-Allium-Origin: charts'

export CF_ASSETS_VERIFY_ATTEMPTS="${CF_ASSETS_VERIFY_ATTEMPTS:-3}"
export CF_ASSETS_VERIFY_MAX_ATTEMPTS="${CF_ASSETS_VERIFY_MAX_ATTEMPTS:-12}"
export CF_ASSETS_VERIFY_RETRY_DELAY="${CF_ASSETS_VERIFY_RETRY_DELAY:-10}"
export CF_ASSETS_VERIFY_CURL_TIMEOUT="${CF_ASSETS_VERIFY_CURL_TIMEOUT:-60}"
CF_ASSETS_UPLOAD_MAX_ATTEMPTS="${CF_ASSETS_UPLOAD_MAX_ATTEMPTS:-3}"
CF_ASSETS_UPLOAD_RETRY_DELAY="${CF_ASSETS_UPLOAD_RETRY_DELAY:-15}"
WRANGLER_LOG="${WRANGLER_LOG:-error}"
WRANGLER_DEFAULT_LOG_PATH="$DEPLOY_DIR/logs/wrangler-debug-sink.log"
WRANGLER_LOG_PATH="${WRANGLER_LOG_PATH:-$WRANGLER_DEFAULT_LOG_PATH}"
WRANGLER_LOG_SANITIZE="${WRANGLER_LOG_SANITIZE:-true}"

LOG_PREFIX='[CF-Assets]'
if [[ "$CF_ASSETS_PROFILE" == "charts" ]]; then
    LOG_PREFIX='[CF-Charts]'
fi

log() {
    printf '%s %s\n' "$LOG_PREFIX" "$1"
}

assert_boolean_setting() {
    local name="$1"
    local value="$2"

    case "$value" in
        true|false) return 0 ;;
        *)
            log "invalid $name=$value; expected true or false"
            return 2
            ;;
    esac
}

assert_safe_worker_name() {
    [[ "$CF_ASSETS_WORKER_NAME" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || {
        log "invalid worker name: $CF_ASSETS_WORKER_NAME"
        return 1
    }
    [[ "$CF_ASSETS_PREVIEW_ALIAS" =~ ^[a-z][a-z0-9-]*$ ]] || {
        log "invalid preview alias: $CF_ASSETS_PREVIEW_ALIAS"
        return 1
    }
}

assert_fresh_checkout() {
    if [[ "${CF_ASSETS_REQUIRE_FRESH_CHECKOUT:-true}" != "true" ]]; then
        return 0
    fi

    local head_sha origin_sha dirty expected_sha
    head_sha=$(git -C "$DEPLOY_DIR" rev-parse HEAD)
    dirty=$(git -C "$DEPLOY_DIR" status --porcelain --untracked-files=normal)

    expected_sha="${CF_ASSETS_EXPECTED_DEPLOY_SHA:-}"
    if [[ -n "$expected_sha" ]]; then
        [[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]] || {
            log "refusing upload: pinned job SHA is malformed"
            return 1
        }
        [[ "$head_sha" == "$expected_sha" ]] || {
            log "refusing upload: checkout HEAD $head_sha does not match pinned job SHA $expected_sha"
            return 1
        }
    else
        run_with_timeout 30 git -C "$DEPLOY_DIR" fetch --quiet origin main
        origin_sha=$(git -C "$DEPLOY_DIR" rev-parse origin/main)
        [[ "$head_sha" == "$origin_sha" ]] || {
            log "refusing upload: checkout HEAD $head_sha does not match origin/main $origin_sha"
            return 1
        }
    fi
    [[ -z "$dirty" ]] || {
        log "refusing upload: checkout has tracked or unignored changes"
        printf '%s\n' "$dirty" >&2
        return 1
    }
}

escape_sed_replacement() {
    printf '%s' "$1" | sed 's/[&|]/\\&/g'
}

assert_charts_layout() {
    case "$CHARTS_LAYOUT" in
        beside|charts) return 0 ;;
        *)
            log "invalid CHARTS_LAYOUT=$CHARTS_LAYOUT; expected beside or charts"
            return 2
            ;;
    esac
}

assert_file_limits() {
    local name
    for name in CF_ASSETS_MAX_FILES CF_ASSETS_WARN_FILES; do
        [[ "${!name}" =~ ^[1-9][0-9]*$ ]] || {
            log "invalid $name=${!name}"
            return 2
        }
    done
}

# count_tree <directory> <true|false>: count the files Wrangler uploads from
# the directory. Wrangler always skips the root _headers, _redirects and
# .assetsignore (nested files with those names are ordinary assets), matches
# ignore patterns ignoring case, and uploads the file a symbolic link points
# to. With true, the main Worker's CHARTS_LAYOUT=charts .assetsignore
# (/charts/) also drops everything below a top-level charts directory. Sets
# TREE_FILES (uploaded), TREE_IGNORED (dropped by /charts/) and TREE_ODD: up to
# five dropped files that the charts stage does not take, as it takes only
# regular *.png files below charts/. Newlines in names become "?" so that
# every file is one record; find prints every path with a leading "./", so the
# bare "symlinks" record separating regular files from symbolic links never
# collides with one.
count_tree() {
    local report
    report=$(
        (cd "$1" && find . -type f -print0 && printf 'symlinks\0' && find . -type l -print0) |
            LC_ALL=C tr '\n\0' '?\n' | LC_ALL=C awk -F/ -v ignore_charts="$2" '
            $0 == "symlinks" { links = 1; next }
            {
                lower = tolower($0)
                if (lower == "./_headers" || lower == "./_redirects" || lower == "./.assetsignore") next
                if (ignore_charts == "true" && NF > 2 && tolower($2) == "charts") {
                    ignored++
                    if ((links || $2 != "charts" || $NF !~ /\.png$/) && ++odd <= 5) {
                        examples = examples "\n" substr($0, 3)
                    }
                    next
                }
                files++
            }
            END { printf "%d %d%s\n", files, ignored, examples }
        '
    ) || {
        log "could not list the files under $1"
        return 1
    }
    read -r TREE_FILES TREE_IGNORED <<< "${report%%$'\n'*}"
    TREE_ODD=""
    if [[ "$report" == *$'\n'* ]]; then
        TREE_ODD="${report#*$'\n'}"
    fi
}

# Cloudflare limits the files in one Worker version, and Wrangler does not
# check the limit before it uploads. Count what Wrangler would upload and
# refuse early (exit status 4), with a warning as the count approaches the
# limit: when the version is prepared (--generate-only), so that the update job
# can hold every publisher in a build that switches the chart layout, and
# again before the upload. Sets UPLOAD_FILE_COUNT.
check_upload_file_count() {
    local ignore_charts=false hint=""

    if [[ "$CF_ASSETS_PROFILE" == "main" && "$CHARTS_LAYOUT" == "charts" ]]; then
        ignore_charts=true
    elif [[ "$CF_ASSETS_PROFILE" == "main" ]]; then
        hint="; CHARTS_LAYOUT=charts moves the chart PNGs to a Worker of their own"
    fi
    count_tree "$CF_ASSETS_DIRECTORY" "$ignore_charts"
    UPLOAD_FILE_COUNT="$TREE_FILES"

    if (( UPLOAD_FILE_COUNT > CF_ASSETS_MAX_FILES )); then
        log "refusing upload: $UPLOAD_FILE_COUNT files exceed the limit of $CF_ASSETS_MAX_FILES files per Worker version$hint"
        return 4
    fi
    if (( UPLOAD_FILE_COUNT >= CF_ASSETS_WARN_FILES )); then
        log "warning: $UPLOAD_FILE_COUNT files approach the limit of $CF_ASSETS_MAX_FILES files per Worker version$hint"
    fi
}

# The assets directory persists across builds, and Wrangler and the asset
# worker act on these root files whenever they exist: .assetsignore drops
# matching files from every upload, and _redirects applies even when an asset
# matches. This code writes both only for CHARTS_LAYOUT=charts, so otherwise
# remove any copy, for example one left behind by a build with that layout, or
# by a newer commit that was reverted or undone by a guarded-pull rollback.
# Code that starts writing one of them must keep removing it here whenever the
# current configuration does not use it.
remove_unowned_control_files() {
    local name
    [[ "$CHARTS_LAYOUT" != "charts" ]] || return 0
    for name in .assetsignore _redirects; do
        if [[ -e "$CF_ASSETS_DIRECTORY/$name" || -L "$CF_ASSETS_DIRECTORY/$name" ]]; then
            rm -f -- "$CF_ASSETS_DIRECTORY/$name" || {
                log "could not remove stale $name from $CF_ASSETS_DIRECTORY"
                return 1
            }
            log "removed stale $name from $CF_ASSETS_DIRECTORY: CHARTS_LAYOUT=$CHARTS_LAYOUT does not use it"
        fi
    done
}

# first_chart <prefix>: the first chart PNG, two levels below <prefix>relay or
# <prefix>contact of the assets directory, or nothing.
first_chart() {
    local root
    local -a roots=()
    for root in "${1}relay" "${1}contact"; do
        if [[ -d "$CF_ASSETS_DIRECTORY/$root" ]]; then
            roots+=("$root")
        fi
    done
    (( ${#roots[@]} > 0 )) || return 0
    (cd "$CF_ASSETS_DIRECTORY" && find "${roots[@]}" -mindepth 2 -maxdepth 2 -type f -name '*.png' -print -quit)
}

# CHARTS_LAYOUT=charts needs a tree that Allium wrote with --chart-layout
# charts: charts below charts/ (none with ALLIUM_NO_CHARTS=true) and none
# beside their pages. Otherwise, for example after a job that started before
# this layout was set, _redirects would send every chart URL to /charts/.
assert_charts_layout_tree() {
    local chart

    chart=$(first_chart "") || { log "could not list the charts of $CF_ASSETS_DIRECTORY"; return 1; }
    if [[ -n "$chart" ]]; then
        log "refusing config: CHARTS_LAYOUT=charts, but $CF_ASSETS_DIRECTORY/$chart is beside its page (Allium ran without --chart-layout charts)"
        return 1
    fi
    [[ "$ALLIUM_NO_CHARTS" != "true" ]] || return 0
    chart=$(first_chart charts/) || { log "could not list the charts of $CF_ASSETS_DIRECTORY"; return 1; }
    if [[ -z "$chart" ]]; then
        log "refusing config: CHARTS_LAYOUT=charts, but $CF_ASSETS_DIRECTORY has no chart PNG below charts/relay or charts/contact"
        return 1
    fi
}

# CHARTS_LAYOUT=beside: an Allium without --chart-layout keeps the charts/relay
# and charts/contact that a CHARTS_LAYOUT=charts build left, which the main
# Worker and the mirrors would publish beside the charts it writes next to
# the pages. Remove them, as Allium's own clear_chart_tree does, and charts/
# when that empties it. Never delete through a symbolic link.
remove_leftover_chart_tree() {
    local kind
    [[ "$CHARTS_LAYOUT" == "beside" ]] || return 0
    if [[ -L "$CF_ASSETS_DIRECTORY/charts" ]]; then
        log "refusing config: $CF_ASSETS_DIRECTORY/charts is a symbolic link"
        return 1
    fi
    for kind in relay contact; do
        if [[ -e "$CF_ASSETS_DIRECTORY/charts/$kind" || -L "$CF_ASSETS_DIRECTORY/charts/$kind" ]]; then
            rm -rf -- "$CF_ASSETS_DIRECTORY/charts/$kind" || {
                log "could not remove the leftover charts/$kind from $CF_ASSETS_DIRECTORY"
                return 1
            }
            log "warning: removed the leftover charts/$kind from $CF_ASSETS_DIRECTORY: CHARTS_LAYOUT=$CHARTS_LAYOUT does not use it"
        fi
    done
    rmdir -- "$CF_ASSETS_DIRECTORY/charts" 2>/dev/null || true
}

# CHARTS_LAYOUT=charts: the main Worker drops /charts/, which the charts Worker
# serves on its own route, and redirects the old chart URLs there. Never write
# through a symbolic link, and fail closed on a directory.
install_charts_control_files() {
    local name source target
    for name in .assetsignore _redirects; do
        source="$CHARTS_CONTROL_SOURCES/$name.charts"
        target="$CF_ASSETS_DIRECTORY/$name"
        [[ -f "$source" ]] || { log "missing $name source: $source"; return 1; }
        if [[ -L "$target" || ( -e "$target" && ! -f "$target" ) ]]; then
            rm -f -- "$target" || { log "could not replace $target"; return 1; }
        fi
        if ! cmp -s "$source" "$target"; then
            install -m 0644 "$source" "$target"
        fi
    done
}

# .assetsignore and _redirects go together: the main Worker may drop /charts/
# only while it redirects the old chart URLs there, and the reverse. Require
# both, as installed, with CHARTS_LAYOUT=charts, and neither otherwise.
assert_control_files_match_layout() {
    local name target
    for name in .assetsignore _redirects; do
        target="$CF_ASSETS_DIRECTORY/$name"
        if [[ "$CHARTS_LAYOUT" == "charts" ]]; then
            if [[ -L "$target" || ! -f "$target" ]] || ! cmp -s "$CHARTS_CONTROL_SOURCES/$name.charts" "$target"; then
                log "refusing config: $target is not the CHARTS_LAYOUT=charts $name"
                return 1
            fi
        elif [[ -e "$target" || -L "$target" ]]; then
            log "refusing config: $target exists with CHARTS_LAYOUT=$CHARTS_LAYOUT"
            return 1
        fi
    done
}

# The config is rendered beside itself and renamed into place. The temporary
# file is gitignored: the main and charts uploads run together, and each checks
# that the checkout is clean while the other may be rendering.
render_config() {
    local worker_name compatibility_date assets_directory config_lines

    worker_name=$(escape_sed_replacement "$CF_ASSETS_WORKER_NAME")
    compatibility_date=$(escape_sed_replacement "$CF_ASSETS_COMPATIBILITY_DATE")
    assets_directory=$(escape_sed_replacement "$CF_ASSETS_DIRECTORY")

    sed -e "s|{{CF_ASSETS_WORKER_NAME}}|$worker_name|g" \
        -e "s|{{CF_ASSETS_COMPATIBILITY_DATE}}|$compatibility_date|g" \
        -e "s|{{CF_ASSETS_DIRECTORY}}|$assets_directory|g" \
        "$CF_ASSETS_TEMPLATE" > "$CF_ASSETS_CONFIG.tmp"
    mv "$CF_ASSETS_CONFIG.tmp" "$CF_ASSETS_CONFIG"

    # route = ..., routes = [...], route.pattern = ..., [route], [[routes]] and
    # custom_domain = true, outside comment lines.
    config_lines=$(grep -v '^[[:space:]]*#' "$CF_ASSETS_CONFIG" || true)
    if grep -Eq '(^|[[:space:]])routes?[[:space:]]*[=.]|^[[:space:]]*\[+[[:space:]]*routes?[[:space:]]*[].]|custom_domain[[:space:]]*=' <<< "$config_lines"; then
        log "refusing shadow config containing a route or custom domain"
        return 1
    fi
}

generate_config() {
    if [[ "$CF_ASSETS_PROFILE" == "charts" ]]; then
        generate_charts_config
        return
    fi

    [[ -f "$CF_ASSETS_TEMPLATE" ]] || { log "missing template: $CF_ASSETS_TEMPLATE"; return 1; }
    [[ -d "$CF_ASSETS_DIRECTORY" ]] || { log "missing assets directory: $CF_ASSETS_DIRECTORY"; return 1; }
    [[ -f "$CF_ASSETS_HEADERS_SOURCE" ]] || { log "missing headers source: $CF_ASSETS_HEADERS_SOURCE"; return 1; }
    [[ -f "$CF_ASSETS_404_SOURCE" ]] || { log "missing 404 source: $CF_ASSETS_404_SOURCE"; return 1; }

    remove_unowned_control_files
    remove_leftover_chart_tree

    if ! cmp -s "$CF_ASSETS_HEADERS_SOURCE" "$CF_ASSETS_DIRECTORY/_headers"; then
        install -m 0644 "$CF_ASSETS_HEADERS_SOURCE" "$CF_ASSETS_DIRECTORY/_headers"
    fi
    if ! cmp -s "$CF_ASSETS_404_SOURCE" "$CF_ASSETS_DIRECTORY/404.html"; then
        install -m 0644 "$CF_ASSETS_404_SOURCE" "$CF_ASSETS_DIRECTORY/404.html"
    fi
    if [[ "$CHARTS_LAYOUT" == "charts" ]]; then
        assert_charts_layout_tree
        install_charts_control_files
    fi
    assert_control_files_match_layout

    render_config

    log "generated route-free config: $CF_ASSETS_CONFIG"
}

file_device() {
    stat -c '%d' "$1" 2>/dev/null || stat -f '%d' "$1"
}

# The charts stage holds hard links to the chart PNGs of the main assets
# directory, so it must be on the same filesystem, and it must neither be
# inside that directory (the main Worker and the storage mirrors read all of
# it) nor contain it. Normalizes CF_ASSETS_DIRECTORY to the stage's physical
# path.
assert_charts_stage_location() {
    local stage="$CF_ASSETS_DIRECTORY" source="$CF_CHARTS_SOURCE_DIRECTORY"
    local name parent source_path parent_path stage_path

    [[ -n "$source" && -d "$source" ]] || {
        log "missing charts source directory: ${source:-unset}"
        return 1
    }
    while [[ "$stage" == */ && "$stage" != / ]]; do
        stage="${stage%/}"
    done
    [[ "$stage" == /?* ]] || {
        log "the charts stage directory must be an absolute path: $stage"
        return 1
    }
    name="${stage##*/}"
    parent="${stage%/*}"
    parent="${parent:-/}"
    [[ "$name" != "." && "$name" != ".." ]] || {
        log "invalid charts stage directory: $stage"
        return 1
    }
    [[ -d "$parent" ]] || {
        log "the parent of the charts stage directory does not exist: $parent"
        return 1
    }
    source_path=$(cd "$source" && pwd -P)
    parent_path=$(cd "$parent" && pwd -P)
    stage_path="${parent_path%/}/$name"

    if [[ "$stage_path" == "$source_path" || "$stage_path" == "$source_path"/* || "$source_path" == "$stage_path"/* ]]; then
        log "the charts stage directory $stage_path must be outside the assets directory $source_path and must not contain it"
        return 1
    fi
    if [[ "$(file_device "$source_path")" != "$(file_device "$parent_path")" ]]; then
        log "the charts stage directory $stage_path must be on the same filesystem as $source_path: its charts are hard links"
        return 1
    fi
    CF_ASSETS_DIRECTORY="$stage_path"
}

# Only ever replace a directory that holds nothing but what the stage builder
# writes, so that a mistaken CF_CHARTS_STAGE_DIR cannot delete anything else.
assert_replaceable_stage() {
    local dir="$1" other

    if [[ ! -e "$dir" && ! -L "$dir" ]]; then
        return 0
    fi
    if [[ -L "$dir" || ! -d "$dir" ]]; then
        log "refusing to replace $dir: it is not a charts stage directory"
        return 1
    fi
    other=$(find "$dir" -mindepth 1 -maxdepth 1 ! -name _headers ! -name charts -print) || {
        log "could not list $dir"
        return 1
    }
    [[ -z "$other" ]] || {
        log "refusing to replace $dir: a charts stage never holds ${other%%$'\n'*}"
        return 1
    }
}

# link_listed_files <target>: hard-link each path read from standard input
# (NUL-separated, relative to the main assets directory) to the same path
# below the target directory.
link_listed_files() {
    local target="$1" file

    if cp --version 2>/dev/null | grep 'GNU coreutils' >/dev/null; then
        # GNU cp links a whole batch of files per process.
        (cd "$CF_CHARTS_SOURCE_DIRECTORY" && xargs -0 -r cp -l --parents -t "$target" --)
    else
        # BSD cp has neither --parents nor -t, so link one file at a time.
        while IFS= read -r -d '' file; do
            mkdir -p "$target/${file%/*}" && ln "$CF_CHARTS_SOURCE_DIRECTORY/$file" "$target/$file" || return 1
        done
    fi
}

# Hard-link every regular *.png below the assets directory's charts/ into
# <stage>/charts.
link_charts_into() {
    local stage="$1"

    [[ -d "$CF_CHARTS_SOURCE_DIRECTORY/charts" ]] || return 0
    (cd "$CF_CHARTS_SOURCE_DIRECTORY" && find charts -type f -name '*.png' -print0) |
        link_listed_files "$stage"
}

# write_charts_headers <file>: the main Worker's _headers (its rules match the
# full public paths, /charts/... included) with CHARTS_ORIGIN_HEADER added to
# its one /* rule. Cloudflare keeps one rule per path: a second /* rule would
# replace the first and drop its security headers from every chart.
write_charts_headers() {
    awk -v header="$CHARTS_ORIGIN_HEADER" '
        { print }
        $0 == "/*" { print "  " header; rules++ }
        END { exit rules == 1 ? 0 : 1 }
    ' "$CF_ASSETS_HEADERS_SOURCE" > "$1" || {
        log "the main Worker's _headers ($CF_ASSETS_HEADERS_SOURCE) must have exactly one /* rule"
        return 1
    }
    chmod 0644 "$1"
}

# keep_live_charts <previous stage> <new stage>: the charts Worker is promoted
# before the main Worker, whose promotion can still fail or be withheld. Until
# a later main version is promoted, the live pages are those of the version in
# CF_CHARTS_LIVE_LIST, so the new stage also keeps each chart they link that
# this build no longer has (a relay or contact that dropped out, for example),
# hard-linked from the previous stage, which has held it ever since. Sets
# KEPT_LIVE_CHARTS; a chart the previous stage lacks is reported, not fatal.
KEPT_LIVE_CHARTS=0
keep_live_charts() {
    local previous="$1" next="$2" path lost=0

    KEPT_LIVE_CHARTS=0
    [[ -s "$CF_CHARTS_LIVE_LIST" ]] || return 0
    while IFS= read -r path; do
        [[ "$path" =~ ^charts/(relay|contact)/[^/]+/[^/]+\.png$ ]] || continue
        if [[ -f "$previous/$path" ]]; then
            mkdir -p -- "$next/${path%/*}" && ln -- "$previous/$path" "$next/$path" || return 1
            KEPT_LIVE_CHARTS=$((KEPT_LIVE_CHARTS + 1))
        else
            lost=$((lost + 1))
        fi
    done < <(LC_ALL=C comm -23 <(LC_ALL=C sort -u "$CF_CHARTS_LIVE_LIST") \
        <(cd "$next" && find charts -type f -name '*.png' -print | LC_ALL=C sort -u))
    if (( KEPT_LIVE_CHARTS > 0 )); then
        log "kept $KEPT_LIVE_CHARTS charts that the live main Worker version links but this build no longer has"
    fi
    if (( lost > 0 )); then
        log "warning: $lost charts that the live main Worker version links are in neither this build nor the previous stage"
    fi
}

# build_charts_stage [bootstrap]: rebuild the charts stage from scratch: the
# main Worker's _headers with the charts marker (see write_charts_headers),
# its 404 page as charts/404.html, which a missing chart gets, and, unless
# for the bootstrap deployment, hard links to the charts below charts/, the
# live pages' charts this build dropped (see keep_live_charts) and a new
# build ID. The new tree is built beside the stage and swapped in by two
# renames, so the stage path never holds a partial tree.
build_charts_stage() {
    local stage="$CF_ASSETS_DIRECTORY"
    local next="$CF_ASSETS_DIRECTORY.next" old="$CF_ASSETS_DIRECTORY.old"

    assert_replaceable_stage "$stage"
    assert_replaceable_stage "$next"
    assert_replaceable_stage "$old"

    rm -rf -- "$next"
    mkdir -p -- "$next/charts"
    write_charts_headers "$next/_headers" || { rm -rf -- "$next"; return 1; }
    install -m 0644 "$CF_ASSETS_404_SOURCE" "$next/charts/404.html"
    if [[ "${1:-}" != bootstrap ]]; then
        link_charts_into "$next" || {
            log "could not hard-link the charts of $CF_CHARTS_SOURCE_DIRECTORY into $next"
            rm -rf -- "$next"
            return 1
        }
        keep_live_charts "$stage" "$next" || {
            log "could not keep the live main Worker version's charts in $next"
            rm -rf -- "$next"
            return 1
        }
        printf '%s %s-%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$$" "$RANDOM" > "$next/$CHARTS_BUILD_ID"
    fi

    rm -rf -- "$old"
    if [[ -d "$stage" ]]; then
        mv -- "$stage" "$old"
    fi
    mv -- "$next" "$stage"
    rm -rf -- "$old"
}

# Each file of the main assets directory must be served by exactly one
# Worker: the main Worker's upload after its .assetsignore, plus the charts in
# the stage, must be every file of the directory apart from the root control
# files. A stage without charts has nothing to publish. The stage's own 404
# page and build ID are not charts. Logs the charts per period (the name's
# last part, as 1m in bandwidth-1m.png), which set the stage's growth.
check_charts_stage() {
    local staged periods

    staged=$(cd "$CF_ASSETS_DIRECTORY" && find charts -type f ! -path charts/404.html ! -path "$CHARTS_BUILD_ID" -print0 | tr -dc '\000' | wc -c) || {
        log "could not list the charts stage $CF_ASSETS_DIRECTORY"
        return 1
    }
    staged="${staged//[[:space:]]/}"
    (( staged > 0 )) || {
        log "no chart PNG to publish from $CF_CHARTS_SOURCE_DIRECTORY (CHARTS_LAYOUT=$CHARTS_LAYOUT)"
        return 1
    }
    periods=$(cd "$CF_ASSETS_DIRECTORY" && find charts -type f -name '*.png' |
        awk -F/ '{ name = $NF; sub(/\.png$/, "", name); sub(/.*-/, "", name); count[name]++ }
            END { for (period in count) print period "=" count[period] }' | LC_ALL=C sort | tr '\n' ' ') || periods=""
    log "charts per period: ${periods% }"

    count_tree "$CF_CHARTS_SOURCE_DIRECTORY" true
    local kept=""
    if (( KEPT_LIVE_CHARTS > 0 )); then
        kept=" (the charts Worker also keeps $KEPT_LIVE_CHARTS for the live pages)"
    fi
    if (( staged - KEPT_LIVE_CHARTS != TREE_IGNORED )); then
        log "partition check failed: the main Worker uploads $TREE_FILES and the charts stage holds $((staged - KEPT_LIVE_CHARTS)) of the $((TREE_FILES + TREE_IGNORED)) files in $CF_CHARTS_SOURCE_DIRECTORY$kept"
        if [[ -n "$TREE_ODD" ]]; then
            printf '%s\n' "$TREE_ODD" | sed 's/^/  served by neither Worker: /'
        fi
        return 1
    fi
    log "partition ok: main Worker $TREE_FILES + charts Worker $((staged - KEPT_LIVE_CHARTS)) = $((TREE_FILES + staged - KEPT_LIVE_CHARTS)) files$kept"
}

generate_charts_config() {
    [[ -f "$CF_ASSETS_TEMPLATE" ]] || { log "missing template: $CF_ASSETS_TEMPLATE"; return 1; }
    [[ -f "$CF_ASSETS_HEADERS_SOURCE" ]] || { log "missing headers source: $CF_ASSETS_HEADERS_SOURCE"; return 1; }
    [[ -f "$CF_ASSETS_404_SOURCE" ]] || { log "missing 404 source: $CF_ASSETS_404_SOURCE"; return 1; }

    assert_charts_stage_location
    # Promotion deploys a version that is already uploaded and needs only the
    # rendered config. It leaves the stage as uploaded: the route check after
    # the promotion compares production with it. The bootstrap deployment
    # builds its stage, the _headers and charts/404.html, only once it knows
    # that the Worker has no deployment (see the end of this script).
    if [[ "$MODE" == "--generate-only" || "$MODE" == "--upload-only" ]]; then
        build_charts_stage
        check_charts_stage
    fi
    render_config

    log "generated route-free charts config: $CF_ASSETS_CONFIG"
}

load_cloudflare_token() {
    local token_file
    for token_file in \
        "$HOME/.config/cloudflare/workers_api_token" \
        "$HOME/.config/cloudflare/api_token"; do
        if [[ -f "$token_file" ]]; then
            # shellcheck disable=SC1090
            source "$token_file"
            break
        fi
    done

    [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] || {
        log "CLOUDFLARE_API_TOKEN is not configured"
        return 1
    }
    export CLOUDFLARE_API_TOKEN
    export CLOUDFLARE_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:-}"
}

run_wrangler() {
    (
        cd "$DEPLOY_DIR"
        export WRANGLER_LOG WRANGLER_LOG_PATH WRANGLER_LOG_SANITIZE
        if [[ -n "${WRANGLER_OUTPUT_FILE_PATH:-}" ]]; then
            export WRANGLER_OUTPUT_FILE_PATH
        fi
        if command -v pnpm >/dev/null 2>&1; then
            pnpm exec wrangler "$@"
        elif command -v corepack >/dev/null 2>&1; then
            corepack pnpm exec wrangler "$@"
        elif [[ -x "$DEPLOY_DIR/node_modules/.bin/wrangler" ]]; then
            # The pinned shim runs the lockfile's Node.js; npm releases that
            # enforce devEngines refuse npx in this project.
            "$DEPLOY_DIR/node_modules/.bin/wrangler" "$@"
        else
            log "Wrangler is not installed; run corepack pnpm install --frozen-lockfile"
            exit 127
        fi
    )
}

# Wrangler logs "Uploaded N of M assets" at info level after every upload
# request. Bulk uploads send about 1,000 files per request, but single-file
# uploads (enabled per account by Cloudflare) log once per file. Keep at most one
# progress line per 1,000 files, plus the first and the last.
thin_upload_progress() {
    awk '
        /^Uploaded [0-9]+ of [0-9]+ assets?$/ {
            thousand = int($2 / 1000)
            if (shown && thousand == last && $2 != $4) next
            shown = 1
            last = thousand
        }
        { print; fflush() }
    '
}

# Wrangler logs its asset upload at info level: "Found N new or modified
# static assets to upload" or "No updated asset files to upload", then the
# progress lines; "Success! Uploaded N files (M already uploaded)" only at log
# level. Pass every line through and note the second each of these was read,
# for the upload summary.
timestamp_upload_lines() {
    local line now
    while IFS= read -r line || [[ -n "$line" ]]; do
        printf '%s\n' "$line"
        case "$line" in
            *' new or modified static asset'*|*'No updated asset files to upload'*|'Uploaded '*' of '*' asset'*|*'Success! Uploaded '*)
                printf -v now '%(%s)T' -1
                printf '%s\t%s\n' "$now" "$line" >> "$UPLOAD_TIMES"
                ;;
        esac
    done
}

# Append one row per Wrangler upload to CF_ASSETS_UPLOADS_FILE, to observe how
# many files each upload had to send: the files the version holds, the files
# Wrangler asked for, the files it reported uploaded, the seconds from its
# "Found" line to its last upload line, and the seconds of the whole command.
# "-" marks a value the Wrangler log level hid: WRANGLER_LOG=info shows them.
record_upload() {
    local status="$1" seconds="$2" version stats asked uploaded transfer
    version=$(jq -r 'select(.type == "version-upload" or .type == "deploy") | .version_id // empty' \
        "$UPLOAD_METADATA" 2>/dev/null | tail -n 1) || version=""
    stats=$(awk -F '\t' '
        $2 ~ /new or modified static asset/ {
            if (match($2, /Found [0-9]+/)) asked = substr($2, RSTART + 6, RLENGTH - 6)
            start = $1
        }
        $2 ~ /No updated asset files to upload/ { asked = 0; uploaded = 0; start = $1; end = $1 }
        $2 ~ /^Uploaded [0-9]+ of [0-9]+ asset/ { split($2, word, " "); uploaded = word[2]; end = $1 }
        $2 ~ /Success! Uploaded [0-9]+ file/ {
            if (match($2, /Uploaded [0-9]+/)) uploaded = substr($2, RSTART + 9, RLENGTH - 9)
            end = $1
        }
        END {
            transfer = (start != "" && end != "") ? end - start : "-"
            printf "%s\t%s\t%s\n", (asked == "" ? "-" : asked), (uploaded == "" ? "-" : uploaded), transfer
        }
    ' "$UPLOAD_TIMES") || return 1

    mkdir -p "$(dirname "$CF_ASSETS_UPLOADS_FILE")" || return 1
    if [[ ! -f "$CF_ASSETS_UPLOADS_FILE" ]]; then
        printf 'timestamp_utc\tworker\tversion_id\texit_status\tfiles\tasked\tuploaded\ttransfer_seconds\ttotal_seconds\n' \
            > "$CF_ASSETS_UPLOADS_FILE" || return 1
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$CF_ASSETS_WORKER_NAME" "${version:--}" "$status" \
        "$UPLOAD_FILE_COUNT" "$stats" "$seconds" >> "$CF_ASSETS_UPLOADS_FILE" || return 1
    IFS=$'\t' read -r asked uploaded transfer <<< "$stats"
    log "upload summary: files=$UPLOAD_FILE_COUNT asked=$asked uploaded=$uploaded transfer=${transfer}s total=${seconds}s exit=$status"
}

# run_upload <wrangler arguments...>: one Wrangler upload with its output shown
# (progress thinned) and kept in UPLOAD_OUTPUT, and its summary recorded. Sets
# UPLOAD_STATUS to Wrangler's exit status.
run_upload() {
    local started finished
    : > "$UPLOAD_OUTPUT"
    : > "$UPLOAD_METADATA"
    : > "$UPLOAD_TIMES"
    started=$(date +%s)
    if WRANGLER_OUTPUT_FILE_PATH="$UPLOAD_METADATA" run_wrangler "$@" 2>&1 |
        thin_upload_progress | timestamp_upload_lines | tee "$UPLOAD_OUTPUT"; then
        UPLOAD_STATUS=0
    else
        UPLOAD_STATUS=${PIPESTATUS[0]}
    fi
    finished=$(date +%s)
    record_upload "$UPLOAD_STATUS" "$((finished - started))" || log "could not record the upload summary in $CF_ASSETS_UPLOADS_FILE"
}

validate_upload_retry_settings() {
    [[ "$CF_ASSETS_UPLOAD_MAX_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || {
        log "invalid CF_ASSETS_UPLOAD_MAX_ATTEMPTS=$CF_ASSETS_UPLOAD_MAX_ATTEMPTS"
        return 2
    }
    [[ "$CF_ASSETS_UPLOAD_RETRY_DELAY" =~ ^[0-9]+$ ]] || {
        log "invalid CF_ASSETS_UPLOAD_RETRY_DELAY=$CF_ASSETS_UPLOAD_RETRY_DELAY"
        return 2
    }
    case "$WRANGLER_LOG" in
        none|error|warn|info|log|debug|NONE|ERROR|WARN|INFO|LOG|DEBUG) ;;
        *) log "invalid WRANGLER_LOG=$WRANGLER_LOG"; return 2 ;;
    esac
    assert_boolean_setting WRANGLER_LOG_SANITIZE "$WRANGLER_LOG_SANITIZE"
}

parse_upload_metadata() {
    local metadata_file="$1"
    local parsed expected_prefix

    [[ -s "$metadata_file" ]] || return 1
    if ! parsed=$(jq -r \
        'select(.type == "version-upload" and .version == 1) | [.version_id // "", .preview_url // ""] | @tsv' \
        "$metadata_file" | tail -n 1); then
        return 1
    fi
    IFS=$'\t' read -r version_id preview_url <<< "$parsed"
    [[ "$version_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1

    expected_prefix="https://${version_id:0:8}-${CF_ASSETS_WORKER_NAME}."
    [[ "$preview_url" == "${expected_prefix}"*".workers.dev" ]] || return 1
    [[ "$preview_url" =~ ^https://[a-z0-9-]+(\.[a-z0-9-]+)*\.workers\.dev$ ]] || return 1
}

# Progress counts and changed-asset paths ("+ /path") at info level are not
# errors, but numbers such as "Uploaded 512 of ..." look like 5xx statuses.
is_transient_upload_failure() {
    local output_file="$1" diagnostics
    diagnostics=$(grep -Ev '^(Uploaded [0-9]+ of [0-9]+ assets?|\+ /.*)$' "$output_file" || true)
    grep -Eiq \
        '(^|[^0-9])5[0-9]{2}([^0-9]|$)|timed? out|timeout|network|fetch failed|socket|ECONN|EAI_AGAIN|ENOTFOUND|unexpected end|malformed|invalid (json|response)|internal error' \
        <<< "$diagnostics"
}

promote_verified_version() {
    local version_to_promote=""
    local promotion_status=0

    if [[ ! -f "$CF_ASSETS_LAST_VERSION_FILE" ]]; then
        log "verified version file is missing: $CF_ASSETS_LAST_VERSION_FILE"
        return 1
    fi

    version_to_promote=$(<"$CF_ASSETS_LAST_VERSION_FILE")
    if [[ ! "$version_to_promote" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        log "verified version file does not contain one valid Worker version ID"
        return 1
    fi

    log "deploying verified version $version_to_promote@100%"
    run_wrangler versions deploy "$version_to_promote@100%" --yes --config "$CF_ASSETS_CONFIG" \
        || promotion_status=$?

    mkdir -p "$(dirname "$CF_ASSETS_PROMOTION_SUMMARY_FILE")"
    if [[ ! -f "$CF_ASSETS_PROMOTION_SUMMARY_FILE" ]]; then
        printf 'timestamp_utc\tversion_id\texit_status\n' > "$CF_ASSETS_PROMOTION_SUMMARY_FILE"
    fi
    printf '%s\t%s\t%s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$version_to_promote" "$promotion_status" \
        >> "$CF_ASSETS_PROMOTION_SUMMARY_FILE"

    return "$promotion_status"
}

# The first upload of a new Worker must be a deployment: a version upload
# needs an existing Worker. Refuse a charts Worker that already has a
# deployment: builds publish it by version upload, preview verification and
# promotion. Wrangler prints the JSON listing only at log level.
assert_no_deployment() {
    local listing count status=0

    listing=$(WRANGLER_LOG=log run_wrangler deployments list --json --config "$CF_ASSETS_CONFIG" 2>"$UPLOAD_OUTPUT") ||
        status=$?
    if (( status == 0 )); then
        count=$(jq -er 'if type == "array" then length else error("not a list") end' <<< "$listing" 2>/dev/null) || {
            log "refusing bootstrap: could not read the deployments of $CF_ASSETS_WORKER_NAME"
            return 1
        }
        if (( count > 0 )); then
            log "refusing bootstrap: $CF_ASSETS_WORKER_NAME already has a deployment; builds with CHARTS_LAYOUT=charts publish it by version upload and promotion"
            return 1
        fi
        return 0
    fi
    # Cloudflare's "This Worker does not exist on your account": nothing to
    # protect.
    if grep -Fq '[code: 10007]' "$UPLOAD_OUTPUT"; then
        return 0
    fi
    cat "$UPLOAD_OUTPUT" >&2
    log "refusing bootstrap: could not list the deployments of $CF_ASSETS_WORKER_NAME (exit $status)"
    return 1
}

# Wrangler's "Found" and "Uploaded" lines, which the upload summary counts,
# show at info level. The scheduled job refuses a checkout with unignored
# files, so the deployment must leave none.
bootstrap_deploy() {
    local version dirty

    log "deploying the charts Worker $CF_ASSETS_WORKER_NAME for the first time from $CF_ASSETS_DIRECTORY"
    WRANGLER_LOG=info run_upload deploy --config "$CF_ASSETS_CONFIG"
    if (( UPLOAD_STATUS != 0 )); then
        log "bootstrap deployment failed (exit $UPLOAD_STATUS)"
        return "$UPLOAD_STATUS"
    fi
    version=$(jq -r 'select(.type == "deploy") | .version_id // empty' "$UPLOAD_METADATA" 2>/dev/null | tail -n 1) ||
        version=""
    log "bootstrap deployment complete: $CF_ASSETS_WORKER_NAME serves version ${version:-unknown} at 100%, with no route"
    [[ "${CF_ASSETS_REQUIRE_FRESH_CHECKOUT:-true}" == "true" ]] || return 0
    dirty=$(git -C "$DEPLOY_DIR" status --porcelain --untracked-files=normal) || dirty="(git status failed)"
    if [[ -n "$dirty" ]]; then
        printf '%s\n' "$dirty" >&2
        log "the checkout is not clean after the deployment: the scheduled job refuses it until these files are removed"
        return 1
    fi
}

# A failed upload, or a version over the file limit, breaks the streak of
# verified versions.
record_failure() {
    local status="$1"
    if [[ "$status" -ne 0 && ( "$MODE" == "--upload-only" || ( "$MODE" == "--generate-only" && "$status" == 4 ) ) ]]; then
        mkdir -p "$(dirname "$CF_ASSETS_CONSECUTIVE_FILE")"
        printf '0\n' > "$CF_ASSETS_CONSECUTIVE_FILE"
    fi
}

trap 'record_failure $?' EXIT

assert_boolean_setting CF_ASSETS_ENABLED "$CF_ASSETS_ENABLED"
assert_boolean_setting CF_ASSETS_ALLOW_PROMOTION "$CF_ASSETS_ALLOW_PROMOTION"
assert_boolean_setting ALLIUM_NO_CHARTS "$ALLIUM_NO_CHARTS"
assert_charts_layout
assert_file_limits
assert_safe_worker_name
validate_upload_retry_settings
generate_config

if [[ "$MODE" == "--generate-only" ]]; then
    check_upload_file_count
    log "generate-only complete; no Cloudflare API call was made"
    exit 0
fi

if [[ "$MODE" == "--promote" ]]; then
    [[ "$CF_ASSETS_ALLOW_PROMOTION" == "true" ]] || {
        log "promotion is disabled; Stage 3 requires explicit review"
        exit 3
    }
    assert_fresh_checkout
    load_cloudflare_token
    if [[ "$WRANGLER_LOG_PATH" == "$WRANGLER_DEFAULT_LOG_PATH" ]]; then
        prepare_null_log_sink "$WRANGLER_LOG_PATH"
    fi
    promote_verified_version
    exit 0
fi

if [[ "$MODE" != "--bootstrap-deploy" && "$CF_ASSETS_ENABLED" != "true" ]]; then
    log "shadow upload is disabled (CF_ASSETS_ENABLED=$CF_ASSETS_ENABLED)"
    exit 0
fi

command -v jq >/dev/null 2>&1 || {
    log "jq is required for structured Wrangler upload metadata"
    exit 2
}
assert_fresh_checkout
if [[ "$MODE" != "--bootstrap-deploy" ]]; then
    check_upload_file_count
fi
load_cloudflare_token
mkdir -p "$DEPLOY_DIR/logs"
if [[ "$WRANGLER_LOG_PATH" == "$WRANGLER_DEFAULT_LOG_PATH" ]]; then
    prepare_null_log_sink "$WRANGLER_LOG_PATH"
fi

UPLOAD_OUTPUT=$(mktemp)
UPLOAD_METADATA=$(mktemp)
UPLOAD_TIMES=$(mktemp)
trap 'status=$?; rm -f "$UPLOAD_OUTPUT" "$UPLOAD_METADATA" "$UPLOAD_TIMES"; record_failure "$status"' EXIT

# A refused bootstrap leaves the stage as it was.
if [[ "$MODE" == "--bootstrap-deploy" ]]; then
    assert_no_deployment
    build_charts_stage bootstrap
    check_upload_file_count
    bootstrap_deploy
    exit 0
fi

started=$(date +%s)
version_id=""
preview_url=""
upload_status=1
for ((upload_attempt=1; upload_attempt<=CF_ASSETS_UPLOAD_MAX_ATTEMPTS; upload_attempt++)); do
    log "uploading immutable shadow version for $CF_ASSETS_WORKER_NAME (attempt $upload_attempt/$CF_ASSETS_UPLOAD_MAX_ATTEMPTS)"

    run_upload versions upload --preview-alias "$CF_ASSETS_PREVIEW_ALIAS" --config "$CF_ASSETS_CONFIG"
    upload_status="$UPLOAD_STATUS"

    if (( upload_status == 0 )); then
        if parse_upload_metadata "$UPLOAD_METADATA"; then
            break
        fi
        upload_status=1
        log "version upload returned malformed or incomplete structured metadata"
    elif ! is_transient_upload_failure "$UPLOAD_OUTPUT"; then
        log "version upload failed with a non-transient error; refusing retry"
        exit "$upload_status"
    else
        log "version upload hit a transient Cloudflare/network failure"
    fi

    if (( upload_attempt >= CF_ASSETS_UPLOAD_MAX_ATTEMPTS )); then
        log "version upload failed after $CF_ASSETS_UPLOAD_MAX_ATTEMPTS bounded attempts"
        exit "$upload_status"
    fi
    log "waiting ${CF_ASSETS_UPLOAD_RETRY_DELAY}s before upload retry"
    sleep "$CF_ASSETS_UPLOAD_RETRY_DELAY"
done

if [[ "$CF_ASSETS_PROFILE" == "charts" ]]; then
    # The charts Worker's preview against its stage, sampling also the charts
    # this build's pages link to.
    "$CF_ASSETS_VERIFY_SCRIPT" "$preview_url" "$CF_ASSETS_DIRECTORY" "$CF_CHARTS_SOURCE_DIRECTORY"
else
    CHARTS_LAYOUT="$CHARTS_LAYOUT" ALLIUM_NO_CHARTS="$ALLIUM_NO_CHARTS" \
        "$CF_ASSETS_VERIFY_SCRIPT" "$preview_url" "$CF_ASSETS_DIRECTORY"
fi

finished=$(date +%s)
duration=$((finished - started))
# The files this version holds, as counted before the upload: with
# CHARTS_LAYOUT=charts the main Worker's count leaves out charts/.
file_count="$UPLOAD_FILE_COUNT"
byte_count=$(du -sb "$CF_ASSETS_DIRECTORY" | awk '{print $1}')
consecutive=$(cat "$CF_ASSETS_CONSECUTIVE_FILE" 2>/dev/null || printf '0')
[[ "$consecutive" =~ ^[0-9]+$ ]] || consecutive=0
consecutive=$((consecutive + 1))

printf '%s\n' "$consecutive" > "$CF_ASSETS_CONSECUTIVE_FILE"
printf '%s\n' "$version_id" > "$CF_ASSETS_LAST_VERSION_FILE"

if [[ ! -f "$CF_ASSETS_SUMMARY_FILE" ]]; then
    printf 'timestamp_utc\tversion_id\tduration_seconds\tfile_count\tbyte_count\tpreview_url\tconsecutive_successes\n' > "$CF_ASSETS_SUMMARY_FILE"
fi
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$version_id" "$duration" \
    "$file_count" "$byte_count" "$preview_url" "$consecutive" \
    >> "$CF_ASSETS_SUMMARY_FILE"

log "shadow version verified: version=$version_id duration=${duration}s consecutive=$consecutive preview=$preview_url"
