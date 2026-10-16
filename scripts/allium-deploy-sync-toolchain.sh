#!/usr/bin/env bash
# Keep node_modules in step with the pinned Workers toolchain.
#
# A guarded auto-pull can bring a new package.json/pnpm-lock.yaml, but nothing
# else reinstalls node_modules, so every later job would keep running the
# previously installed Wrangler. This installs the lockfile only when it differs
# from the last verified install. The previous node_modules is moved aside first
# and restored on any install, timeout, version, or checkout-cleanliness failure,
# so a registry or network problem never removes the last working Wrangler. A
# failed install's changes to the tracked toolchain manifests are reverted; any
# other change is reported and left for an operator, never deleted. The same
# lockfile is not retried until CF_ASSETS_TOOLCHAIN_RETRY_SECONDS have passed.
# pnpm runs through corepack, so the packageManager pin and its allowBuilds list
# apply. pnpm, the build scripts it allows, and the new Wrangler start from an
# empty environment, so they inherit none of the deploy job's variables. They
# still run as this user and can read its files, so the exact pins, lockfile
# integrity and allowBuilds remain the controls against a compromised package.
# GNU timeout is required so a timed-out install stops with all its children.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

INSTALL_TIMEOUT="${CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT:-180}"
RETRY_SECONDS="${CF_ASSETS_TOOLCHAIN_RETRY_SECONDS:-3600}"
MODULES_DIR="$DEPLOY_DIR/node_modules"
STATE_DIR="$DEPLOY_DIR/.toolchain"
PREVIOUS_DIR="$STATE_DIR/previous-node_modules"
DISCARD_DIR="$STATE_DIR/discard-node_modules"
FAILURE_FILE="$STATE_DIR/last-failure"
STAMP_NAME=".allium-toolchain.sha256"
# Files that decide what pnpm installs; .npmrc only counts when present.
TOOLCHAIN_FILES=(package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc)

log() {
    printf '[Toolchain] %s\n' "$1"
}

# Third-party code (pnpm, the build scripts it allows, and the installed
# Wrangler) starts from an empty environment plus a few variables (see
# set_clean_env). This strips inherited variables only; it does not limit
# which files the code can read.
set_clean_env

# Wrangler prints --version at its "log" level, which the deploy's exported
# WRANGLER_LOG (error or info) would suppress. A runtime that hangs at startup
# must not hold the deploy lock, so the check gets at most 30 seconds.
wrangler_version() {
    run_with_timeout "$VERSION_TIMEOUT" "${CLEAN_ENV[@]}" WRANGLER_LOG=log "$MODULES_DIR/.bin/wrangler" --version 2>&1 \
        | tail -n 1
}

toolchain_digest() {
    local file
    for file in "${TOOLCHAIN_FILES[@]}"; do
        if [[ -f "$DEPLOY_DIR/$file" ]]; then
            printf '%s\n' "$file"
            cat "$DEPLOY_DIR/$file"
        fi
    done | sha256sum | awk '{print $1}'
}

stamp_matches() {
    local stamp_file="$MODULES_DIR/$STAMP_NAME"
    [[ -f "$stamp_file" && "$(<"$stamp_file")" == "$1" ]]
}

checkout_status() {
    git -C "$DEPLOY_DIR" status --porcelain --untracked-files=normal
}

discard_previous() {
    [[ -e "$PREVIOUS_DIR" ]] || return 0
    rm -rf "$DISCARD_DIR"
    mv "$PREVIOUS_DIR" "$DISCARD_DIR"
    rm -rf "$DISCARD_DIR"
}

restore_previous() {
    rm -rf "$MODULES_DIR"
    if [[ -e "$PREVIOUS_DIR" ]]; then
        mv "$PREVIOUS_DIR" "$MODULES_DIR"
        log "restored the previous toolchain"
    fi
}

# The checkout was clean before the install. Left dirty, it would stop the
# Workers snapshot and every guarded auto-pull, including one that brings a fix.
# Only the manifests pnpm can rewrite that exist in HEAD are reverted, staged or
# not, by restoring both the index and the worktree from HEAD. Any other change,
# including a newly added manifest, is left in place and reported: it may belong
# to another process writing the deploy directory, so it is never discarded
# here. Ignored files (config.env, logs/, node_modules/, .toolchain/) are not
# touched.
TOOLCHAIN_MANIFESTS=(package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc)
revert_checkout_changes() {
    local dirty manifest
    local -a changed=()
    dirty=$(checkout_status) || { log "could not read the checkout status"; return 0; }
    [[ -n "$dirty" ]] || return 0
    printf '%s\n' "$dirty" | sed 's/^/[Toolchain] [changed] /'
    for manifest in "${TOOLCHAIN_MANIFESTS[@]}"; do
        git -C "$DEPLOY_DIR" cat-file -e "HEAD:$manifest" 2>/dev/null || continue
        # The worktree and the index can each differ from HEAD on their own.
        if ! git -C "$DEPLOY_DIR" diff --quiet HEAD -- "$manifest" \
            || ! git -C "$DEPLOY_DIR" diff --cached --quiet HEAD -- "$manifest"; then
            changed+=("$manifest")
        fi
    done
    if (( ${#changed[@]} )) && ! git -C "$DEPLOY_DIR" checkout -q HEAD -- "${changed[@]}"; then
        log "could not revert the failed install's changes to ${changed[*]}"
        return 0
    fi
    dirty=$(checkout_status) || { log "could not read the checkout status"; return 0; }
    if [[ -z "$dirty" ]]; then
        log "reverted the failed install's changes to the checkout"
    else
        printf '%s\n' "$dirty" | sed 's/^/[Toolchain] [left in place] /'
        log "left changes outside the toolchain manifests in place; clean the checkout by hand"
    fi
}

[[ "$INSTALL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || {
    log "invalid CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT=$INSTALL_TIMEOUT"
    exit 2
}
[[ "$RETRY_SECONDS" =~ ^[0-9]+$ ]] || {
    log "invalid CF_ASSETS_TOOLCHAIN_RETRY_SECONDS=$RETRY_SECONDS"
    exit 2
}
VERSION_TIMEOUT=$(( INSTALL_TIMEOUT < 30 ? INSTALL_TIMEOUT : 30 ))
for required in "$DEPLOY_DIR/package.json" "$DEPLOY_DIR/pnpm-lock.yaml"; do
    [[ -f "$required" ]] || { log "missing $required"; exit 1; }
done

rm -rf "$DISCARD_DIR"
expected_digest=$(toolchain_digest)

# A previous sync was interrupted after moving node_modules aside. Keep the new
# tree only if it was verified for the current lockfile; otherwise restore.
if [[ -e "$PREVIOUS_DIR" ]]; then
    if stamp_matches "$expected_digest"; then
        discard_previous
    else
        log "previous sync was interrupted"
        restore_previous
    fi
fi

if stamp_matches "$expected_digest"; then
    rm -f "$FAILURE_FILE"
    log "pinned toolchain is current"
    exit 0
fi

# During a registry or nodejs.org outage every attempt can cost the whole
# install timeout, so a lockfile that failed to install is not retried on every
# job. A different lockfile (for example a revert) is tried at once.
if [[ -f "$FAILURE_FILE" ]]; then
    failed_digest="" failed_at=""
    read -r failed_digest failed_at < "$FAILURE_FILE" || true
    if [[ "$failed_digest" == "$expected_digest" && "$failed_at" =~ ^[0-9]+$ ]]; then
        since_failure=$(($(date +%s) - failed_at))
        if (( since_failure >= 0 && since_failure < RETRY_SECONDS )); then
            log "skipping install: this lockfile failed to install ${since_failure}s ago; next attempt after ${RETRY_SECONDS}s"
            exit 1
        fi
    fi
fi

command -v jq >/dev/null 2>&1 || { log "jq is required to read the Wrangler pin"; exit 1; }
expected_wrangler=$(jq -r '.devDependencies.wrangler // empty' "$DEPLOY_DIR/package.json")
[[ "$expected_wrangler" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    log "package.json must pin an exact Wrangler version (found '${expected_wrangler:-none}')"
    exit 1
}

# GNU timeout signals the whole process group, so pnpm, corepack and build-script
# children cannot keep writing to the checkout after a timed-out install is rolled
# back. The library fallback without it signals only the direct child.
if [[ "$(timeout --version 2>/dev/null)" != *"GNU coreutils"* ]]; then
    log "GNU timeout is required to bound the install and stop all of its processes"
    exit 1
fi

# corepack runs the packageManager pin. A pnpm already on PATH is used only when
# it is exactly that version, because another pnpm may ignore allowBuilds. A
# version probe that fails or hangs counts as a mismatch.
expected_pnpm=$(jq -r '.packageManager // empty' "$DEPLOY_DIR/package.json")
if command -v corepack >/dev/null 2>&1; then
    pnpm_cmd=(corepack pnpm)
elif command -v pnpm >/dev/null 2>&1 \
    && [[ -n "$expected_pnpm" \
        && "pnpm@$(run_with_timeout "$VERSION_TIMEOUT" "${CLEAN_ENV[@]}" pnpm --version 2>/dev/null)" == "$expected_pnpm" ]]; then
    pnpm_cmd=(pnpm)
else
    log "corepack, or pnpm matching packageManager (${expected_pnpm:-not set}), is required to install the pinned toolchain"
    exit 1
fi

status_before=$(checkout_status)
if [[ -n "$status_before" ]]; then
    log "skipping install: checkout has tracked or unignored changes"
    exit 1
fi

previous_wrangler="none"
if [[ -x "$MODULES_DIR/.bin/wrangler" ]]; then
    previous_wrangler=$(wrangler_version || true)
fi
log "installing pinned toolchain: wrangler ${previous_wrangler:-unknown} -> $expected_wrangler"

install_output=$(mktemp)
install_started=false
install_complete=false
finish() {
    if [[ "$install_started" == "true" && "$install_complete" != "true" ]]; then
        restore_previous
        revert_checkout_changes
    fi
    rm -f "$install_output"
}
trap finish EXIT

mkdir -p "$STATE_DIR"
if [[ -e "$MODULES_DIR" ]]; then
    mv "$MODULES_DIR" "$PREVIOUS_DIR"
fi
install_started=true

started=$(date +%s)
install_status=0
(
    cd "$DEPLOY_DIR"
    run_with_timeout "$INSTALL_TIMEOUT" "${CLEAN_ENV[@]}" "${pnpm_cmd[@]}" install --frozen-lockfile \
        --reporter=append-only --config.confirmModulesPurge=false
) > "$install_output" 2>&1 || install_status=$?
duration=$(($(date +%s) - started))

failure=""
installed_wrangler=""
if (( install_status != 0 )); then
    failure="pnpm install exited $install_status after ${duration}s"
elif ! installed_wrangler=$(wrangler_version); then
    failure="installed wrangler does not run: $installed_wrangler"
elif [[ "$installed_wrangler" != "$expected_wrangler" ]]; then
    failure="installed wrangler $installed_wrangler does not match pin $expected_wrangler"
elif [[ "$(checkout_status)" != "$status_before" ]]; then
    failure="install changed the checkout"
fi

if [[ -n "$failure" ]]; then
    log "install failed: $failure"
    tail -n 20 "$install_output" | sed 's/^/[Toolchain] | /'
    printf '%s %s\n' "$expected_digest" "$(date +%s)" > "$FAILURE_FILE"
    exit 1
fi

printf '%s\n' "$expected_digest" > "$MODULES_DIR/$STAMP_NAME"
install_complete=true
rm -f "$FAILURE_FILE"
discard_previous
log "installed wrangler $installed_wrangler in ${duration}s"
