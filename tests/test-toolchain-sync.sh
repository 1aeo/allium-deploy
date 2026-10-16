#!/usr/bin/env bash
# Behaviour of scripts/allium-deploy-sync-toolchain.sh and its update.sh hook.
# Every case runs script copies in a temporary DEPLOY_DIR with stub corepack and
# pnpm. The sync starts pnpm from an empty environment, so the stubs keep their
# state in files next to their bin directory instead of environment variables.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export GIT_AUTHOR_NAME="1aeo"
export GIT_AUTHOR_EMAIL="1aeo@users.noreply.github.com"
export GIT_COMMITTER_NAME="1aeo"
export GIT_COMMITTER_EMAIL="1aeo@users.noreply.github.com"

fail() {
    echo "not ok - $1"
    exit 1
}

pass() {
    echo "ok - $1"
}

MOCK_BIN="$TMP_DIR/bin"
PNPM_ONLY_BIN="$TMP_DIR/bin-pnpm-only"
TOOLS_BIN="$TMP_DIR/tools"
TOOLS_NO_TIMEOUT_BIN="$TMP_DIR/tools-no-timeout"
MOCK_PNPM_CALLS="$TMP_DIR/pnpm-calls"
mkdir -p "$MOCK_BIN" "$PNPM_ONLY_BIN"

# link_tools <dir> <name>...: every command on the caller's PATH except the named
# ones, so each case decides exactly which package managers the sync can find.
link_tools() {
    local dir="$1" path_dir tool name
    local -a path_dirs
    shift
    mkdir -p "$dir"
    IFS=: read -r -a path_dirs <<< "$PATH"
    for path_dir in "${path_dirs[@]}"; do
        [[ -d "$path_dir" ]] || continue
        for tool in "$path_dir"/*; do
            name="${tool##*/}"
            if [[ " $* " == *" $name "* ]]; then
                continue
            fi
            if [[ -f "$tool" && -x "$tool" && ! -e "$dir/$name" ]]; then
                ln -s "$tool" "$dir/$name"
            fi
        done
    done
}
link_tools "$TOOLS_BIN" corepack pnpm pnpx
link_tools "$TOOLS_NO_TIMEOUT_BIN" corepack pnpm pnpx timeout gtimeout

# The sync requires GNU timeout; without it only the refusal and hook cases run.
GNU_TIMEOUT=0
if [[ "$(timeout --version 2>/dev/null)" == *"GNU coreutils"* ]]; then
    GNU_TIMEOUT=1
fi

# Records the name of any stub that can see a deploy setting.
cat > "$MOCK_BIN/pnpm" <<'STUB'
#!/usr/bin/env bash
state="$(dirname "$(dirname "$0")")"
[[ -z "${TOOLCHAIN_TEST_SECRET:-}" ]] || echo pnpm >> "$state/leaks"
printf '%s\n' "$*" >> "$state/pnpm-calls"
if [[ "$1" == "--version" ]]; then
    if [[ "$(cat "$state/pnpm-version" 2>/dev/null)" == "hang" ]]; then
        exec sleep 30
    fi
    cat "$state/pnpm-version" 2>/dev/null || echo 10.34.5
    exit 0
fi
[[ "$1" == "install" ]] || exit 64
mode=$(cat "$state/pnpm-mode" 2>/dev/null || echo ok)
case "$mode" in
    fail)
        mkdir -p node_modules
        printf 'partial\n' > node_modules/partial-install
        # A failing install can still leave tracked and untracked changes.
        printf 'touched\n' >> pnpm-workspace.yaml
        printf 'stray\n' > stray-install-file
        echo "ERR_PNPM_META_FETCH_FAIL registry unreachable" >&2
        exit 1
        ;;
    staged)
        # A failing install hook that stages a manifest edit, a new manifest,
        # and a lockfile edit that exists only in the index.
        mkdir -p node_modules
        printf 'touched\n' >> pnpm-workspace.yaml
        printf 'registry=https://registry.example.invalid/\n' > .npmrc
        cp pnpm-lock.yaml pnpm-lock.yaml.orig
        printf 'touched\n' >> pnpm-lock.yaml
        git add pnpm-workspace.yaml .npmrc pnpm-lock.yaml
        mv pnpm-lock.yaml.orig pnpm-lock.yaml
        echo "ERR_PNPM_LIFECYCLE install hook failed" >&2
        exit 1
        ;;
    hang)
        mkdir -p node_modules
        exec sleep 30
        ;;
    hang-child)
        # A build-script child that would write after the install timed out.
        mkdir -p node_modules
        ( sleep 3; printf 'late\n' > "$state/late-write" ) &
        exec sleep 30
        ;;
    dirty)
        printf 'touched\n' >> pnpm-workspace.yaml
        mkdir -p stray-dir
        printf 'stray\n' > stray-dir/file
        ;;
esac
version=$(jq -r '.devDependencies.wrangler' package.json)
if [[ "$mode" == "wrong-version" ]]; then
    version=0.0.1
fi
mkdir -p node_modules/.bin
if [[ "$mode" == "hang-version" ]]; then
    printf '#!/usr/bin/env bash\nexec sleep 30\n' > node_modules/.bin/wrangler
else
    printf '#!/usr/bin/env bash\n[[ -z "${TOOLCHAIN_TEST_SECRET:-}" ]] || echo wrangler >> %q\ncase "${WRANGLER_LOG:-log}" in log|debug) echo %s ;; esac\n' \
        "$state/leaks" "$version" > node_modules/.bin/wrangler
fi
chmod +x node_modules/.bin/wrangler
echo "+ wrangler $version"
STUB
cat > "$MOCK_BIN/corepack" <<'STUB'
#!/usr/bin/env bash
state="$(dirname "$(dirname "$0")")"
[[ "$1" == "pnpm" ]] || exit 64
shift
printf 'pnpm %s\n' "$*" >> "$state/corepack-calls"
exec "$(dirname "$0")/pnpm" "$@"
STUB
chmod +x "$MOCK_BIN/pnpm" "$MOCK_BIN/corepack"
ln -s "$MOCK_BIN/pnpm" "$PNPM_ONLY_BIN/pnpm"
export PATH="$MOCK_BIN:$PATH"
# The update job exports a quiet WRANGLER_LOG; the sync must still read versions.
export WRANGLER_LOG=info

new_deploy_dir() {
    local dir="$TMP_DIR/$1"
    mkdir -p "$dir/scripts"
    cp "$ROOT_DIR/scripts/allium-deploy-sync-toolchain.sh" "$ROOT_DIR/scripts/allium-deploy-lib.sh" "$dir/scripts/"
    cp "$ROOT_DIR/.gitignore" "$dir/.gitignore"
    printf '{"devDependencies":{"wrangler":"4.86.0"}}\n' > "$dir/package.json"
    printf 'lockfileVersion: 9.0\n# wrangler 4.86.0\n' > "$dir/pnpm-lock.yaml"
    printf 'allowBuilds: {}\n' > "$dir/pnpm-workspace.yaml"
    git init -q -b main "$dir"
    git -C "$dir" add -A
    git -C "$dir" commit -qm "base"
    # Ignored production files that a checkout revert must keep.
    printf 'SECRET=kept\n' > "$dir/config.env"
    mkdir -p "$dir/logs"
    printf 'kept\n' > "$dir/logs/update.log"
    printf '%s\n' "$dir"
}

assert_checkout_clean() {
    local dir="$1" label="$2"
    [[ -z "$(git -C "$dir" status --porcelain --untracked-files=normal)" ]] \
        || fail "$label: checkout is not clean: $(git -C "$dir" status --porcelain --untracked-files=normal | tr '\n' ' ')"
    [[ "$(<"$dir/config.env")" == "SECRET=kept" && -f "$dir/logs/update.log" ]] \
        || fail "$label: ignored config or logs were touched"
}

bump_pin() {
    local dir="$1" version="$2"
    printf '{"devDependencies":{"wrangler":"%s"}}\n' "$version" > "$dir/package.json"
    printf 'lockfileVersion: 9.0\n# wrangler %s\n' "$version" > "$dir/pnpm-lock.yaml"
    git -C "$dir" commit -qam "wrangler $version"
}

seed_installed_toolchain() {
    # Simulate the existing production install: a working wrangler plus a
    # marker that only survives if this exact tree is kept or restored.
    local dir="$1" version="$2"
    mkdir -p "$dir/node_modules/.bin"
    # shellcheck disable=SC2016 # the stub expands WRANGLER_LOG when it runs
    printf '#!/usr/bin/env bash\ncase "${WRANGLER_LOG:-log}" in log|debug) echo %s ;; esac\n' "$version" \
        > "$dir/node_modules/.bin/wrangler"
    chmod +x "$dir/node_modules/.bin/wrangler"
    printf 'previous\n' > "$dir/node_modules/previous-marker"
}

# run_sync <dir> [NAME=value ...]: MOCK_PNPM_MODE and MOCK_PNPM_VERSION go to the
# stubs' state files; other settings, including PATH, go to the sync script.
run_sync() {
    local dir="$1" arg
    local -a env_args=()
    shift
    : > "$MOCK_PNPM_CALLS"
    : > "$TMP_DIR/corepack-calls"
    printf 'ok\n' > "$TMP_DIR/pnpm-mode"
    rm -f "$TMP_DIR/pnpm-version"
    for arg in "$@"; do
        case "$arg" in
            MOCK_PNPM_MODE=*) printf '%s\n' "${arg#MOCK_PNPM_MODE=}" > "$TMP_DIR/pnpm-mode" ;;
            MOCK_PNPM_VERSION=*) printf '%s\n' "${arg#MOCK_PNPM_VERSION=}" > "$TMP_DIR/pnpm-version" ;;
            *) env_args+=("$arg") ;;
        esac
    done
    env PATH="$MOCK_BIN:$TOOLS_BIN" ${env_args[@]+"${env_args[@]}"} \
        "$dir/scripts/allium-deploy-sync-toolchain.sh" > "$TMP_DIR/sync.out" 2>&1
}

# Number of installs; pnpm --version calls do not count.
pnpm_calls() {
    grep -c '^install' "$MOCK_PNPM_CALLS" || true
}

assert_previous_restored() {
    local dir="$1" label="$2"
    [[ -f "$dir/node_modules/previous-marker" ]] || fail "$label: previous node_modules was not restored"
    [[ ! -e "$dir/node_modules/partial-install" ]] || fail "$label: partial install was left in place"
    [[ "$(WRANGLER_LOG=log "$dir/node_modules/.bin/wrangler" --version)" == "4.86.0" ]] || fail "$label: previous wrangler is not active"
    [[ ! -e "$dir/.toolchain/previous-node_modules" ]] || fail "$label: backup was left behind"
}

test_first_install_and_noop() {
    local dir
    dir=$(new_deploy_dir first)

    run_sync "$dir" || fail "first install failed: $(cat "$TMP_DIR/sync.out")"
    [[ "$(pnpm_calls)" == "1" ]] || fail "first install did not call pnpm once"
    grep -q -- 'install --frozen-lockfile' "$MOCK_PNPM_CALLS" || fail "install was not frozen to the lockfile"
    [[ "$(WRANGLER_LOG=log "$dir/node_modules/.bin/wrangler" --version)" == "4.86.0" ]] || fail "first install did not install the pin"
    [[ -s "$dir/node_modules/.allium-toolchain.sha256" ]] || fail "verified install was not stamped"
    [[ -z "$(git -C "$dir" status --porcelain --untracked-files=normal)" ]] || fail "install dirtied the checkout"

    run_sync "$dir" || fail "no-op sync failed"
    [[ "$(pnpm_calls)" == "0" ]] || fail "unchanged lockfile reinstalled"
    grep -q 'pinned toolchain is current' "$TMP_DIR/sync.out" || fail "no-op sync was not logged"

    # pnpm-workspace.yaml decides which install scripts run, so it is part of the pin.
    printf 'allowBuilds:\n  esbuild: true\n' > "$dir/pnpm-workspace.yaml"
    git -C "$dir" commit -qam "workspace"
    run_sync "$dir" || fail "workspace change sync failed: $(cat "$TMP_DIR/sync.out")"
    [[ "$(pnpm_calls)" == "1" ]] || fail "a pnpm-workspace.yaml change did not reinstall"
    pass "first sync installs and stamps the pin; unchanged files are a no-op; workspace changes reinstall"
}

test_lockfile_change_replaces_toolchain() {
    local dir
    dir=$(new_deploy_dir upgrade)
    seed_installed_toolchain "$dir" 4.86.0
    bump_pin "$dir" 4.149.0

    run_sync "$dir" || fail "upgrade failed: $(cat "$TMP_DIR/sync.out")"
    [[ "$(WRANGLER_LOG=log "$dir/node_modules/.bin/wrangler" --version)" == "4.149.0" ]] || fail "upgrade did not install the new pin"
    [[ ! -e "$dir/node_modules/previous-marker" ]] || fail "upgrade reused the previous tree"
    [[ ! -e "$dir/.toolchain/previous-node_modules" ]] || fail "backup was not discarded after success"
    grep -q 'wrangler 4.86.0 -> 4.149.0' "$TMP_DIR/sync.out" || fail "version change was not logged"
    pass "a changed lockfile installs the new pin and discards the backup"
}

test_failures_restore_previous_toolchain() {
    local dir mode
    for mode in fail wrong-version dirty staged; do
        dir=$(new_deploy_dir "failure-$mode")
        seed_installed_toolchain "$dir" 4.86.0
        bump_pin "$dir" 4.149.0

        if run_sync "$dir" MOCK_PNPM_MODE="$mode"; then
            fail "$mode: sync reported success"
        fi
        assert_previous_restored "$dir" "$mode"
        git -C "$dir" diff --quiet HEAD -- pnpm-workspace.yaml || fail "$mode: changed toolchain manifest was not reverted"
        case "$mode" in
            fail)
                [[ -e "$dir/stray-install-file" ]] || fail "$mode: an untracked file outside the manifests was deleted"
                grep -q 'left changes outside the toolchain manifests in place' "$TMP_DIR/sync.out" \
                    || fail "$mode: untracked leftovers were not reported"
                ;;
            dirty)
                [[ -e "$dir/stray-dir/file" ]] || fail "$mode: an untracked file outside the manifests was deleted"
                grep -q 'left changes outside the toolchain manifests in place' "$TMP_DIR/sync.out" \
                    || fail "$mode: untracked leftovers were not reported"
                grep -q 'install changed the checkout' "$TMP_DIR/sync.out" \
                    || fail "dirty checkout reason was not logged"
                ;;
            staged)
                # Staged manifest edits are reverted in the index too; the
                # newly added .npmrc has no HEAD version, so it is kept and reported.
                git -C "$dir" diff --cached --quiet -- pnpm-workspace.yaml \
                    || fail "$mode: staged toolchain manifest change was not reverted"
                git -C "$dir" diff --cached --quiet -- pnpm-lock.yaml \
                    || fail "$mode: index-only toolchain manifest change was not reverted"
                [[ "$(git -C "$dir" status --porcelain -- .npmrc)" == "A  .npmrc" ]] \
                    || fail "$mode: a newly added manifest was not left in place"
                grep -q 'left in place\] A  .npmrc' "$TMP_DIR/sync.out" \
                    || fail "$mode: the newly added manifest was not reported"
                ;;
            *) assert_checkout_clean "$dir" "$mode" ;;
        esac
        [[ ! -e "$dir/node_modules/.allium-toolchain.sha256" ]] || fail "$mode: failed install was stamped"
        grep -q 'install failed' "$TMP_DIR/sync.out" || fail "$mode: failure was not logged"
    done
    pass "install, version, and checkout failures restore the previous toolchain, revert only the toolchain manifests (staged or not), and never delete other files"
}

test_failed_lockfile_retry_backoff() {
    local dir
    dir=$(new_deploy_dir backoff)
    seed_installed_toolchain "$dir" 4.86.0
    bump_pin "$dir" 4.149.0
    if run_sync "$dir" MOCK_PNPM_MODE=fail; then
        fail "failed install reported success"
    fi
    # The failed install left an untracked file the sync reports but never
    # deletes; an operator removes it before the next attempt.
    rm -f "$dir/stray-install-file"

    if run_sync "$dir"; then
        fail "backed-off sync reported success"
    fi
    [[ "$(pnpm_calls)" == "0" ]] || fail "a failed lockfile was retried within the retry interval"
    grep -q 'skipping install: this lockfile failed to install' "$TMP_DIR/sync.out" || fail "backoff was not logged"
    assert_previous_restored "$dir" "backoff"

    # The interval is measured from the failure.
    printf '%s %s\n' "$(cut -d ' ' -f1 "$dir/.toolchain/last-failure")" "$(($(date +%s) - 3601))" \
        > "$dir/.toolchain/last-failure"
    run_sync "$dir" MOCK_PNPM_MODE=fail || true
    [[ "$(pnpm_calls)" == "1" ]] || fail "a failed lockfile was not retried after the retry interval"
    rm -f "$dir/stray-install-file"

    # A different lockfile, such as a revert, is tried at once.
    bump_pin "$dir" 4.150.0
    run_sync "$dir" || fail "a new lockfile was held back by an older failure: $(cat "$TMP_DIR/sync.out")"
    [[ "$(WRANGLER_LOG=log "$dir/node_modules/.bin/wrangler" --version)" == "4.150.0" ]] || fail "new lockfile was not installed"
    [[ ! -e "$dir/.toolchain/last-failure" ]] || fail "failure record was kept after a successful install"

    if run_sync "$dir" CF_ASSETS_TOOLCHAIN_RETRY_SECONDS=soon; then
        fail "invalid retry interval was accepted"
    fi
    pass "a failed lockfile is retried after the retry interval; a different lockfile at once"
}

test_timeout_restores_previous_toolchain() {
    local dir started elapsed
    dir=$(new_deploy_dir timeout)
    seed_installed_toolchain "$dir" 4.86.0
    bump_pin "$dir" 4.149.0

    started=$(date +%s)
    if run_sync "$dir" MOCK_PNPM_MODE=hang CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT=1; then
        fail "timed-out install reported success"
    fi
    elapsed=$(($(date +%s) - started))
    (( elapsed < 20 )) || fail "install timeout was not enforced (${elapsed}s)"
    assert_previous_restored "$dir" "timeout"

    # A new runtime that hangs at startup must not hold the deploy lock.
    dir=$(new_deploy_dir version-timeout)
    seed_installed_toolchain "$dir" 4.86.0
    bump_pin "$dir" 4.149.0
    started=$(date +%s)
    if run_sync "$dir" MOCK_PNPM_MODE=hang-version CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT=2; then
        fail "hung wrangler --version reported success"
    fi
    elapsed=$(($(date +%s) - started))
    (( elapsed < 20 )) || fail "wrangler --version was not bounded (${elapsed}s)"
    grep -q 'installed wrangler does not run' "$TMP_DIR/sync.out" || fail "hung version check was not logged"
    assert_previous_restored "$dir" "version-timeout"

    # The timeout stops the install's children too, not only pnpm itself.
    dir=$(new_deploy_dir timeout-children)
    seed_installed_toolchain "$dir" 4.86.0
    bump_pin "$dir" 4.149.0
    rm -f "$TMP_DIR/late-write"
    if run_sync "$dir" MOCK_PNPM_MODE=hang-child CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT=1; then
        fail "timed-out install with a child reported success"
    fi
    sleep 4
    [[ ! -e "$TMP_DIR/late-write" ]] || fail "a child of the timed-out install kept running"
    assert_previous_restored "$dir" "timeout-children"
    pass "a hung install, its children, or a hung version check are bounded and restore the previous toolchain"
}

test_interrupted_sync_is_recovered() {
    local dir
    dir=$(new_deploy_dir interrupted)
    # A verified, stamped tree for the current lockfile.
    run_sync "$dir" || fail "initial install failed: $(cat "$TMP_DIR/sync.out")"
    printf 'previous\n' > "$dir/node_modules/previous-marker"
    mkdir -p "$dir/.toolchain"
    mv "$dir/node_modules" "$dir/.toolchain/previous-node_modules"
    mkdir -p "$dir/node_modules"
    printf 'partial\n' > "$dir/node_modules/partial-install"

    run_sync "$dir" || fail "recovery failed: $(cat "$TMP_DIR/sync.out")"
    [[ "$(pnpm_calls)" == "0" ]] || fail "recovered verified tree was reinstalled"
    assert_previous_restored "$dir" "interrupted"

    # Interrupted after the new tree was verified and stamped: keep it.
    bump_pin "$dir" 4.149.0
    run_sync "$dir" || fail "upgrade before second interruption failed"
    mkdir -p "$dir/.toolchain/previous-node_modules"
    printf 'stale\n' > "$dir/.toolchain/previous-node_modules/previous-marker"
    run_sync "$dir" || fail "verified-tree recovery failed: $(cat "$TMP_DIR/sync.out")"
    [[ "$(pnpm_calls)" == "0" ]] || fail "verified new tree was reinstalled"
    [[ "$(WRANGLER_LOG=log "$dir/node_modules/.bin/wrangler" --version)" == "4.149.0" ]] || fail "verified new tree was replaced"
    [[ ! -e "$dir/.toolchain/previous-node_modules" ]] || fail "stale backup was not discarded"
    pass "an interrupted sync keeps a verified tree, otherwise restores the previous one"
}

test_refusals_leave_toolchain_untouched() {
    local dir
    dir=$(new_deploy_dir dirty-before)
    seed_installed_toolchain "$dir" 4.86.0
    bump_pin "$dir" 4.149.0
    printf 'local edit\n' >> "$dir/pnpm-workspace.yaml"
    if run_sync "$dir"; then
        fail "dirty checkout was synced"
    fi
    [[ "$(pnpm_calls)" == "0" ]] || fail "dirty checkout called pnpm"
    assert_previous_restored "$dir" "dirty-before"

    dir=$(new_deploy_dir range-pin)
    seed_installed_toolchain "$dir" 4.86.0
    printf '{"devDependencies":{"wrangler":"^4.149.0"}}\n' > "$dir/package.json"
    git -C "$dir" commit -qam "range pin"
    if run_sync "$dir"; then
        fail "range pin was synced"
    fi
    [[ "$(pnpm_calls)" == "0" ]] || fail "range pin called pnpm"
    assert_previous_restored "$dir" "range-pin"

    if run_sync "$dir" CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT=0; then
        fail "invalid timeout was accepted"
    fi

    if [[ "$(id -u)" == "0" ]]; then
        pass "dirty checkouts, range pins, and invalid timeouts never touch node_modules (move test skipped as root)"
        return
    fi
    # node_modules cannot be moved aside: it must stay exactly where it is.
    dir=$(new_deploy_dir unmovable)
    seed_installed_toolchain "$dir" 4.86.0
    bump_pin "$dir" 4.149.0
    mkdir -p "$dir/.toolchain"
    chmod 555 "$dir/.toolchain"
    if run_sync "$dir"; then
        chmod 755 "$dir/.toolchain"
        fail "sync succeeded without moving node_modules aside"
    fi
    chmod 755 "$dir/.toolchain"
    [[ "$(pnpm_calls)" == "0" ]] || fail "install ran although node_modules was not moved aside"
    assert_previous_restored "$dir" "unmovable"
    pass "dirty checkouts, range pins, invalid timeouts, and failed moves never touch node_modules"
}

test_install_environment_is_scrubbed() {
    local dir
    dir=$(new_deploy_dir scrubbed)
    seed_installed_toolchain "$dir" 4.86.0
    bump_pin "$dir" 4.149.0
    rm -f "$TMP_DIR/leaks"

    run_sync "$dir" TOOLCHAIN_TEST_SECRET=hunter2 R2_SECRET_ACCESS_KEY=hunter2 \
        || fail "install with deploy settings in the environment failed: $(cat "$TMP_DIR/sync.out")"
    [[ ! -e "$TMP_DIR/leaks" ]] || fail "deploy settings reached: $(tr '\n' ' ' < "$TMP_DIR/leaks")"
    [[ "$(pnpm_calls)" == "1" ]] || fail "scrubbed install did not run"
    [[ "$(grep -c '^pnpm install' "$TMP_DIR/corepack-calls")" == "1" ]] || fail "install did not run through corepack"
    [[ "$(WRANGLER_LOG=log "$dir/node_modules/.bin/wrangler" --version)" == "4.149.0" ]] \
        || fail "scrubbed install did not install the pin"

    # Both probes detect a setting they can see.
    TOOLCHAIN_TEST_SECRET=hunter2 "$MOCK_BIN/pnpm" --version > /dev/null
    TOOLCHAIN_TEST_SECRET=hunter2 WRANGLER_LOG=log "$dir/node_modules/.bin/wrangler" --version > /dev/null
    [[ "$(tr '\n' ' ' < "$TMP_DIR/leaks")" == "pnpm wrangler " ]] || fail "leak probes do not detect an inherited setting"
    rm -f "$TMP_DIR/leaks"
    pass "pnpm, its build scripts and the new Wrangler never see the deploy job's settings; pnpm runs through corepack"
}

test_pnpm_selection() {
    local dir started manifest='{"packageManager":"pnpm@10.34.5","devDependencies":{"wrangler":"4.149.0"}}'

    dir=$(new_deploy_dir pnpm-match)
    seed_installed_toolchain "$dir" 4.86.0
    printf '%s\n' "$manifest" > "$dir/package.json"
    git -C "$dir" commit -qam "packageManager"
    run_sync "$dir" PATH="$PNPM_ONLY_BIN:$TOOLS_BIN" \
        || fail "pnpm matching packageManager was refused: $(cat "$TMP_DIR/sync.out")"
    [[ "$(pnpm_calls)" == "1" && ! -s "$TMP_DIR/corepack-calls" ]] || fail "matching pnpm on PATH did not install"

    dir=$(new_deploy_dir pnpm-mismatch)
    seed_installed_toolchain "$dir" 4.86.0
    printf '%s\n' "$manifest" > "$dir/package.json"
    git -C "$dir" commit -qam "packageManager"
    if run_sync "$dir" PATH="$PNPM_ONLY_BIN:$TOOLS_BIN" MOCK_PNPM_VERSION=9.15.0; then
        fail "a pnpm that does not match packageManager was used"
    fi
    [[ "$(pnpm_calls)" == "0" ]] || fail "mismatched pnpm ran an install"
    grep -q 'corepack, or pnpm matching packageManager (pnpm@10.34.5), is required' "$TMP_DIR/sync.out" \
        || fail "mismatched pnpm refusal was not explained: $(cat "$TMP_DIR/sync.out")"
    assert_previous_restored "$dir" "pnpm-mismatch"

    started=$(date +%s)
    if run_sync "$dir" PATH="$PNPM_ONLY_BIN:$TOOLS_BIN" MOCK_PNPM_VERSION=hang CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT=2; then
        fail "a pnpm whose version probe hangs was used"
    fi
    (( $(date +%s) - started < 20 )) || fail "hung pnpm --version probe was not bounded"
    [[ "$(pnpm_calls)" == "0" ]] || fail "hung pnpm probe ran an install"

    if run_sync "$dir" PATH="$TOOLS_BIN"; then
        fail "sync ran without corepack or pnpm"
    fi
    [[ "$(pnpm_calls)" == "0" ]] || fail "sync without corepack or pnpm ran an install"
    assert_previous_restored "$dir" "no-pnpm"
    pass "corepack is preferred; a pnpm on PATH is used only when it matches packageManager, and a hung probe is bounded"
}

test_requires_gnu_timeout() {
    local dir
    dir=$(new_deploy_dir no-timeout)
    seed_installed_toolchain "$dir" 4.86.0
    bump_pin "$dir" 4.149.0
    if run_sync "$dir" PATH="$MOCK_BIN:$TOOLS_NO_TIMEOUT_BIN"; then
        fail "sync installed without GNU timeout"
    fi
    [[ "$(pnpm_calls)" == "0" ]] || fail "install ran without GNU timeout"
    grep -q 'GNU timeout is required' "$TMP_DIR/sync.out" || fail "missing GNU timeout was not explained: $(cat "$TMP_DIR/sync.out")"
    assert_previous_restored "$dir" "no-timeout"
    pass "without GNU timeout the sync refuses and keeps the previous toolchain"
}

test_update_hook() {
    local calls="$TMP_DIR/hook-calls" output
    cat > "$TMP_DIR/sync-stub.sh" <<'STUB'
#!/usr/bin/env bash
printf 'timeout=%s retry=%s\n' "$CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT" "$CF_ASSETS_TOOLCHAIN_RETRY_SECONDS" >> "$HOOK_CALLS"
exit "${HOOK_EXIT:-0}"
STUB
    chmod +x "$TMP_DIR/sync-stub.sh"
    export HOOK_CALLS="$calls"

    export ALLIUM_DEPLOY_TEST_MODE=1
    # shellcheck source=../scripts/allium-deploy-update.sh
    source "$ROOT_DIR/scripts/allium-deploy-update.sh"
    CF_ASSETS_TOOLCHAIN_SYNC_SCRIPT="$TMP_DIR/sync-stub.sh"
    CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT=42
    CF_ASSETS_TOOLCHAIN_RETRY_SECONDS=7

    : > "$calls"
    CF_ASSETS_ENABLED=false CF_ASSETS_TOOLCHAIN_AUTO_SYNC=true sync_workers_toolchain
    [[ ! -s "$calls" ]] || fail "hook ran with Workers Assets disabled"

    CF_ASSETS_ENABLED=true CF_ASSETS_TOOLCHAIN_AUTO_SYNC=false sync_workers_toolchain > /dev/null
    [[ ! -s "$calls" ]] || fail "hook ran with auto-sync disabled"

    CF_ASSETS_ENABLED=true CF_ASSETS_TOOLCHAIN_AUTO_SYNC=true sync_workers_toolchain
    [[ "$(cat "$calls")" == "timeout=42 retry=7" ]] || fail "hook did not pass the install timeout and retry interval"

    : > "$calls"
    output=$(HOOK_EXIT=1 CF_ASSETS_ENABLED=true CF_ASSETS_TOOLCHAIN_AUTO_SYNC=true sync_workers_toolchain) \
        || fail "a failed sync aborted the deployment"
    [[ -s "$calls" ]] || fail "hook did not run the sync script"
    grep -q 'continuing with the previously installed toolchain' <<< "$output" \
        || fail "failed sync was not logged"

    [[ "$(<"$ROOT_DIR/scripts/allium-deploy-update.sh")" == \
        *$'\nguarded_pull_allium\nsync_workers_toolchain\nif ! capture_cfassets_deploy_snapshot; then\n'* ]] \
        || fail "sync is not between guarded pulls and the Workers snapshot"
    pass "update hook is gated, passes its settings, and never aborts the deployment"
}

test_requires_gnu_timeout
if (( GNU_TIMEOUT )); then
    test_first_install_and_noop
    test_lockfile_change_replaces_toolchain
    test_failures_restore_previous_toolchain
    test_failed_lockfile_retry_backoff
    test_timeout_restores_previous_toolchain
    test_interrupted_sync_is_recovered
    test_refusals_leave_toolchain_untouched
    test_install_environment_is_scrubbed
    test_pnpm_selection
else
    echo "ok - # SKIP install cases: no GNU timeout on this host (CI runs them)"
fi
test_update_hook
