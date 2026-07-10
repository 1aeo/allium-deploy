#!/usr/bin/env bash
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

make_gh_stub() {
    local bin_dir="$1"
    mkdir -p "$bin_dir"
    cat > "$bin_dir/gh" <<'STUB'
#!/usr/bin/env bash
for arg in "$@"; do
    case "$arg" in
        auth)
            exit "${GH_AUTH_EXIT:-0}"
            ;;
        api)
            printf '%s\n' "${GH_CHECKS_PAYLOAD:?GH_CHECKS_PAYLOAD must be set}"
            exit 0
            ;;
    esac
done
exit 1
STUB
    chmod +x "$bin_dir/gh"
}

source_update_script() {
    export ALLIUM_DEPLOY_TEST_MODE=1
    # shellcheck source=../scripts/allium-deploy-update.sh
    source "$ROOT_DIR/scripts/allium-deploy-update.sh"
}

test_allium_path_derivation() {
    local repo_root from_root from_subdir
    repo_root="$TMP_DIR/path-repo"
    git init -b master "$repo_root" >/dev/null
    mkdir -p "$repo_root/allium"
    touch "$repo_root/allium/allium.py"

    from_root=$(ALLIUM_DEPLOY_TEST_MODE=1 ALLIUM_DIR="$repo_root" bash -c 'source "$1"; printf "%s|%s\n" "$ALLIUM_REPO_DIR" "$ALLIUM_DIR"' _ "$ROOT_DIR/scripts/allium-deploy-update.sh")
    [[ "$from_root" == "$repo_root|$repo_root/allium" ]] || fail "repo-root ALLIUM_DIR derived unexpected paths: $from_root"

    from_subdir=$(ALLIUM_DEPLOY_TEST_MODE=1 ALLIUM_DIR="$repo_root/allium" bash -c 'source "$1"; printf "%s|%s\n" "$ALLIUM_REPO_DIR" "$ALLIUM_DIR"' _ "$ROOT_DIR/scripts/allium-deploy-update.sh")
    [[ "$from_subdir" == "$repo_root|$repo_root/allium" ]] || fail "generator-dir ALLIUM_DIR derived unexpected paths: $from_subdir"

    pass "allium path derivation supports repo root and generator dir"
}

init_repo_pair() {
    local branch="$1"
    local name="$2"
    local bare="$TMP_DIR/$name-origin.git"
    local seed="$TMP_DIR/$name-seed"
    local clone="$TMP_DIR/$name-clone"

    git init --bare "$bare" >/dev/null
    git init -b "$branch" "$seed" >/dev/null
    git -C "$seed" config user.name "1aeo"
    git -C "$seed" config user.email "1aeo@users.noreply.github.com"
    printf 'base\n' > "$seed/file.txt"
    git -C "$seed" add file.txt
    git -C "$seed" commit -m "base" >/dev/null
    git -C "$seed" remote add origin "$bare"
    git -C "$seed" push -u origin "$branch" >/dev/null 2>&1
    git --git-dir="$bare" symbolic-ref HEAD "refs/heads/$branch"
    git clone "$bare" "$clone" >/dev/null 2>&1

    printf '%s\n' "$bare|$seed|$clone"
}

push_remote_commit() {
    local seed="$1"
    local branch="$2"
    local text="$3"

    printf '%s\n' "$text" >> "$seed/file.txt"
    git -C "$seed" add file.txt
    git -C "$seed" commit -m "$text" >/dev/null
    git -C "$seed" push origin "$branch" >/dev/null 2>&1
}

install_cfpages_test_script() {
    local seed="$1"
    local clone="$2"

    mkdir -p "$seed/scripts"
    cp "$ROOT_DIR/scripts/allium-deploy-cfpages.sh" "$seed/scripts/allium-deploy-cfpages.sh"
    cp "$ROOT_DIR/scripts/allium-deploy-lib.sh" "$seed/scripts/allium-deploy-lib.sh"
    chmod +x "$seed/scripts/allium-deploy-cfpages.sh"
    git -C "$seed" add scripts/allium-deploy-cfpages.sh scripts/allium-deploy-lib.sh
    git -C "$seed" commit -m "add cfpages script" >/dev/null
    git -C "$seed" push origin main >/dev/null 2>&1
    git -C "$clone" pull --ff-only >/dev/null 2>&1
}

prepare_guarded_pull_test() {
    local clone="$1"
    local checks_payload="$2"

    export PATH="$TMP_DIR/bin:$PATH"
    make_gh_stub "$TMP_DIR/bin"
    unset GH_AUTH_EXIT
    export GH_CHECKS_PAYLOAD="$checks_payload"
    # shellcheck disable=SC2034
    ALLIUM_REPO_DIR="$clone"
    unset ALLIUM_ROLLBACK_SHA
    source_update_script
}

test_green_pull() {
    local parts seed clone old new
    parts=$(init_repo_pair master green)
    IFS='|' read -r _ seed clone <<< "$parts"
    old=$(git -C "$clone" rev-parse HEAD)
    push_remote_commit "$seed" master "green"
    new=$(git -C "$seed" rev-parse HEAD)

    prepare_guarded_pull_test "$clone" '{"total_count":1,"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}'

    guarded_pull_allium

    [[ "$(git -C "$clone" rev-parse HEAD)" == "$new" ]] || fail "green pull did not fast-forward"
    [[ "${ALLIUM_ROLLBACK_SHA:-}" == "$old" ]] || fail "green pull did not record rollback sha"
    pass "green check-runs allow fast-forward"
}

test_auth_failure_skips_check_runs() {
    export PATH="$TMP_DIR/bin:$PATH"
    make_gh_stub "$TMP_DIR/bin"
    export GH_AUTH_EXIT=1
    export GH_CHECKS_PAYLOAD='{"total_count":1,"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}'
    source_update_script

    if check_runs_are_green "1aeo/allium" "deadbeef" "allium"; then
        fail "unauthenticated gh was accepted"
    fi
    unset GH_AUTH_EXIT
    pass "unauthenticated gh skips check-run gate"
}

test_no_check_runs_skip_pull() {
    local parts seed clone old
    parts=$(init_repo_pair master no-checks)
    IFS='|' read -r _ seed clone <<< "$parts"
    old=$(git -C "$clone" rev-parse HEAD)
    push_remote_commit "$seed" master "unchecked"

    prepare_guarded_pull_test "$clone" '{"total_count":0,"check_runs":[]}'

    guarded_pull_allium

    [[ "$(git -C "$clone" rev-parse HEAD)" == "$old" ]] || fail "no-check-runs pull changed checkout"
    [[ -z "${ALLIUM_ROLLBACK_SHA:-}" ]] || fail "no-check-runs pull recorded rollback sha"
    pass "missing check-runs skip pull"
}

test_paginated_check_runs() {
    export PATH="$TMP_DIR/bin:$PATH"
    make_gh_stub "$TMP_DIR/bin"
    export GH_CHECKS_PAYLOAD=$'{"total_count":1,"check_runs":[{"name":"lint","status":"completed","conclusion":"success"}]}\n{"total_count":1,"check_runs":[{"name":"test","status":"completed","conclusion":"success"}]}'
    source_update_script

    check_runs_are_green "1aeo/allium" "deadbeef" "allium" || fail "paginated check-runs were not accepted"
    pass "paginated check-runs are parsed across pages"
}

test_not_green_skip() {
    local parts seed clone old
    parts=$(init_repo_pair master notgreen)
    IFS='|' read -r _ seed clone <<< "$parts"
    old=$(git -C "$clone" rev-parse HEAD)
    push_remote_commit "$seed" master "blocked"

    prepare_guarded_pull_test "$clone" '{"total_count":1,"check_runs":[{"name":"ci","status":"completed","conclusion":"failure"}]}'

    guarded_pull_allium

    [[ "$(git -C "$clone" rev-parse HEAD)" == "$old" ]] || fail "not-green pull changed checkout"
    [[ -z "${ALLIUM_ROLLBACK_SHA:-}" ]] || fail "not-green pull recorded rollback sha"
    pass "non-green check-runs skip pull"
}

test_ff_fail_skip() {
    local parts seed clone old
    parts=$(init_repo_pair master fffail)
    IFS='|' read -r _ seed clone <<< "$parts"
    printf 'local\n' >> "$clone/file.txt"
    git -C "$clone" config user.name "1aeo"
    git -C "$clone" config user.email "1aeo@users.noreply.github.com"
    git -C "$clone" add file.txt
    git -C "$clone" commit -m "local" >/dev/null
    old=$(git -C "$clone" rev-parse HEAD)
    push_remote_commit "$seed" master "remote"

    prepare_guarded_pull_test "$clone" '{"total_count":1,"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}'

    guarded_pull_allium

    [[ "$(git -C "$clone" rev-parse HEAD)" == "$old" ]] || fail "ff-fail changed checkout"
    [[ -z "${ALLIUM_ROLLBACK_SHA:-}" ]] || fail "ff-fail recorded rollback sha"
    pass "non-fast-forward remote skips pull"
}

test_dirty_worktree_skips_pull() {
    local parts seed clone old
    parts=$(init_repo_pair master dirty)
    IFS='|' read -r _ seed clone <<< "$parts"
    old=$(git -C "$clone" rev-parse HEAD)
    push_remote_commit "$seed" master "remote"
    printf 'dirty\n' >> "$clone/file.txt"

    prepare_guarded_pull_test "$clone" '{"total_count":1,"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}'

    guarded_pull_allium

    [[ "$(git -C "$clone" rev-parse HEAD)" == "$old" ]] || fail "dirty checkout changed HEAD"
    [[ -z "${ALLIUM_ROLLBACK_SHA:-}" ]] || fail "dirty checkout recorded rollback sha"
    pass "dirty checkout skips guarded pull"
}

test_fetch_failure_skips_pull() {
    local parts clone old
    parts=$(init_repo_pair master fetch-fail)
    IFS='|' read -r _ _ clone <<< "$parts"
    old=$(git -C "$clone" rev-parse HEAD)
    git -C "$clone" remote set-url origin "$TMP_DIR/missing-origin.git"

    prepare_guarded_pull_test "$clone" '{"total_count":1,"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}'

    guarded_pull_allium

    [[ "$(git -C "$clone" rev-parse HEAD)" == "$old" ]] || fail "fetch-failure checkout changed HEAD"
    [[ -z "${ALLIUM_ROLLBACK_SHA:-}" ]] || fail "fetch-failure recorded rollback sha"
    pass "fetch failure skips guarded pull"
}

test_wrong_branch_skips_pull() {
    local parts seed clone old
    parts=$(init_repo_pair master wrong-branch)
    IFS='|' read -r _ seed clone <<< "$parts"
    git -C "$clone" checkout -b side >/dev/null 2>&1
    old=$(git -C "$clone" rev-parse HEAD)
    push_remote_commit "$seed" master "remote"

    prepare_guarded_pull_test "$clone" '{"total_count":1,"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}'

    guarded_pull_allium

    [[ "$(git -C "$clone" branch --show-current)" == "side" ]] || fail "wrong-branch checkout changed branches"
    [[ "$(git -C "$clone" rev-parse HEAD)" == "$old" ]] || fail "wrong-branch checkout changed HEAD"
    [[ -z "${ALLIUM_ROLLBACK_SHA:-}" ]] || fail "wrong-branch checkout recorded rollback sha"
    pass "wrong branch skips guarded pull"
}

test_rollback_both() {
    local allium_parts deploy_parts allium_seed allium_clone deploy_seed deploy_clone allium_old deploy_old
    allium_parts=$(init_repo_pair master rollback-allium)
    deploy_parts=$(init_repo_pair main rollback-deploy)
    IFS='|' read -r _ allium_seed allium_clone <<< "$allium_parts"
    IFS='|' read -r _ deploy_seed deploy_clone <<< "$deploy_parts"
    allium_old=$(git -C "$allium_clone" rev-parse HEAD)
    deploy_old=$(git -C "$deploy_clone" rev-parse HEAD)
    push_remote_commit "$allium_seed" master "allium-next"
    push_remote_commit "$deploy_seed" main "deploy-next"

    export PATH="$TMP_DIR/bin:$PATH"
    make_gh_stub "$TMP_DIR/bin"
    export GH_CHECKS_PAYLOAD='{"total_count":1,"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}'
    source_update_script
    # shellcheck disable=SC2034
    ALLIUM_REPO_DIR="$allium_clone"
    # shellcheck disable=SC2034
    DEPLOY_DIR="$deploy_clone"
    unset ALLIUM_ROLLBACK_SHA ALLIUM_DEPLOY_ROLLBACK_SHA

    guarded_pull_allium
    guarded_pull_allium_deploy
    rollback_guarded_pulls

    [[ "$(git -C "$allium_clone" rev-parse HEAD)" == "$allium_old" ]] || fail "allium rollback did not restore pre-pull sha"
    [[ "$(git -C "$deploy_clone" rev-parse HEAD)" == "$deploy_old" ]] || fail "allium-deploy rollback did not restore pre-pull sha"
    [[ "$(git -C "$allium_clone" branch --show-current)" == "master" ]] || fail "allium rollback detached branch"
    [[ "$(git -C "$deploy_clone" branch --show-current)" == "main" ]] || fail "allium-deploy rollback detached branch"
    pass "rollback restores both pulled checkouts"
}

test_stale_cfpages_refuses_deploy() {
    local parts seed clone output
    parts=$(init_repo_pair main stale-cfpages)
    IFS='|' read -r _ seed clone <<< "$parts"
    install_cfpages_test_script "$seed" "$clone"
    push_remote_commit "$seed" main "new-function"

    if output=$(ALLIUM_CFPAGES_TEST_MODE=1 "$clone/scripts/allium-deploy-cfpages.sh" 2>&1); then
        fail "stale cfpages checkout was allowed"
    fi
    grep -q "Refusing Pages deploy" <<< "$output" || fail "stale cfpages refusal did not explain why"
    pass "stale Pages checkout refuses deploy"
}

test_fresh_cfpages_allows_deploy() {
    local parts seed clone output
    parts=$(init_repo_pair main fresh-cfpages)
    IFS='|' read -r _ seed clone <<< "$parts"
    install_cfpages_test_script "$seed" "$clone"

    if ! output=$(ALLIUM_CFPAGES_TEST_MODE=1 "$clone/scripts/allium-deploy-cfpages.sh" 2>&1); then
        fail "fresh cfpages checkout was refused: $output"
    fi
    pass "fresh Pages checkout allows deploy"
}

test_allium_path_derivation
test_green_pull
test_auth_failure_skips_check_runs
test_no_check_runs_skip_pull
test_paginated_check_runs
test_not_green_skip
test_ff_fail_skip
test_dirty_worktree_skips_pull
test_fetch_failure_skips_pull
test_wrong_branch_skips_pull
test_rollback_both
test_stale_cfpages_refuses_deploy
test_fresh_cfpages_allows_deploy
