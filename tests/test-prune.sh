#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "not ok - $1"
    exit 1
}

pass() {
    echo "ok - $1"
}

make_rclone_stub() {
    local bin_dir="$1"
    mkdir -p "$bin_dir"
    cat > "$bin_dir/rclone" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
    lsf)
        if [[ -n "${RCLONE_LSF_SLEEP:-}" ]]; then
            sleep "$RCLONE_LSF_SLEEP"
        fi
        if [[ -n "${RCLONE_LSF_ERROR:-}" || -n "${RCLONE_LSF_EXIT:-}" ]]; then
            if [[ -n "${RCLONE_LSF_ERROR:-}" ]]; then
                echo "$RCLONE_LSF_ERROR" >&2
            fi
            exit "${RCLONE_LSF_EXIT:-1}"
        fi
        printf '%s\n' "${RCLONE_LSF_OUTPUT:-}"
        ;;
    purge)
        if [[ -n "${RCLONE_PURGE_ERROR:-}" ]]; then
            echo "$RCLONE_PURGE_ERROR" >&2
            exit "${RCLONE_PURGE_EXIT:-1}"
        fi
        printf '%s\n' "${2:?purge path required}" >> "${RCLONE_PURGE_LOG:?RCLONE_PURGE_LOG must be set}"
        ;;
    *)
        echo "unexpected rclone command: $*" >&2
        exit 1
        ;;
esac
STUB
    chmod +x "$bin_dir/rclone"
}

make_ls_failure_stub() {
    local bin_dir="$1"
    mkdir -p "$bin_dir"
    cat > "$bin_dir/ls" <<'STUB'
#!/usr/bin/env bash
echo "forced ls failure" >&2
exit 2
STUB
    chmod +x "$bin_dir/ls"
}

make_timeout_stub() {
    local bin_dir="$1"
    mkdir -p "$bin_dir"
    cat > "$bin_dir/timeout" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail

sleep "${TIMEOUT_STUB_SLEEP:-0}"
exit "${TIMEOUT_STUB_EXIT:-0}"
STUB
    chmod +x "$bin_dir/timeout"
}

run_prune() {
    local backup_dir="$1"
    local rclone_path="$2"
    local purge_log="$3"
    local r2_listing="$4"

    BACKUP_DIR="$backup_dir" \
    KEEP_BACKUPS=5 \
    R2_BUCKET=test-bucket \
    RCLONE_PATH="$rclone_path" \
    R2_LIST_TIMEOUT="${R2_LIST_TIMEOUT:-300}" \
    RCLONE_PURGE_LOG="$purge_log" \
    RCLONE_LSF_OUTPUT="$r2_listing" \
    RCLONE_LSF_ERROR="${RCLONE_LSF_ERROR:-}" \
    RCLONE_LSF_EXIT="${RCLONE_LSF_EXIT:-}" \
    RCLONE_LSF_SLEEP="${RCLONE_LSF_SLEEP:-}" \
    RCLONE_PURGE_ERROR="${RCLONE_PURGE_ERROR:-}" \
    TIMEOUT_STUB_EXIT="${TIMEOUT_STUB_EXIT:-}" \
    TIMEOUT_STUB_SLEEP="${TIMEOUT_STUB_SLEEP:-}" \
        "$ROOT_DIR/scripts/allium-deploy-prune.sh"
}

test_empty_backup_sets_skip_cleanly() {
    local backup_dir rclone_dir purge_log
    backup_dir="$TMP_DIR/empty-local"
    rclone_dir="$TMP_DIR/rclone bin"
    purge_log="$TMP_DIR/empty-purge.log"
    mkdir -p "$backup_dir"
    make_rclone_stub "$rclone_dir"

    run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "" >/dev/null

    [[ -z "$(find "$backup_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || fail "empty local backup dir changed"
    [[ ! -s "$purge_log" ]] || fail "empty R2 listing triggered purge"
    pass "empty local and R2 backup sets skip cleanly"
}

test_environment_overrides_config_env() {
    local deploy_dir backup_dir rclone_dir purge_log
    deploy_dir="$TMP_DIR/config deploy"
    backup_dir="$TMP_DIR/config override local"
    rclone_dir="$TMP_DIR/rclone bin config override"
    purge_log="$TMP_DIR/config-override-purge.log"
    mkdir -p "$deploy_dir/scripts" "$backup_dir"
    cp "$ROOT_DIR/scripts/allium-deploy-lib.sh" "$deploy_dir/scripts/"
    cp "$ROOT_DIR/scripts/allium-deploy-prune.sh" "$deploy_dir/scripts/"
    make_rclone_stub "$rclone_dir"
    cat > "$deploy_dir/config.env" <<CONFIG
BACKUP_DIR="$TMP_DIR/config local should not be used"
R2_BUCKET=config-bucket
RCLONE_PATH=/bin/false
KEEP_BACKUPS=1
R2_LIST_TIMEOUT=1
CONFIG

    BACKUP_DIR="$backup_dir" \
    KEEP_BACKUPS=5 \
    R2_BUCKET=test-bucket \
    RCLONE_PATH="$rclone_dir/rclone" \
    R2_LIST_TIMEOUT=300 \
    RCLONE_PURGE_LOG="$purge_log" \
    RCLONE_LSF_OUTPUT="" \
    "$deploy_dir/scripts/allium-deploy-prune.sh" >/dev/null

    [[ -z "$(find "$backup_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || fail "config override backup dir changed"
    [[ ! -s "$purge_log" ]] || fail "config override triggered purge"
    pass "environment overrides config.env"
}

test_multiple_backups_prune_oldest() {
    local backup_dir rclone_dir purge_log i name r2_listing remaining purged expected_purges
    backup_dir="$TMP_DIR/multi local"
    rclone_dir="$TMP_DIR/rclone bin multi"
    purge_log="$TMP_DIR/multi-purge.log"
    mkdir -p "$backup_dir"
    make_rclone_stub "$rclone_dir"

    r2_listing=""
    for i in 1 2 3 4 5 6 7 8; do
        name="backup-0$i"
        if [[ "$i" == "1" ]]; then
            name="backup-01 old"
        fi
        mkdir -p "$backup_dir/$name"
        touch -t "20260101010$i" "$backup_dir/$name"
        r2_listing+="$name/"$'\n'
    done

    run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "$r2_listing" >/dev/null

    remaining=$(find "$backup_dir" -mindepth 1 -maxdepth 1 -type d -name 'backup-*' -exec basename {} \; | sort | paste -sd ' ' -)
    [[ "$remaining" == "backup-04 backup-05 backup-06 backup-07 backup-08" ]] || fail "unexpected local backups remain: $remaining"

    purged=$(sort "$purge_log" | paste -sd ' ' -)
    expected_purges="r2-metrics:test-bucket/_backups/backup-01 old/ r2-metrics:test-bucket/_backups/backup-02/ r2-metrics:test-bucket/_backups/backup-03/"
    [[ "$purged" == "$expected_purges" ]] || fail "unexpected R2 purges: $purged"
    pass "multiple local and R2 backups prune oldest entries"
}

test_safety_buffer_boundary_skips_prune() {
    local backup_dir rclone_dir purge_log i r2_listing remaining
    backup_dir="$TMP_DIR/boundary local"
    rclone_dir="$TMP_DIR/rclone bin boundary"
    purge_log="$TMP_DIR/boundary-purge.log"
    mkdir -p "$backup_dir"
    make_rclone_stub "$rclone_dir"

    r2_listing=""
    for i in 1 2 3 4 5 6 7; do
        mkdir -p "$backup_dir/backup-0$i"
        touch -t "20260101010$i" "$backup_dir/backup-0$i"
        r2_listing+="backup-0$i/"$'\n'
    done

    run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "$r2_listing" >/dev/null

    remaining=$(find "$backup_dir" -mindepth 1 -maxdepth 1 -type d -name 'backup-*' -exec basename {} \; | sort | paste -sd ' ' -)
    [[ "$remaining" == "backup-01 backup-02 backup-03 backup-04 backup-05 backup-06 backup-07" ]] || fail "boundary local backups changed: $remaining"
    [[ ! -s "$purge_log" ]] || fail "boundary R2 listing triggered purge"
    pass "safety buffer boundary skips local and R2 pruning"
}

test_r2_listing_failure_is_reported() {
    local backup_dir rclone_dir purge_log output
    backup_dir="$TMP_DIR/r2-lsf-fail"
    rclone_dir="$TMP_DIR/rclone bin r2 lsf fail"
    purge_log="$TMP_DIR/r2-lsf-fail-purge.log"
    mkdir -p "$backup_dir"
    make_rclone_stub "$rclone_dir"

    if output=$(RCLONE_LSF_ERROR="r2 auth failed" run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "" 2>&1); then
        fail "R2 listing failure was treated as success"
    fi
    grep -q "R2 backup enumeration failed: r2 auth failed" <<< "$output" || fail "R2 listing failure was not reported: $output"
    pass "R2 listing failures are reported"
}

test_r2_listing_timeout_is_reported() {
    local backup_dir rclone_dir purge_log output
    backup_dir="$TMP_DIR/r2-lsf-timeout"
    rclone_dir="$TMP_DIR/rclone bin r2 lsf timeout"
    purge_log="$TMP_DIR/r2-lsf-timeout-purge.log"
    mkdir -p "$backup_dir"
    make_rclone_stub "$rclone_dir"

    if output=$(RCLONE_LSF_SLEEP=2 R2_LIST_TIMEOUT=1 run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "" 2>&1); then
        fail "R2 listing timeout was treated as success"
    fi
    grep -q "R2 backup enumeration failed: timed out after 1s" <<< "$output" || fail "R2 listing timeout was not reported: $output"
    pass "R2 listing timeouts are reported"
}

test_r2_listing_sigkill_timeout_is_reported() {
    local backup_dir rclone_dir timeout_dir purge_log output
    backup_dir="$TMP_DIR/r2-lsf-sigkill-timeout"
    rclone_dir="$TMP_DIR/rclone bin r2 lsf sigkill timeout"
    timeout_dir="$TMP_DIR/timeout bin r2 lsf sigkill timeout"
    purge_log="$TMP_DIR/r2-lsf-sigkill-timeout-purge.log"
    mkdir -p "$backup_dir"
    make_rclone_stub "$rclone_dir"
    make_timeout_stub "$timeout_dir"

    if output=$(PATH="$timeout_dir:$PATH" TIMEOUT_STUB_EXIT=137 TIMEOUT_STUB_SLEEP=2 R2_LIST_TIMEOUT=1 run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "" 2>&1); then
        fail "R2 listing SIGKILL timeout was treated as success"
    fi
    grep -q "R2 backup enumeration failed: timed out after 1s" <<< "$output" || fail "R2 listing SIGKILL timeout was not reported: $output"
    pass "R2 listing SIGKILL timeouts are reported"
}

test_r2_listing_sigkill_failure_is_reported() {
    local backup_dir rclone_dir purge_log output
    backup_dir="$TMP_DIR/r2-lsf-sigkill-fail"
    rclone_dir="$TMP_DIR/rclone bin r2 lsf sigkill fail"
    purge_log="$TMP_DIR/r2-lsf-sigkill-fail-purge.log"
    mkdir -p "$backup_dir"
    make_rclone_stub "$rclone_dir"

    if output=$(RCLONE_LSF_EXIT=137 R2_LIST_TIMEOUT=300 run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "" 2>&1); then
        fail "R2 listing SIGKILL failure was treated as success"
    fi
    grep -q "R2 backup enumeration failed: exit status 137" <<< "$output" || fail "R2 listing SIGKILL failure was not reported: $output"
    pass "R2 listing SIGKILL failures are reported"
}

test_r2_purge_failure_is_reported() {
    local backup_dir rclone_dir purge_log i r2_listing output
    backup_dir="$TMP_DIR/r2-purge-fail"
    rclone_dir="$TMP_DIR/rclone bin r2 purge fail"
    purge_log="$TMP_DIR/r2-purge-fail-purge.log"
    mkdir -p "$backup_dir"
    make_rclone_stub "$rclone_dir"

    r2_listing=""
    for i in 1 2 3 4 5 6 7 8; do
        r2_listing+="backup-0$i/"$'\n'
    done

    if output=$(RCLONE_PURGE_ERROR="r2 purge failed" run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "$r2_listing" 2>&1); then
        fail "R2 purge failure was treated as success"
    fi
    grep -q "Failed to remove R2 backup" <<< "$output" || fail "R2 purge failure was not reported: $output"
    grep -q "R2 prune completed with one or more purge failures" <<< "$output" || fail "R2 purge failure did not fail the prune: $output"
    pass "R2 purge failures are reported"
}

test_local_enumeration_failure_is_reported() {
    local backup_dir ls_dir rclone_dir purge_log output
    backup_dir="$TMP_DIR/local-enum-fail"
    ls_dir="$TMP_DIR/ls fail bin"
    rclone_dir="$TMP_DIR/rclone bin local enum fail"
    purge_log="$TMP_DIR/local-enum-fail-purge.log"
    mkdir -p "$backup_dir/backup-01"
    make_ls_failure_stub "$ls_dir"
    make_rclone_stub "$rclone_dir"

    if output=$(PATH="$ls_dir:$PATH" run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "" 2>&1); then
        fail "local enumeration failure was treated as success"
    fi
    grep -q "Local backup enumeration failed" <<< "$output" || fail "local enumeration failure was not reported: $output"
    pass "local enumeration failures are reported"
}

test_local_permission_failure_is_reported() {
    local backup_dir rclone_dir purge_log output

    if [[ "$(id -u)" -eq 0 ]]; then
        pass "local permission failure test skipped under root"
        return
    fi

    backup_dir="$TMP_DIR/local-perm-fail"
    rclone_dir="$TMP_DIR/rclone bin local perm fail"
    purge_log="$TMP_DIR/local-perm-fail-purge.log"
    mkdir -p "$backup_dir/backup-01"
    make_rclone_stub "$rclone_dir"
    chmod 000 "$backup_dir"

    if output=$(run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "" 2>&1); then
        chmod 700 "$backup_dir"
        fail "local permission failure was treated as success"
    fi
    chmod 700 "$backup_dir"
    grep -q "Local backup enumeration failed" <<< "$output" || fail "local permission failure was not reported: $output"
    pass "local permission failures are reported"
}

test_empty_backup_sets_skip_cleanly
test_environment_overrides_config_env
test_multiple_backups_prune_oldest
test_safety_buffer_boundary_skips_prune
test_r2_listing_failure_is_reported
test_r2_listing_timeout_is_reported
test_r2_listing_sigkill_timeout_is_reported
test_r2_listing_sigkill_failure_is_reported
test_r2_purge_failure_is_reported
test_local_enumeration_failure_is_reported
test_local_permission_failure_is_reported
