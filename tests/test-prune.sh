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
        printf '%s\n' "${RCLONE_LSF_OUTPUT:-}"
        ;;
    purge)
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

run_prune() {
    local backup_dir="$1"
    local rclone_path="$2"
    local purge_log="$3"
    local r2_listing="$4"

    BACKUP_DIR="$backup_dir" \
    KEEP_BACKUPS=5 \
    R2_BUCKET=test-bucket \
    RCLONE_PATH="$rclone_path" \
    RCLONE_PURGE_LOG="$purge_log" \
    RCLONE_LSF_OUTPUT="$r2_listing" \
        "$ROOT_DIR/scripts/allium-deploy-prune.sh" >/dev/null
}

test_empty_backup_sets_skip_cleanly() {
    local backup_dir rclone_dir purge_log
    backup_dir="$TMP_DIR/empty-local"
    rclone_dir="$TMP_DIR/rclone bin"
    purge_log="$TMP_DIR/empty-purge.log"
    mkdir -p "$backup_dir"
    make_rclone_stub "$rclone_dir"

    run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" ""

    [[ -z "$(find "$backup_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || fail "empty local backup dir changed"
    [[ ! -s "$purge_log" ]] || fail "empty R2 listing triggered purge"
    pass "empty local and R2 backup sets skip cleanly"
}

test_multiple_backups_prune_oldest() {
    local backup_dir rclone_dir purge_log i r2_listing remaining purged expected_purges
    backup_dir="$TMP_DIR/multi local"
    rclone_dir="$TMP_DIR/rclone bin multi"
    purge_log="$TMP_DIR/multi-purge.log"
    mkdir -p "$backup_dir"
    make_rclone_stub "$rclone_dir"

    r2_listing=""
    for i in 1 2 3 4 5 6 7 8; do
        mkdir -p "$backup_dir/backup-0$i"
        touch -t "20260101010$i" "$backup_dir/backup-0$i"
        r2_listing+="backup-0$i/"$'\n'
    done

    run_prune "$backup_dir" "$rclone_dir/rclone" "$purge_log" "$r2_listing"

    remaining=$(find "$backup_dir" -mindepth 1 -maxdepth 1 -type d -name 'backup-*' -exec basename {} \; | sort | paste -sd ' ' -)
    [[ "$remaining" == "backup-04 backup-05 backup-06 backup-07 backup-08" ]] || fail "unexpected local backups remain: $remaining"

    purged=$(sort "$purge_log" | paste -sd ' ' -)
    expected_purges="r2-metrics:test-bucket/_backups/backup-01/ r2-metrics:test-bucket/_backups/backup-02/ r2-metrics:test-bucket/_backups/backup-03/"
    [[ "$purged" == "$expected_purges" ]] || fail "unexpected R2 purges: $purged"
    pass "multiple local and R2 backups prune oldest entries"
}

test_empty_backup_sets_skip_cleanly
test_multiple_backups_prune_oldest
