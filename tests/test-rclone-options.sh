#!/usr/bin/env bash

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$TEST_DIR")"

# shellcheck source=../scripts/allium-deploy-upload-common.sh
source "$ROOT_DIR/scripts/allium-deploy-upload-common.sh"

TRANSFERS=4
CHECKERS=8
BUFFER_SIZE=16M
S3_CONCURRENCY=2
S3_CHUNK=8M

RCLONE_FAST_LIST=true
opts=$(build_rclone_opts)
[[ " $opts " == *" --fast-list "* ]] || {
    echo "expected --fast-list when RCLONE_FAST_LIST=true" >&2
    exit 1
}

RCLONE_FAST_LIST=false
opts=$(build_rclone_opts)
[[ " $opts " != *" --fast-list "* ]] || {
    echo "did not expect --fast-list when RCLONE_FAST_LIST=false" >&2
    exit 1
}

RCLONE_FAST_LIST=invalid
if build_rclone_opts >/dev/null 2>&1; then
    echo "invalid RCLONE_FAST_LIST should fail closed" >&2
    exit 1
fi

grep -Fq 'RCLONE_FAST_LIST="${DO_RCLONE_FAST_LIST:-false}"' \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" || {
        echo "DigitalOcean must default to directory traversal" >&2
        exit 1
    }

echo "rclone option tests passed"
