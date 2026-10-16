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
TPS_LIMIT=120
TPS_LIMIT_BURST=1
S3_DISABLE_HTTP2=true

RCLONE_FAST_LIST=true
opts=$(build_rclone_opts)
[[ " $opts " == *" --fast-list "* ]] || {
    echo "expected --fast-list when RCLONE_FAST_LIST=true" >&2
    exit 1
}
[[ " $opts " == *" --tpslimit=120 "* ]] || {
    echo "expected configured transaction-rate limit" >&2
    exit 1
}
[[ " $opts " == *" --tpslimit-burst=1 "* ]] || {
    echo "expected configured transaction-rate burst" >&2
    exit 1
}
[[ " $opts " == *" --s3-disable-http2 "* ]] || {
    echo "expected configured S3 HTTP/2 disable flag" >&2
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

RCLONE_FAST_LIST=false
TPS_LIMIT=invalid
if build_rclone_opts >/dev/null 2>&1; then
    echo "invalid RCLONE_TPS_LIMIT should fail closed" >&2
    exit 1
fi

TPS_LIMIT=120
TPS_LIMIT_BURST=0
if build_rclone_opts >/dev/null 2>&1; then
    echo "invalid RCLONE_TPS_LIMIT_BURST should fail closed" >&2
    exit 1
fi
TPS_LIMIT_BURST=1

S3_DISABLE_HTTP2=invalid
if build_rclone_opts >/dev/null 2>&1; then
    echo "invalid RCLONE_S3_DISABLE_HTTP2 should fail closed" >&2
    exit 1
fi

S3_DISABLE_HTTP2=false
opts=$(build_rclone_opts)
[[ " $opts " != *" --s3-disable-http2 "* ]] || {
    echo "did not expect S3 HTTP/2 disable flag when configured false" >&2
    exit 1
}
S3_DISABLE_HTTP2=true

RCLONE_CHECKSUM=true
opts=$(build_rclone_opts)
[[ " $opts " == *" --checksum "* ]] || {
    echo "expected --checksum when RCLONE_CHECKSUM=true" >&2
    exit 1
}

RCLONE_CHECKSUM=false
opts=$(build_rclone_opts)
[[ " $opts " != *" --checksum "* ]] || {
    echo "did not expect --checksum when RCLONE_CHECKSUM=false" >&2
    exit 1
}

RCLONE_CHECKSUM=invalid
if build_rclone_opts >/dev/null 2>&1; then
    echo "invalid RCLONE_CHECKSUM should fail closed" >&2
    exit 1
fi
RCLONE_CHECKSUM=false

# Skipping the post-upload HEAD is opt-in and requires checksum comparison.
for checksum in false true; do
    RCLONE_CHECKSUM=$checksum
    opts=$(build_rclone_opts)
    [[ " $opts " != *" --s3-no-head "* ]] || {
        echo "did not expect --s3-no-head unless S3_NO_HEAD=true" >&2
        exit 1
    }
done

S3_NO_HEAD=true
RCLONE_CHECKSUM=true
opts=$(build_rclone_opts)
[[ " $opts " == *" --checksum --s3-no-head "* ]] || {
    echo "expected --s3-no-head when S3_NO_HEAD=true with checksum" >&2
    exit 1
}

RCLONE_CHECKSUM=false
if build_rclone_opts >/dev/null 2>&1; then
    echo "S3_NO_HEAD=true without checksum comparison should fail closed" >&2
    exit 1
fi

S3_NO_HEAD=invalid
RCLONE_CHECKSUM=true
if build_rclone_opts >/dev/null 2>&1; then
    echo "invalid S3_NO_HEAD should fail closed" >&2
    exit 1
fi
S3_NO_HEAD=false
RCLONE_CHECKSUM=false

grep -Fq 'RCLONE_CHECKSUM="${RCLONE_CHECKSUM:-false}"' \
    "$ROOT_DIR/scripts/allium-deploy-upload-common.sh" || {
        echo "shared uploads must default to modtime comparison" >&2
        exit 1
    }
grep -Fq 'RCLONE_CHECKSUM="${DO_RCLONE_CHECKSUM:-false}"' \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" || {
        echo "DigitalOcean checksum comparison must remain opt-in" >&2
        exit 1
    }
grep -Fxq '    S3_NO_HEAD=false' \
    "$ROOT_DIR/scripts/allium-deploy-upload-common.sh" || {
        echo "shared uploads must keep the post-upload HEAD" >&2
        exit 1
    }
grep -Fq 'DO_NO_HEAD="${DO_RCLONE_NO_HEAD:-false}"' \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" || {
        echo "skipping the DigitalOcean post-upload HEAD must remain opt-in" >&2
        exit 1
    }
grep -Fq 'DO_FAST_LIST_SUBTREES="${DO_RCLONE_FAST_LIST_SUBTREES:-}"' \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" || {
        echo "DigitalOcean per-subtree fast-list must remain opt-in" >&2
        exit 1
    }

grep -Fq 'RCLONE_FAST_LIST="${DO_RCLONE_FAST_LIST:-false}"' \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" || {
        echo "DigitalOcean must default to directory traversal" >&2
        exit 1
    }
grep -Fq 'TPS_LIMIT="${DO_RCLONE_TPS_LIMIT:-120}"' \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" || {
        echo "DigitalOcean must default to the bounded transaction rate" >&2
        exit 1
    }
grep -Fq 'S3_DISABLE_HTTP2="${DO_RCLONE_DISABLE_HTTP2:-true}"' \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" || {
        echo "DigitalOcean must default to independent HTTP/1.1 connections" >&2
        exit 1
    }
grep -Fq 'TPS_LIMIT="${DO_REMOTE_BACKUP_TPS_LIMIT:-30}"' \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" || {
        echo "DigitalOcean remote backup must default to a 30-operation cap" >&2
        exit 1
    }
grep -Fq 'DO_REMOTE_BACKUP_INLINE="${DO_REMOTE_BACKUP_INLINE:-true}"' \
    "$ROOT_DIR/scripts/allium-deploy-upload-do.sh" || {
        echo "DigitalOcean remote backup decoupling must remain opt-in" >&2
        exit 1
    }

echo "rclone option tests passed"
