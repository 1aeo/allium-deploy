#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

export STAGE5_ACTIVATION_TEST_MODE=1
export STAGE5_CONFIG_FILE="$TMP_DIR/config.env"
export STAGE5_ACTIVATION_LOG="$TMP_DIR/activation.log"
touch "$STAGE5_ACTIVATION_LOG"

# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/run-stage5-24h-activation.sh"

cat > "$STAGE5_CONFIG_FILE" <<'EOF'
R2_ENABLED=true
R2_CONTENT_SYNC_INTERVAL=every-build
DAILY_R2_BACKUP=true
DO_ENABLED=true
EOF
chmod 600 "$STAGE5_CONFIG_FILE"

set_config_interval every-build daily
[[ "$(config_interval)" == daily ]]
[[ "$(file_mode "$STAGE5_CONFIG_FILE")" == 600 ]]
grep -Fxq 'DAILY_R2_BACKUP=true' "$STAGE5_CONFIG_FILE"
grep -Fxq 'DO_ENABLED=true' "$STAGE5_CONFIG_FILE"

if set_config_interval every-build daily; then
    echo "expected stale-value protection to reject a second activation" >&2
    exit 1
fi
[[ "$(config_interval)" == daily ]]

set_config_interval daily every-build
[[ "$(config_interval)" == every-build ]]

cat >> "$STAGE5_CONFIG_FILE" <<'EOF'
R2_CONTENT_SYNC_INTERVAL=every-build
EOF
if set_config_interval every-build daily; then
    echo "expected duplicate config entries to fail" >&2
    exit 1
fi

healthy_segment=$(cat <<'EOF'
Skipping R2 live content sync (already verified today: 2026-07-29)
DO Spaces upload completed
Workers Assets shadow upload and verification completed
Workers Assets promotion completed successfully
Purged 0 of 29000 cached HTML pages
Stage 2 job result: status=0 total=900s cadence_ok=true shadow_counter=60
EOF
)
verify_job_segment "$healthy_segment"

if verify_job_segment "${healthy_segment/Skipping R2 live content sync (already verified today: 2026-07-29)/R2 live content synchronization is due (daily)}"; then
    echo "expected an unexpected R2 sync to fail job verification" >&2
    exit 1
fi

if verify_job_segment "${healthy_segment/DO Spaces upload completed/DO Spaces upload failed}"; then
    echo "expected missing DO completion to fail job verification" >&2
    exit 1
fi

# 03:40 UTC is five minutes before an Allium :45 slot; 03:46 is 29 minutes
# before the next :15 slot.
[[ "$(seconds_until_next_allium_slot 1785296400)" == 300 ]]
[[ "$(seconds_until_next_allium_slot 1785296760)" == 1740 ]]

echo "stage5 activation helper tests passed"
