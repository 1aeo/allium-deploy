#!/usr/bin/env bash
# The Workers checks of run-cfassets-remediation-audit.sh: production must
# serve the main Worker's last successful promotion (failed and withheld
# promotion rows skipped), and with CHARTS_LAYOUT=charts the charts Worker's.
# A copy of the audit runs with a fake config.env and stubs for Wrangler and
# the other tools; only the Workers lines are checked.

set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "not ok - $1" >&2
    exit 1
}

pass() {
    echo "ok - $1"
}

DEPLOY_DIR="$TMP_DIR/deploy"
MOCK_BIN="$TMP_DIR/bin"
mkdir -p "$DEPLOY_DIR/scripts" "$DEPLOY_DIR/logs" "$MOCK_BIN" "$TMP_DIR/output"
cp "$REPO_DIR/scripts/run-cfassets-remediation-audit.sh" "$REPO_DIR/scripts/allium-deploy-lib.sh" "$DEPLOY_DIR/scripts/"
printf '<html></html>\n' > "$TMP_DIR/output/index.html"
printf '{}\n' > "$TMP_DIR/output/search-index.json"

# Wrangler: deployments status answers with the version in
# status-<config basename>.
cat > "$MOCK_BIN/corepack" <<EOF
#!/usr/bin/env bash
config=""
previous=""
for arg in "\$@"; do
    [[ "\$previous" != --config ]] || config="\$arg"
    previous="\$arg"
done
version=\$(cat "$TMP_DIR/status-\$(basename "\$config")" 2>/dev/null) || exit 1
printf '{"versions":[{"version_id":"%s","percentage":100}]}\n' "\$version"
EOF
# Everything else the audit runs answers emptily.
for tool in node curl rclone; do
    printf '#!/usr/bin/env bash\nprintf "{}"\n' > "$MOCK_BIN/$tool"
done
chmod 0755 "$MOCK_BIN"/*

# promotions <summary file> <version<TAB>exit status>...
promotions() {
    local file="$1"
    shift
    printf 'timestamp_utc\tversion_id\texit_status\n' > "$file"
    printf '2026-10-14T00:00:00Z\t%s\n' "$@" >> "$file"
}

# audit [config lines...]: the audit's output.
audit() {
    printf '%s\n' "OUTPUT_DIR=\"$TMP_DIR/output\"" DO_SPACES_BUCKET=bucket "$@" > "$DEPLOY_DIR/config.env"
    env -i HOME="$TMP_DIR" PATH="$MOCK_BIN:$PATH" CF_REMEDIATION_AUDIT_CALLER_HOLDS_LOCK=true \
        RCLONE_PATH="$MOCK_BIN/rclone" bash "$DEPLOY_DIR/scripts/run-cfassets-remediation-audit.sh" --smoke 2>&1 || true
}

PROMOTION_FILE="$DEPLOY_DIR/logs/cfassets-promotion-summary.tsv"
promotions "$PROMOTION_FILE" $'aaaa\t0' $'bbbb\t1' $'cccc\t7'
printf 'aaaa\n' > "$TMP_DIR/status-wrangler.assets.toml"
output=$(audit)
[[ "$output" == *'ok - latest verified version serves 100% of production'* && "$output" != *'charts Worker'* ]] \
    || fail "the last successful promotion was not the one compared, or beside checked the charts Worker: $output"
printf 'cccc\n' > "$TMP_DIR/status-wrangler.assets.toml"
[[ "$(audit)" == *'not ok - Cloudflare production version does not match the latest promotion'* ]] \
    || fail "a withheld version passed as production's"
pass "the main Worker must serve its last successful promotion; failed and withheld rows are skipped"

PROMOTION_FILE="$DEPLOY_DIR/logs/cfcharts-promotion-summary.tsv"
promotions "$PROMOTION_FILE" $'dddd\t0' $'eeee\t9'
printf 'aaaa\n' > "$TMP_DIR/status-wrangler.assets.toml"
printf 'dddd\n' > "$TMP_DIR/status-wrangler.charts.toml"
output=$(audit CHARTS_LAYOUT=charts)
[[ "$output" == *'ok - latest verified version serves 100% of production'* \
    && "$output" == *"ok - the charts Worker's latest promoted version serves 100% of /charts/"* ]] \
    || fail "the charts Worker was not checked against its last promotion: $output"
printf 'eeee\n' > "$TMP_DIR/status-wrangler.charts.toml"
[[ "$(audit CHARTS_LAYOUT=charts)" == *"not ok - the charts Worker's production version does not match its latest promotion"* ]] \
    || fail "a charts Worker serving another version passed"
rm "$PROMOTION_FILE"
[[ "$(audit CHARTS_LAYOUT=charts)" == *"not ok - the charts Worker's production version does not match"* ]] \
    || fail "a charts Worker without any promotion passed"
pass "with CHARTS_LAYOUT=charts the charts Worker must serve its last successful promotion"
