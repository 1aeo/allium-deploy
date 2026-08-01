#!/usr/bin/env bash
# Allium Deploy - Deploy Cloudflare Pages Function
# Generates wrangler.toml and deploys the Pages function
#
# Supports configurable storage fetch order via STORAGE_ORDER:
#   "r2,do,failover"  - Try R2 first, then DO Spaces, then failover
#   "do,r2,failover"  - Try DO Spaces first, then R2, then failover
#   "do,failover"     - DO Spaces only with failover
#   etc.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

# shellcheck source=./scripts/allium-deploy-lib.sh
source "$SCRIPT_DIR/allium-deploy-lib.sh"

assert_pages_checkout_fresh() {
    local head_sha origin_sha dirty_status

    if [[ ! -d "$DEPLOY_DIR/.git" ]]; then
        echo "❌ Refusing Pages deploy: $DEPLOY_DIR is not a git checkout"
        return 1
    fi

    if ! run_with_timeout 30 git -C "$DEPLOY_DIR" fetch origin main >/dev/null 2>&1; then
        echo "❌ Refusing Pages deploy: could not fetch origin/main"
        return 1
    fi

    head_sha=$(git -C "$DEPLOY_DIR" rev-parse HEAD)
    origin_sha=$(git -C "$DEPLOY_DIR" rev-parse origin/main)
    if [[ "$head_sha" != "$origin_sha" ]]; then
        echo "❌ Refusing Pages deploy: checkout HEAD $head_sha does not match origin/main $origin_sha"
        return 1
    fi

    dirty_status=$(git -C "$DEPLOY_DIR" status --porcelain)
    if [[ -n "$dirty_status" ]]; then
        echo "❌ Refusing Pages deploy: working tree changes are present"
        echo "$dirty_status"
        return 1
    fi
}

if [[ "${ALLIUM_CFPAGES_TEST_MODE:-}" == "1" ]]; then
    assert_pages_checkout_fresh
    exit $?
fi

assert_pages_checkout_fresh

if [[ -f "$DEPLOY_DIR/config.env" ]]; then
    source "$DEPLOY_DIR/config.env"
fi

# --- Check/Install Dependencies ---

install_nodejs() {
    echo "📦 Installing Node.js..."
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
    else
        OS_ID="unknown"
    fi
    
    case "$OS_ID" in
        ubuntu|debian)
            echo "   Detected: $OS_ID $OS_VERSION"
            if ! command -v node &>/dev/null; then
                echo "   Installing nodejs via apt..."
                sudo apt-get update
                sudo apt-get install -y nodejs npm
            fi
            ;;
        *)
            echo "❌ Unsupported OS: $OS_ID"
            echo "   Please install Node.js manually: https://nodejs.org/"
            exit 1
            ;;
    esac
    
    if command -v node &>/dev/null; then
        echo "✅ Node.js $(node --version) installed"
    else
        echo "❌ Failed to install Node.js"
        exit 1
    fi
}

install_wrangler() {
    echo "📦 Installing Wrangler..."
    if command -v npm &>/dev/null; then
        sudo npm install -g wrangler
        echo "✅ Wrangler installed"
    else
        echo "❌ npm not found, cannot install wrangler"
        exit 1
    fi
}

# Check Node.js
if ! command -v node &>/dev/null; then
    echo "⚠️  Node.js not found"
    read -p "   Install Node.js? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_nodejs
    else
        echo "❌ Node.js required for wrangler. Aborting."
        exit 1
    fi
else
    echo "✅ Node.js $(node --version) found"
fi

# Check npm
if ! command -v npm &>/dev/null; then
    echo "⚠️  npm not found"
    read -p "   Install npm? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt-get update && sudo apt-get install -y npm
    else
        echo "❌ npm required for wrangler. Aborting."
        exit 1
    fi
else
    echo "✅ npm $(npm --version) found"
fi

# Check wrangler
if ! command -v wrangler &>/dev/null && ! npx wrangler --version &>/dev/null 2>&1; then
    echo "⚠️  Wrangler not found"
    read -p "   Install Wrangler globally? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_wrangler
    else
        echo "   Will use npx wrangler (slower but works)"
    fi
else
    echo "✅ Wrangler found"
fi

# --- Load Cloudflare Credentials ---

if [[ -f "$HOME/.config/cloudflare/api_token" ]]; then
    source "$HOME/.config/cloudflare/api_token"
fi

if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
    echo ""
    echo "❌ Error: CLOUDFLARE_API_TOKEN not set"
    echo "   Create ~/.config/cloudflare/api_token with:"
    echo "   CLOUDFLARE_API_TOKEN=your_token_here"
    exit 1
fi

export CLOUDFLARE_API_TOKEN
export CLOUDFLARE_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:-}"

# --- Generate wrangler.toml from template ---

TEMPLATE_FILE="$DEPLOY_DIR/wrangler.toml.template"
OUTPUT_FILE="$DEPLOY_DIR/wrangler.toml"

if [[ ! -f "$TEMPLATE_FILE" ]]; then
    echo "❌ Template not found: $TEMPLATE_FILE"
    exit 1
fi

echo ""
echo "📝 Generating wrangler.toml from template..."

# Set defaults
PAGES_PROJECT_NAME="${PAGES_PROJECT_NAME:-my-metrics}"
STORAGE_ORDER="${STORAGE_ORDER:-r2,do,failover}"
R2_ENABLED="${R2_ENABLED:-true}"
R2_BUCKET="${R2_BUCKET:-}"
R2_BINDING_NAME="${R2_BINDING_NAME:-METRICS_CONTENT}"
DO_ENABLED="${DO_ENABLED:-false}"
DO_SPACES_URL="${DO_SPACES_URL:-}"
WRANGLER_COMPATIBILITY_DATE="${WRANGLER_COMPATIBILITY_DATE:-2025-12-01}"
PAGES_BUILD_OUTPUT_DIR="${PAGES_BUILD_OUTPUT_DIR:-public}"
FAILOVER_ORIGIN_URL="${FAILOVER_ORIGIN_URL:-}"
CACHE_TTL_HTML="${CACHE_TTL_HTML:-1800}"
CACHE_TTL_STATIC="${CACHE_TTL_STATIC:-86400}"
CACHE_KEY_ORIGIN="${CACHE_KEY_ORIGIN:-${SITE_URL:-https://metrics.example.com}}"
PURGE_SECRET="${PURGE_SECRET:-}"
SOURCE_EVENTS_ENABLED="${SOURCE_EVENTS_ENABLED:-false}"
SOURCE_EVENTS_DATASET="${SOURCE_EVENTS_DATASET:-allium_source_events}"

if [[ ! "$CACHE_KEY_ORIGIN" =~ ^https://[a-z0-9][a-z0-9.-]*[a-z0-9]/?$ ]]; then
    echo "❌ CACHE_KEY_ORIGIN must be an HTTPS origin without a path, query, or fragment"
    exit 1
fi
CACHE_KEY_ORIGIN="${CACHE_KEY_ORIGIN%/}"

# Build conditional sections
R2_BUCKET_SECTION=""
if [[ "$R2_ENABLED" == "true" ]]; then
    R2_BUCKET_SECTION="[[r2_buckets]]
binding = \"${R2_BINDING_NAME}\"
bucket_name = \"${R2_BUCKET}\""
else
    R2_BUCKET_SECTION="# R2 disabled (R2_ENABLED=false)"
fi

DO_SPACES_URL_VAR=""
if [[ "$DO_ENABLED" == "true" ]] && [[ -n "$DO_SPACES_URL" ]]; then
    DO_SPACES_URL_VAR="DO_SPACES_URL = \"${DO_SPACES_URL}\""
else
    DO_SPACES_URL_VAR="# DO_SPACES_URL not configured (DO_ENABLED=false)"
fi

SOURCE_EVENTS_SECTION=""
if [[ "$SOURCE_EVENTS_ENABLED" == "true" ]]; then
    SOURCE_EVENTS_SECTION="[[analytics_engine_datasets]]
binding = \"SOURCE_EVENTS\"
dataset = \"${SOURCE_EVENTS_DATASET}\""
else
    SOURCE_EVENTS_SECTION="# Sparse source telemetry disabled (SOURCE_EVENTS_ENABLED=false)"
fi

# Generate wrangler.toml
sed -e "s|{{PAGES_PROJECT_NAME}}|${PAGES_PROJECT_NAME}|g" \
    -e "s|{{WRANGLER_COMPATIBILITY_DATE}}|${WRANGLER_COMPATIBILITY_DATE}|g" \
    -e "s|{{PAGES_BUILD_OUTPUT_DIR}}|${PAGES_BUILD_OUTPUT_DIR}|g" \
    -e "s|{{STORAGE_ORDER}}|${STORAGE_ORDER}|g" \
    -e "s|{{FAILOVER_ORIGIN_URL}}|${FAILOVER_ORIGIN_URL}|g" \
    -e "s|{{CACHE_TTL_HTML}}|${CACHE_TTL_HTML}|g" \
    -e "s|{{CACHE_TTL_STATIC}}|${CACHE_TTL_STATIC}|g" \
    -e "s|{{CACHE_KEY_ORIGIN}}|${CACHE_KEY_ORIGIN}|g" \
    -e "s|{{PURGE_SECRET}}|${PURGE_SECRET}|g" \
    "$TEMPLATE_FILE" > "$OUTPUT_FILE.tmp"

# Replace multi-line sections (sed can't handle these well)
awk -v r2_section="$R2_BUCKET_SECTION" -v do_section="$DO_SPACES_URL_VAR" -v source_events_section="$SOURCE_EVENTS_SECTION" '
    /\{\{R2_BUCKET_SECTION\}\}/ { print r2_section; next }
    /\{\{DO_SPACES_URL_VAR\}\}/ { print do_section; next }
    /\{\{SOURCE_EVENTS_SECTION\}\}/ { print source_events_section; next }
    { print }
' "$OUTPUT_FILE.tmp" > "$OUTPUT_FILE"
rm -f "$OUTPUT_FILE.tmp"

# Parse storage order for display
HAS_R2=false
HAS_DO=false
HAS_FAILOVER=false
IFS=',' read -ra ORDER_ARRAY <<< "$STORAGE_ORDER"
for backend in "${ORDER_ARRAY[@]}"; do
    backend=$(echo "$backend" | tr -d ' ')
    case "$backend" in
        r2) HAS_R2=true ;;
        do) HAS_DO=true ;;
        failover) HAS_FAILOVER=true ;;
    esac
done

# Display configuration
echo ""
echo "   Storage Configuration:"
echo "   ─────────────────────"
echo "   Fetch Order: $STORAGE_ORDER"
echo ""
echo "   Backends:"
if [[ "$HAS_R2" == "true" ]]; then
    if [[ "$R2_ENABLED" == "true" ]]; then
        echo "   • R2:       ✅ Enabled ($R2_BUCKET)"
    else
        echo "   • R2:       ⚠️  In order but R2_ENABLED=false"
    fi
fi
if [[ "$HAS_DO" == "true" ]]; then
    if [[ "$DO_ENABLED" == "true" ]]; then
        echo "   • DO:       ✅ Enabled ($DO_SPACES_URL)"
    else
        echo "   • DO:       ⚠️  In order but DO_ENABLED=false"
    fi
fi
if [[ "$HAS_FAILOVER" == "true" ]]; then
    if [[ -n "$FAILOVER_ORIGIN_URL" ]]; then
        echo "   • Failover: ✅ Enabled ($FAILOVER_ORIGIN_URL)"
    else
        echo "   • Failover: ⚠️  In order but FAILOVER_ORIGIN_URL not set"
    fi
fi
echo ""
echo "   Cloudflare CDN Cache:"
echo "   • HTML:   ${CACHE_TTL_HTML}s"
echo "   • Static: ${CACHE_TTL_STATIC}s"
echo ""
echo "✅ Generated: $OUTPUT_FILE"

# --- Deploy ---

echo ""
echo "🚀 Deploying Cloudflare Pages function..."
cd "$DEPLOY_DIR"

assert_pages_checkout_fresh

if command -v wrangler &>/dev/null; then
    wrangler pages deploy --branch=production --commit-dirty=true
else
    npx wrangler pages deploy --branch=production --commit-dirty=true
fi

echo ""
echo "✅ Done! Pages function deployed."
echo "   Site: ${SITE_URL:-https://metrics.example.com}"
