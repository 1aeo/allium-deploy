#!/usr/bin/env bash
# Allium Deploy - One-time Installation
# Installs allium, rclone, configures R2, and sets up cron

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

echo "🌐 Allium Deploy - Installation"
echo "================================"
echo ""

# Check for config.env
if [[ ! -f "$DEPLOY_DIR/config.env" ]]; then
    echo "❌ Error: config.env not found"
    echo "   Copy config.env.example to config.env and configure it first:"
    echo ""
    echo "   cp $DEPLOY_DIR/config.env.example $DEPLOY_DIR/config.env"
    echo "   nano $DEPLOY_DIR/config.env"
    exit 1
fi

source "$DEPLOY_DIR/config.env"

# Validate required config
if [[ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]] || [[ "$CLOUDFLARE_ACCOUNT_ID" == "your_account_id_here" ]]; then
    echo "❌ Error: CLOUDFLARE_ACCOUNT_ID not configured in config.env"
    exit 1
fi

if [[ -z "${R2_ACCESS_KEY_ID:-}" ]] || [[ "$R2_ACCESS_KEY_ID" == "your_access_key_here" ]]; then
    echo "❌ Error: R2_ACCESS_KEY_ID not configured in config.env"
    exit 1
fi

echo "✅ Configuration validated"
echo ""

# Check Python version
echo "🔍 Checking Python version..."
if ! python3 -c "import sys; assert sys.version_info >= (3, 8)" 2>/dev/null; then
    echo "❌ Error: Python 3.8+ required"
    exit 1
fi
echo "✅ Python $(python3 --version | cut -d' ' -f2) found"

# Install system dependencies
echo ""
echo "📦 Checking system dependencies..."
if ! python3 -c "import jinja2" 2>/dev/null; then
    echo "   Installing python3-jinja2..."
    sudo apt-get update && sudo apt-get install -y python3-jinja2
fi
echo "✅ System dependencies ready"

# --- RCLONE SETUP ---
echo ""
echo "📦 Setting up rclone..."

RCLONE_PATH="${RCLONE_PATH:-$HOME/bin/rclone}"

if [[ ! -f "$RCLONE_PATH" ]]; then
    echo "   Downloading rclone..."
    mkdir -p "$(dirname "$RCLONE_PATH")"
    cd /tmp
    wget -q https://downloads.rclone.org/rclone-current-linux-amd64.zip
    unzip -oq rclone-current-linux-amd64.zip
    mv rclone-*/rclone "$RCLONE_PATH"
    rm -rf rclone-current-linux-amd64.zip rclone-*/
    chmod +x "$RCLONE_PATH"
    echo "✅ rclone installed to $RCLONE_PATH"
else
    echo "✅ rclone already installed at $RCLONE_PATH"
fi

echo "   Configuring rclone for R2..."
mkdir -p ~/.config/rclone

cat > ~/.config/rclone/rclone.conf << EOF
[r2-metrics]
type = s3
provider = Cloudflare
access_key_id = ${R2_ACCESS_KEY_ID}
secret_access_key = ${R2_SECRET_ACCESS_KEY}
endpoint = https://${CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com
acl = private
EOF

chmod 600 ~/.config/rclone/rclone.conf

echo "   Testing R2 connection..."
BUCKET="${R2_BUCKET:?R2_BUCKET must be set in config.env}"
if $RCLONE_PATH lsf "r2-metrics:$BUCKET" --max-depth 1 >/dev/null 2>&1; then
    echo "✅ R2 connection successful (bucket: $BUCKET)"
else
    echo "⚠️  Could not connect to R2 bucket '$BUCKET'"
    echo "   Make sure the bucket exists and credentials are correct"
fi

# --- ALLIUM SETUP ---
ALLIUM_DIR="${ALLIUM_DIR:-$HOME/allium}"
if [[ ! -d "$ALLIUM_DIR" ]]; then
    echo ""
    echo "📥 Cloning allium..."
    git clone https://github.com/1aeo/allium.git "$ALLIUM_DIR"
    echo "✅ Allium cloned to $ALLIUM_DIR"
else
    echo ""
    echo "✅ Allium already present at $ALLIUM_DIR"
fi

OUTPUT_DIR="${OUTPUT_DIR:-$HOME/metrics-output}"
mkdir -p "$OUTPUT_DIR"
echo "✅ Output directory: $OUTPUT_DIR"

mkdir -p "$DEPLOY_DIR/logs"
chmod +x "$SCRIPT_DIR"/allium-deploy-*.sh

# --- CRON SETUP (drop-in file) ---
echo ""
echo "⏰ Setting up cron job..."
CRON_SCHEDULE="${CRON_SCHEDULE:-*/30 * * * *}"

# Generate drop-in file
cat > "$DEPLOY_DIR/allium.cron" << EOF
SHELL=/bin/bash
$CRON_SCHEDULE $USER $SCRIPT_DIR/allium-deploy-update.sh >> $DEPLOY_DIR/logs/update.log 2>&1
EOF

if [[ -f /etc/cron.d/allium ]] && grep -q "allium-deploy-update" /etc/cron.d/allium; then
    echo "✅ Cron installed: /etc/cron.d/allium"
else
    echo "⚠️  Install cron: sudo cp $DEPLOY_DIR/allium.cron /etc/cron.d/allium && sudo chmod 644 /etc/cron.d/allium"
fi

# Clean up old user crontab entries
crontab -l 2>/dev/null | grep -v "allium-deploy-update" | crontab - 2>/dev/null || true

# --- DONE ---
echo ""
echo "🎉 Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Run first update:  $SCRIPT_DIR/allium-deploy-update.sh"
echo "  2. Monitor logs:      tail -f $DEPLOY_DIR/logs/update.log"
echo "  3. View site:         ${SITE_URL:-https://your-site.com}"
echo ""
echo "Commands:"
echo "  Manual update:    $SCRIPT_DIR/allium-deploy-update.sh"
echo "  Manual upload:    $SCRIPT_DIR/allium-deploy-upload.sh"
echo "  List backups:     $SCRIPT_DIR/allium-deploy-upload.sh --list-backups"
echo "  View cron:        cat /etc/cron.d/allium"

