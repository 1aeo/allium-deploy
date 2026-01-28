#!/usr/bin/env bash
# Check if allium cron is installed and show status

CRON_FILE="/etc/cron.d/allium"

if [[ -f "$CRON_FILE" ]] && grep -q "allium-deploy-update" "$CRON_FILE"; then
    echo "✅ Cron installed: $CRON_FILE"
    grep -v "^#\|^$\|^SHELL\|^PATH" "$CRON_FILE"
    exit 0
else
    echo "❌ Cron NOT installed"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"
    [[ -f "$DEPLOY_DIR/allium.cron" ]] && echo "   Install: sudo cp $DEPLOY_DIR/allium.cron $CRON_FILE && sudo chmod 644 $CRON_FILE"
    exit 1
fi
