# Allium Metrics - Deployment Template

Automated Tor relay metrics generation and deployment to Cloudflare Pages with multi-storage support.

**Live example:** https://metrics.1aeo.com  
**Allium source:** https://github.com/1aeo/allium

---

## Storage Options

| Provider | Best For |
|----------|----------|
| **Cloudflare R2** | Native integration, zero egress |
| **DigitalOcean Spaces** | Simple flat pricing |
| **Both** | Redundancy with failover |

---

## Quick Start

```bash
# 1. Clone this deployment repo
git clone https://github.com/1aeo/allium-deploy.git ~/allium-deploy
cd ~/allium-deploy

# 2. Configure
cp config.env.example config.env
nano config.env  # Edit values (see below)

# 3. Install
./scripts/allium-deploy-install.sh

# Done! Metrics update every 30 minutes
```

---

## Configuration (config.env)

### Storage Selection

```bash
# Storage fetch order: comma-separated list of backends to try
# Options: r2, do, failover
# Examples:
#   "r2,do,failover"  - Try R2 first, then DO Spaces, then failover
#   "do,r2,failover"  - Try DO Spaces first, then R2, then failover
#   "r2,failover"     - R2 only with failover
#   "do,failover"     - DO Spaces only with failover
STORAGE_ORDER=r2,do,failover
```

### Cloudflare R2 (if using R2)

```bash
# Cloudflare credentials
CLOUDFLARE_ACCOUNT_ID=your_account_id
R2_ENABLED=true
R2_ACCESS_KEY_ID=your_access_key
R2_SECRET_ACCESS_KEY=your_secret_key
R2_BUCKET=my-metrics-content
```

**Get R2 credentials:**
1. Account ID: Found in dashboard URL or R2 overview
2. R2 API Token: R2 → Manage R2 API Tokens → Create token with "Object Read & Write"

### DigitalOcean Spaces (if using DO)

```bash
DO_ENABLED=true
DO_SPACES_KEY=your_spaces_key
DO_SPACES_SECRET=your_spaces_secret
DO_SPACES_REGION=nyc3
DO_SPACES_BUCKET=my-metrics-content
DO_SPACES_URL=https://my-metrics-content.nyc3.digitaloceanspaces.com
```

**Get DO Spaces credentials:** See [DigitalOcean Spaces Setup](#digitalocean-spaces-setup) below.

### Pages Configuration

```bash
PAGES_PROJECT_NAME=my-metrics
SITE_URL=https://metrics.example.com
```

---

## DigitalOcean Spaces Setup

### 1. Create a Space

1. Log in to [DigitalOcean](https://cloud.digitalocean.com/)
2. Go to **Spaces** → **Create a Space**
3. Configure:
   - **Region:** Choose closest to your users (nyc3, sfo3, ams3, sgp1, fra1)
   - **Name:** `your-metrics-content` (must be globally unique)
   - **File Listing:** Enable "Restrict File Listing" = OFF (public read)
4. Click **Create a Space**

### 2. Enable CDN (Optional)

DO Spaces CDN is optional. It's faster but has a limitation:

| Mode | Setting | Speed | Freshness |
|------|---------|-------|-----------|
| **Origin** | `DO_SPACES_CDN=false` | Slower | Always fresh |
| **CDN** | `DO_SPACES_CDN=true` | Faster | Up to ~1hr stale |

**Important:** DO Spaces CDN does NOT support cache invalidation/purging. If using CDN, content may be up to 1 hour stale.

To enable CDN:
1. Go to your Space → **Settings** → **CDN** → **Enable CDN**
2. Set in `config.env`:
   ```bash
   DO_SPACES_CDN=true
   ```

### 3. Create Spaces Access Keys

1. Go to **API** → **Spaces Keys**
2. Click **Generate New Key**
3. Name it (e.g., "allium-deploy")
4. Copy both the **Key** and **Secret** (secret shown only once!)
5. Add to `config.env`:
   ```bash
   DO_SPACES_KEY=XXXXXXXXXXXXXXXXXXXX
   DO_SPACES_SECRET=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   ```

### 4. Make Bucket Public

For the Pages function to fetch content, the bucket must be publicly readable:

1. Go to your Space → **Settings**
2. Under **File Listing**, ensure it's set to allow public access
3. Alternatively, use a CDN endpoint which handles this automatically

### 5. Configure rclone (Automatic)

The upload script auto-configures rclone on first run. Manual setup:

```bash
rclone config create spaces s3 \
    provider=DigitalOcean \
    access_key_id="YOUR_KEY" \
    secret_access_key="YOUR_SECRET" \
    endpoint="nyc3.digitaloceanspaces.com" \
    acl=public-read
```

### 6. View Metrics

DigitalOcean does not provide built-in Spaces metrics via the dashboard or API. To monitor usage:

- **Bandwidth:** Check your monthly bill/usage in **Billing** → **Usage**
- **Storage size:** Run `rclone size spaces:your-bucket`
- **Object count:** Run `rclone ls spaces:your-bucket | wc -l`
- **Third-party tools:** Consider [MetricFire](https://www.metricfire.com/integrations/digital-ocean/) or custom scripts using the S3-compatible API

---

## Architecture

```
┌─────────────────────────┐
│  Allium Generator       │
│  (Python + Jinja2)      │
│  ~4 min / ~21k files    │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│  Local Output           │
│  ~/metrics-output       │
│  ~3GB                   │
└───────────┬─────────────┘
            │ rclone sync (128 parallel)
            ▼
┌─────────────────────────┐  ┌─────────────────────────┐
│  Cloudflare R2          │  │  DigitalOcean Spaces    │
│  (native binding)       │  │  (HTTP fetch via CDN)   │
└───────────┬─────────────┘  └───────────┬─────────────┘
            │                            │
            └──────────┬─────────────────┘
                       │ STORAGE_ORDER determines try order
                       ▼
         ┌─────────────────────────┐
         │  Cloudflare Pages       │
         │  (tries sources in      │
         │   configured order)     │
         └─────────────────────────┘
```

---

## Commands

```bash
# === Upload Commands ===

# Upload to R2
~/allium-deploy/scripts/allium-deploy-upload-r2.sh

# Upload to DO Spaces
~/allium-deploy/scripts/allium-deploy-upload-do.sh

# List backups (R2)
~/allium-deploy/scripts/allium-deploy-upload-r2.sh --list-backups

# List backups (DO Spaces)
~/allium-deploy/scripts/allium-deploy-upload-do.sh --list-backups

# Force backup even if done today
~/allium-deploy/scripts/allium-deploy-upload-r2.sh --force-backup

# === Other Commands ===

# Manual update (runs allium + upload)
~/allium-deploy/scripts/allium-deploy-update.sh

# View logs
tail -f ~/allium-deploy/logs/update.log

# Deploy Pages function
~/allium-deploy/scripts/allium-deploy-cfpages.sh

# Check cron
crontab -l
```

---

## Directory Structure

```
allium/                 # Allium source (git clone)
allium-deploy/          # This deployment repo
├── config.env          # Your settings (gitignored)
├── config.env.example  # Template
├── wrangler.toml.template  # Wrangler config template
├── wrangler.toml       # Generated at deploy time (gitignored)
├── functions/
│   └── [[path]].js     # Pages function (multi-storage + failover)
├── scripts/
│   ├── allium-deploy-install.sh      # One-time setup
│   ├── allium-deploy-update.sh       # Main cron script
│   ├── allium-deploy-upload-r2.sh    # R2 upload with backups
│   ├── allium-deploy-upload-do.sh    # DO Spaces upload with backups
│   ├── allium-deploy-upload-common.sh # Shared upload functions
│   ├── allium-deploy-prune.sh        # Remove old backups
│   └── allium-deploy-cfpages.sh      # Deploy Pages function
├── logs/
│   ├── update.log
│   ├── last-local-backup-date
│   ├── last-r2-backup-date
│   └── last-do-backup-date
└── public/             # Empty dir for Pages build output
```

---

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Allium generation | ~4 min | 9,800 relays → 21,000 pages |
| R2 upload (full) | ~3 min | 128 parallel transfers |
| DO Spaces upload (full) | ~3 min | 128 parallel transfers |
| Upload (incremental) | <1 min | Only changed files |
| Local backup | ~1.5 min | Download from storage |
| Remote backup | ~3.5 min | Server-side copy |

---

## Backup & Rollback

**Automatic backups (once daily):**
- Local: `~/metrics-backups/backup-YYYY-MM-DD_HHMMSS/`
- R2: `r2:bucket/_backups/YYYY-MM-DD_HHMMSS/`
- DO Spaces: `spaces:bucket/_backups/YYYY-MM-DD_HHMMSS/`

**Rollback from local backup:**
```bash
./scripts/allium-deploy-upload-r2.sh ~/metrics-backups/backup-2025-12-01_063000
# or
./scripts/allium-deploy-upload-do.sh ~/metrics-backups/backup-2025-12-01_063000
```

**Rollback from remote backup:**
```bash
# From R2
~/bin/rclone sync r2:bucket/_backups/2025-12-01_063000 ~/metrics-output
./scripts/allium-deploy-upload-r2.sh

# From DO Spaces
~/bin/rclone sync spaces:bucket/_backups/2025-12-01_063000 ~/metrics-output
./scripts/allium-deploy-upload-do.sh
```

---

## Multi-Storage Modes

### R2 Only (`STORAGE_ORDER=r2,failover`)

- Native R2 binding (fastest)
- Best for: Maximum performance

### DO Spaces Only (`STORAGE_ORDER=do,failover`)

- HTTP fetch from Spaces CDN
- Best for: Simplicity

### Both (`STORAGE_ORDER=do,r2,failover` or `r2,do,failover`)

- Tries storage backends in order
- Best for: Redundancy

**Response headers show which source served the request:**
- `X-Served-From: cloudflare-r2`
- `X-Served-From: digitalocean-spaces`
- `X-Served-From: failover-origin`

---

## Origin Failover

Independent of storage selection, you can configure a failover origin:

```bash
FAILOVER_ENABLED=true
FAILOVER_ORIGIN_URL=https://backup.example.com/metrics
```

The Pages function tries sources in order defined by `STORAGE_ORDER`:
1. First storage backend (R2 or DO Spaces)
2. Second storage backend (if configured)
3. Failover origin (if enabled)
4. Return 404

---

## CDN Caching

### Cloudflare CDN (via Pages)

- **HTML:** 30 min cache, purged after each upload
- **Static assets:** 24 hour cache
- **Purge:** Automatic via `/_purge` endpoint after uploads

### DigitalOcean Spaces

| Mode | `DO_SPACES_CDN` | Behavior |
|------|-----------------|----------|
| **Origin** | `false` | Always fresh (default) |
| **CDN** | `true` | Faster, up to ~1hr stale (no purge available) |

---

## Troubleshooting

**502 errors during upload:**
- Normal with 128 parallel connections
- Retries handle it automatically

**DO Spaces "Access Denied":**
- Check bucket is public or CDN is enabled
- Verify DO_SPACES_URL matches your bucket

**R2 connection failed:**
- Verify credentials in config.env
- Test: `~/bin/rclone ls r2:bucket --max-depth 1`

**Pages function not using correct storage:**
- Check `STORAGE_ORDER` in config.env
- Redeploy: `./scripts/allium-deploy-cfpages.sh`
- Check `X-Served-From` response header

**DO Spaces serving stale content:**
- If using CDN (`DO_SPACES_CDN=true`), switch to origin (`DO_SPACES_CDN=false`)
- DO Spaces CDN has no cache purge - origin mode always serves fresh content

---

## Requirements

- Debian/Ubuntu Linux
- Python 3.8+
- python3-jinja2
- Cloudflare account (for Pages, optionally R2)
- DigitalOcean account (optional, for Spaces)
- ~4GB RAM (for allium processing)
- ~10GB disk space

---

## Credits

- **Allium:** https://github.com/1aeo/allium
- **Tor Project:** https://www.torproject.org
- **Onionoo API:** https://onionoo.torproject.org

---

## License

Apache 2.0
