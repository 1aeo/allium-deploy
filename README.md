# Allium Metrics — Deployment

Automated Tor relay metrics generation and deployment for [1aeo/allium](https://github.com/1aeo/allium).

**Live site:** https://metrics.1aeo.com  
**Workers Static Assets guide:** [docs/WORKERS_STATIC_ASSETS.md](docs/WORKERS_STATIC_ASSETS.md)

---

## Architecture & Current Production Path

Production traffic (`metrics.1aeo.com/*`) is served by **Cloudflare Workers Static Assets** (`workers/search.js` with the `ALLIUM_ASSETS` binding). When `CHARTS_LAYOUT=charts` is enabled, a second assets-only charts Worker serves `<host>/charts/*` while the main Worker serves pages and redirects legacy chart URLs.

Each scheduled build ([`scripts/allium-deploy-update.sh`](scripts/allium-deploy-update.sh)) runs guarded pulls, syncs the pinned Workers toolchain, generates the site with Allium, validates search and discovery artifacts, starts all enabled publishers in parallel, and acts on them in restore-priority order:

1. **Cloudflare Workers Static Assets** (`allium-deploy-cfassets.sh`, plus `allium-deploy-cfcharts.sh` when `CHARTS_LAYOUT=charts`): uploads immutable version(s), verifies preview URLs, and promotes to `100%` without waiting on storage mirrors.
2. **DigitalOcean Spaces** (`allium-deploy-upload-do.sh`): every-build hot mirror.
3. **Cloudflare R2** (`allium-deploy-upload-r2.sh`): daily live-content replication (`R2_CONTENT_SYNC_INTERVAL=daily`, verified by object count, total bytes, and representative SHA-256 hashes).
4. **Cloudflare Pages** (`functions/[[path]].js`, `functions/search.js`, `functions/_shared.js`): maintained behind `PAGES_PURGE_URL` as a route-removal rollback target reading backends in `STORAGE_ORDER`.

```
┌──────────────────────────────────┐
│  Allium Generator + Validation   │  ~/allium → ~/metrics-output
└─────────────────┬────────────────┘
                  │ parallel launch; restore-priority gating
     ┌────────────┼──────────────────────┐
     ▼            ▼                      ▼
┌──────────┐ ┌──────────────┐ ┌──────────────────┐
│ Workers  │ │ DigitalOcean │ │ Cloudflare R2    │
│ Assets   │ │ Spaces       │ │ (daily live sync)│
│ (+charts │ │ (every-build)│ │                  │
│ optional)│ └──────┬───────┘ └────────┬─────────┘
└────┬─────┘        └────────┬─────────┘
     │                       ▼ STORAGE_ORDER
     │              ┌──────────────────┐
     │              │ Cloudflare Pages │ (route-removal rollback;
     ▼              │ (warm fallback)  │  purged via PAGES_PURGE_URL)
metrics.1aeo.com/*  └──────────────────┘
```

See [docs/WORKERS_STATIC_ASSETS.md](docs/WORKERS_STATIC_ASSETS.md) for promotion safety, `CHARTS_LAYOUT=charts`, verification gates, bounded TSV logs, and Pages rollback steps.

---

## Quick Start

```bash
# 1. Clone this deployment repo
git clone https://github.com/1aeo/allium-deploy.git ~/allium-deploy
cd ~/allium-deploy

# 2. Configure settings and Cloudflare API tokens
cp config.env.example config.env
nano config.env
# Save Cloudflare API token(s) in ~/.config/cloudflare/workers_api_token and/or api_token (chmod 600)

# 3. Install dependencies (python3-jinja2, pinned Workers toolchain, rclone, allium, allium.cron)
./scripts/allium-deploy-install.sh

# 4. Install cron drop-in (defaults to 15,45 * * * * in config.env.example)
sudo cp ~/allium-deploy/allium.cron /etc/cron.d/allium && sudo chmod 644 /etc/cron.d/allium
```

---

## Commands

```bash
# === Scheduled Pipeline ===
./scripts/allium-deploy-update.sh                  # Full build, verify, publish, purge & prune
tail -f ~/allium-deploy/logs/update.log            # Follow deployment output

# === Storage Uploads & Backups ===
./scripts/allium-deploy-upload-r2.sh               # Sync/verify R2 (+ daily backups)
./scripts/allium-deploy-upload-r2.sh --force-content-sync
./scripts/allium-deploy-upload-r2.sh --force-backup
./scripts/allium-deploy-upload-r2.sh --skip-local-backup
./scripts/allium-deploy-upload-r2.sh --list-backups

./scripts/allium-deploy-upload-do.sh               # Sync DO Spaces (+ daily backups)
./scripts/allium-deploy-upload-do.sh --force-backup
./scripts/allium-deploy-upload-do.sh --skip-local-backup
./scripts/allium-deploy-upload-do.sh --remote-backup-only --force-backup
./scripts/allium-deploy-upload-do.sh --list-backups

# === Cloudflare Workers & Pages ===
./scripts/allium-deploy-cfassets.sh --generate-only # Render wrangler.assets.toml + overlays & check file count
./scripts/allium-deploy-cfassets.sh --upload-only   # Upload & preview-verify candidate (never promotes)
./scripts/allium-deploy-cfassets.sh --promote       # Promote verified version@100% (if allowed)
./scripts/allium-deploy-cfcharts.sh --check-config  # Validate CHARTS_LAYOUT=charts configuration
./scripts/allium-deploy-cfpages.sh                  # Deploy Pages rollback functions

# === Diagnostics & Tests ===
./scripts/allium-cron-check.sh                      # Verify /etc/cron.d/allium
pnpm test                                           # Run Node tests + all shell behavior suites
```

---

## Configuration (`config.env`)

[`config.env.example`](config.env.example) is the canonical reference for all variables, comments, and safe defaults. Configuration groups:

| Group | Key Variables | Purpose |
|---|---|---|
| **Storage selection** | `STORAGE_ORDER` | Comma-separated backend order (`r2`, `do`, `failover`) for Pages fallback and `/search` AROI checks |
| **Workers & promotion** | `CLOUDFLARE_ACCOUNT_ID`, `CF_ASSETS_ENABLED`, `CF_ASSETS_REQUIRED`, `CF_ASSETS_ALLOW_PROMOTION`, `CF_ASSETS_WORKER_NAME`, `CF_ASSETS_PREVIEW_ALIAS`, `CF_ASSETS_COMPATIBILITY_DATE`, `CF_ASSETS_VERIFY_*`, `CF_ASSETS_UPLOAD_*`, `CF_ASSETS_MAX_JOB_SECONDS`, `CF_ASSETS_MAX_FILES`, `CF_ASSETS_WARN_FILES` | Workers Static Assets credentials, preview retries, file-count limits (`100000` max; warn at `98000` or `60000` with `charts` layout), and promotion gates |
| **Chart layout** | `CHARTS_LAYOUT`, `CF_CHARTS_WORKER_NAME`, `CF_CHARTS_PREVIEW_ALIAS`, `CF_CHARTS_STAGE_DIR`, `CF_CHARTS_WARN_FILES`, `CF_CHARTS_ALLOW_STALE`, `ALLIUM_NO_CHARTS` | `beside` (default) vs split `charts` Worker on `<host>/charts/*`, plus `--no-charts` emergency shedding |
| **Heartbeat** | `HEALTHCHECK_URL` | Optional healthchecks.io-style ping endpoint for start/success/failure/warnings |
| **Toolchain & logs** | `CF_ASSETS_TOOLCHAIN_AUTO_SYNC`, `CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT`, `CF_ASSETS_TOOLCHAIN_RETRY_SECONDS`, `WRANGLER_LOG*`, `ALLIUM_UPDATE_LOG_*` | Automated `pnpm` toolchain sync and bounded log rotation |
| **R2 & DO sync** | `R2_ENABLED`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET`, `R2_BINDING_NAME`, `R2_CONTENT_SYNC_INTERVAL`, `R2_CONTENT_VERIFY_PATHS`, `RCLONE_*`, `DO_ENABLED`, `DO_SPACES_*`, `DO_RCLONE_*` | R2 credentials and daily verification (`every-build` template default; `daily` in production); DO Spaces credentials, CDN toggle, TPS limit (`120`), HTTP/2 disable, checksum, `--s3-no-head`, and fast-list subtrees |
| **Backups & retention** | `LOCAL_BACKUP_FREQUENCY`, `R2_BACKUP_FREQUENCY`, `DO_BACKUP_FREQUENCY`, `KEEP_BACKUPS`, `LOCAL_KEEP_BACKUPS`, `DO_REMOTE_BACKUP_INLINE`, `DO_REMOTE_BACKUP_*`, `DO_IO_LOCK_WAIT_SECONDS` | Snapshot frequencies, local/R2 retention counts, and deferred DO remote snapshot throttling |
| **Failover & Pages** | `FAILOVER_ORIGIN_URL`, `PAGES_PROJECT_NAME`, `WRANGLER_COMPATIBILITY_DATE`, `PAGES_BUILD_OUTPUT_DIR`, `SITE_URL`, `PAGES_PURGE_URL`, `CACHE_KEY_ORIGIN`, `PAGES_ROLLBACK_MAINTENANCE_ENABLED`, `PAGES_BULK_PURGE_ENABLED`, `CACHE_TTL_*`, `PURGE_SECRET` | Fallback origin, Pages rollback deployment, cache TTLs, and `/_purge` control |
| **Sparse telemetry** | `SOURCE_EVENTS_ENABLED`, `SOURCE_EVENTS_DATASET` | Analytics Engine point only on R2/failover fallback or total failure (no URLs, queries, IPs, or user agents) |
| **Local paths & cron** | `OUTPUT_DIR`, `BACKUP_DIR`, `ALLIUM_DIR`, `RCLONE_PATH`, `CRON_SCHEDULE` | Output/backup/repo paths and cron schedule (`15,45 * * * *`) |

---

## Backup & Rollback

### Snapshot Locations & Frequencies

- **Local:** `~/metrics-backups/backup-YYYY-MM-DD_HHMMSS/`
- **R2:** `r2-metrics:<bucket>/_backups/YYYY-MM-DD_HHMMSS/`
- **DO Spaces:** `spaces-metrics:<bucket>/_backups/YYYY-MM-DD_HHMMSS/`

`LOCAL_BACKUP_FREQUENCY`, `R2_BACKUP_FREQUENCY`, and `DO_BACKUP_FREQUENCY` control how often snapshots run:

| Value | Behavior |
|---|---|
| `daily` (default) | Once per day (gated by `logs/last-*-backup-date`) |
| `every-run` | On every upload invocation |
| `off` | Skipped on scheduled runs (manual `--force-backup` still takes it) |

The deprecated `DAILY_LOCAL_BACKUP`, `DAILY_R2_BACKUP`, and `DAILY_DO_BACKUP` variables still work when the matching `*_FREQUENCY` setting is unset (`true` means `daily`, `false` means `every-run`, never `off`), emitting a deprecation notice. Any unrecognized value fails before `rclone` runs.

### Coordinated Daily Local Backup & Retention

When both `R2_ENABLED=true` and `DO_ENABLED=true` in `allium-deploy-update.sh`, local backup runs once instead of once per backend:

- R2 executes `create_local_backup` first and publishes its result (`created`, `already_done`, `skipped`, or `failed`) via `ALLIUM_LOCAL_BACKUP_RESULT_FILE`.
- DO waits on `ALLIUM_PRIMARY_LOCAL_BACKUP_RESULT_FILE`. If R2 succeeded (`created` or `already_done`), DO skips its local backup; if R2 failed or skipped, DO runs the local backup itself before modifying live DO objects and aborts the upload if that fallback fails or times out.
- Concurrent local backups serialize with `flock` on `logs/.local-backup.lock` (`LOCAL_BACKUP_LOCK_FILE`) and write into `backup-*.tmp.*` staging directories renamed atomically on completion.
- `--skip-local-backup` (or `ALLIUM_SKIP_LOCAL_BACKUP=true`) skips local backup for a single run unless `--force-backup` is passed (which enforces local backup completion).
- **Retention:** `KEEP_BACKUPS` governs R2 `_backups/` retention; `LOCAL_KEEP_BACKUPS` sets an independent retention count for local `BACKUP_DIR` (defaulting to `KEEP_BACKUPS`). [`scripts/allium-deploy-prune.sh`](scripts/allium-deploy-prune.sh) retains `SAFETY_BUFFER=2` extra backups before pruning and skips stale `backup-*.tmp.*` cleanup while `logs/.local-backup.lock` is held.
- **Deferred DO remote snapshots:** With `DO_REMOTE_BACKUP_INLINE=false`, scheduled uploads skip the DO server-side snapshot. Run [`scripts/run-do-remote-backup.sh`](scripts/run-do-remote-backup.sh) hourly instead (throttled at `DO_REMOTE_BACKUP_TPS_LIMIT=30` ops/s under `/tmp/allium-do-spaces-io.lock`), or run `./scripts/allium-deploy-upload-do.sh --remote-backup-only --force-backup` on demand.

### Storage Rollback

```bash
# Restore a local snapshot to R2 or DO Spaces
./scripts/allium-deploy-upload-r2.sh ~/metrics-backups/backup-2025-12-01_063000
./scripts/allium-deploy-upload-do.sh ~/metrics-backups/backup-2025-12-01_063000

# Restore ONE remote snapshot to OUTPUT_DIR, then re-publish. Run only one command:
# Option A: Restore from R2 snapshot
~/bin/rclone sync r2-metrics:<bucket>/_backups/2025-12-01_063000 ~/metrics-output
# Option B: Restore from DO Spaces snapshot
~/bin/rclone sync spaces-metrics:<bucket>/_backups/2025-12-01_063000 ~/metrics-output
```

For Workers Static Assets version rollback or route-removal rollback to Cloudflare Pages, see [docs/WORKERS_STATIC_ASSETS.md](docs/WORKERS_STATIC_ASSETS.md).

---

## Search, Heartbeat & Workers Toolchain

### Search (`/search`)

Production `/search?q=...` requests are handled by `workers/search.js` delegating to `functions/search.js` (reading `search-index.json` via the `ALLIUM_ASSETS` binding, with storage fallback for Pages). Supported queries include full/partial fingerprints, nicknames, AS numbers, countries, IPv4/IPv6 addresses, contact/AROI domains, platforms, and flags.

- **Index schema:** Requires `search-index.json` generated by Allium. Schema `v1.6+` renders CIISS `v2` (grey) / `v3` (green) badges from each relay's `vn` field on disambiguation pages; `v1.7` preserves `/platform/<folder>/` casing; `2.x` major bumps fail closed.
- **Validation:** `scripts/validate-search-discovery.py` verifies search and crawler discovery outputs after every Allium run.

### Heartbeat (`HEALTHCHECK_URL`)

When `HEALTHCHECK_URL` is configured, each update pings `<url>/start`, `<url>` on success, `<url>/fail` (`class=<class> exit=<status>`) on failure, and `<url>/log` on non-fatal warnings (failed DO upload, failed old-URL redirect check, or Allium held back for charts layout).

Failure classes: `allium`, `setup`, `charts_config`, `local`, `storage`, `cap`, `main_prepare`, `main_upload`, `main_promote`, `charts_prepare`, `charts_upload`, `charts_promote`, `route_definitive`, `route_inconclusive`, `charts_stale`, or `other`. Workers failures ping `/fail` even when `CF_ASSETS_REQUIRED=false` exits `0`.

### Workers Toolchain (`allium-deploy-sync-toolchain.sh`)

`package.json` and `pnpm-lock.yaml` pin Wrangler (`4.149.0`) and Node.js (`24.21.0` via `devEngines.runtime`). When a guarded auto-pull changes `package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, or `.npmrc`, `scripts/allium-deploy-sync-toolchain.sh` runs `corepack pnpm install --frozen-lockfile` in an empty environment with GNU `timeout` (`CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT`), verifies `wrangler --version` and a clean checkout, and restores the prior `node_modules` and `HEAD` manifests on failure (retrying the same lockfile after `CF_ASSETS_TOOLCHAIN_RETRY_SECONDS`).

`patches/wrangler@4.149.0.patch` (listed in `pnpm-workspace.yaml` `patchedDependencies`) replaces Wrangler's linear scan of the asset manifest with a hash `Map` lookup.

---

## Directory Structure

```
allium-deploy/
├── config.env.example                     # Canonical configuration reference
├── package.json                           # Pinned Wrangler/Node/pnpm & test scripts
├── pnpm-lock.yaml                         # Lockfile & patch hashes
├── pnpm-workspace.yaml                    # allowBuilds & patchedDependencies
├── wrangler.assets.toml.template          # Main Workers Static Assets template
├── wrangler.charts.toml.template          # Split charts Worker template
├── wrangler.toml.template                 # Cloudflare Pages rollback template
├── cloudflare-assets/
│   ├── _headers                           # Security, cache & preview noindex rules
│   ├── 404.html                           # Static 404 page
│   ├── .assetsignore.charts               # Excludes /charts/ from main Worker
│   └── _redirects.charts                  # 302 redirects legacy chart URLs
├── functions/
│   ├── _shared.js                         # MIME types, security headers & HTML escaping
│   ├── [[path]].js                        # Pages multi-storage, failover & /_purge
│   └── search.js                          # Search handler shared by Workers & Pages
├── workers/
│   └── search.js                          # Workers /search entry point + ALLIUM_ASSETS
├── patches/
│   └── wrangler@4.149.0.patch             # Hash-indexed asset manifest lookup patch
├── docs/
│   └── WORKERS_STATIC_ASSETS.md           # Workers architecture, operations & rollback
├── scripts/
│   ├── allium-deploy-install.sh           # Install/cron/update: one-time setup
│   ├── allium-cron-check.sh               # Install/cron/update: cron verification
│   ├── allium-deploy-update.sh            # Install/cron/update: main scheduled pipeline
│   ├── allium-deploy-lib.sh               # Install/cron/update: shared shell helpers
│   ├── allium-deploy-cfassets.sh          # Workers publish & verify: main config/upload/promote
│   ├── allium-deploy-verify-cfassets.sh   # Workers publish & verify: main preview checks
│   ├── allium-deploy-cfcharts.sh          # Workers publish & verify: split charts Worker
│   ├── allium-deploy-verify-cfcharts.sh   # Workers publish & verify: charts preview & route checks
│   ├── allium-deploy-charts-route.sh      # Workers publish & verify: <host>/charts/* route CRUD
│   ├── allium-deploy-cfpages.sh           # Workers publish & verify: Pages rollback deploy
│   ├── allium-deploy-upload-common.sh     # DO/R2 upload/backup/prune: shared helpers & locks
│   ├── allium-deploy-upload-r2.sh         # DO/R2 upload/backup/prune: R2 sync, verify & backup
│   ├── allium-deploy-upload-do.sh         # DO/R2 upload/backup/prune: DO sync & backup
│   ├── allium-deploy-prune.sh             # DO/R2 upload/backup/prune: local & R2 pruning
│   ├── run-do-remote-backup.sh            # DO/R2 upload/backup/prune: hourly DO snapshot runner
│   ├── allium-deploy-sync-toolchain.sh    # Toolchain/log maintenance: pinned pnpm/Wrangler sync
│   ├── allium-deploy-maintain-logs.sh     # Toolchain/log maintenance: bounded log rotation
│   ├── validate-search-discovery.py       # Audit/validation/cutover: search & discovery checks
│   ├── verify-deployed-matches-checkout.sh# Audit/validation/cutover: Pages deploy SHA check
│   ├── audit-cfassets-soak.js             # Audit/validation/cutover: shadow soak TSV audit
│   ├── audit-cfassets-stage4.js           # Audit/validation/cutover: promotion correlation audit
│   ├── audit-remote-live-stats.js         # Audit/validation/cutover: live output stats check
│   ├── run-cfassets-remediation-audit.sh  # Audit/validation/cutover: read-only live audit
│   ├── run-stage4-24h-acceptance.sh       # Audit/validation/cutover: 24h acceptance wrapper
│   ├── run-stage5-24h-activation.sh       # Audit/validation/cutover: Stage 5 R2 daily toggle
│   └── run-stage6-worker-domain-cutover.sh# Audit/validation/cutover: Custom Domain cutover
├── tests/                                 # Node tests (*.test.js) & shell suites (test-*.sh)
├── logs/                                  # Runtime logs, markers & TSV summaries (gitignored)
└── public/                                # Empty directory for Pages deployment
```

---

## Requirements & License

- **Host requirements:** Debian/Ubuntu Linux, Python 3.8+, `python3-jinja2`, Node.js 18+ with `corepack`, `jq`, `curl`, `flock`, GNU `timeout`, `sha256sum`, `rclone`.
- **Accounts & capacity:** Cloudflare account (Workers Static Assets, R2, Pages), optional DigitalOcean Spaces, ~4 GB RAM, ~10 GB+ disk space (scaled by `LOCAL_KEEP_BACKUPS`).
- **License:** [Apache 2.0](LICENSE)
