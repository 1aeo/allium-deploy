# Cloudflare Workers Static Assets

Production traffic (`metrics.1aeo.com/*`) is served by **Cloudflare Workers Static Assets** via [`workers/search.js`](../workers/search.js) and the `ALLIUM_ASSETS` binding. Historical Stage 1–5 execution logs and planning records remain in git history; this document covers current production architecture, split-charts operations, verification, and rollback.

---

## Current Architecture & Status

- **Production origin:** Workers Static Assets runs with `CF_ASSETS_ENABLED=true`, `CF_ASSETS_REQUIRED=true`, and `CF_ASSETS_ALLOW_PROMOTION=true`. Static files are served directly by Cloudflare's assets layer before Worker code executes; only `/search` invokes [`workers/search.js`](../workers/search.js).
- **Storage mirrors:** DigitalOcean Spaces mirrors every build ([`scripts/allium-deploy-upload-do.sh`](../scripts/allium-deploy-upload-do.sh)). Cloudflare R2 replicates live content daily (`R2_CONTENT_SYNC_INTERVAL=daily`), verified against generated output by object count, total bytes, and representative SHA-256 hashes (`R2_CONTENT_VERIFY_PATHS`).
- **Pages rollback target:** [`functions/[[path]].js`](../functions/[[path]].js) and [`functions/search.js`](../functions/search.js) stay deployed behind the zone Worker route. Because the Worker intercepts `SITE_URL`, [`scripts/allium-deploy-update.sh`](../scripts/allium-deploy-update.sh) sends cache purges to `PAGES_PURGE_URL` (`https://*.pages.dev/_purge`) with absolute `SITE_URL` cache keys (governed by `PAGES_ROLLBACK_MAINTENANCE_ENABLED` and `PAGES_BULK_PURGE_ENABLED`).
- **Dormant Stage 6 cutover:** [`scripts/run-stage6-worker-domain-cutover.sh`](../scripts/run-stage6-worker-domain-cutover.sh) (`--preflight` / `--execute`) remains available to switch from the `<host>/*` zone Worker route over the Pages CNAME to a Workers Custom Domain, retain `<host>/charts/*` when `CF_CHARTS_WORKER_NAME` is configured, and disable Pages rollback maintenance.

---

## Publish & Restore-Priority Pipeline

Before any publisher starts, `allium-deploy-update.sh` runs guarded pulls (`allium-deploy` and `allium`), syncs the pinned toolchain, pins the clean deploy SHA (`CF_ASSETS_EXPECTED_DEPLOY_SHA`), runs Allium, validates search/discovery artifacts, prepares Workers overlays, and enforces local tree/file-count gates:

1. **Overlay & file-count guard (`--generate-only`):**
   - Copies `cloudflare-assets/_headers` and `404.html` into `OUTPUT_DIR`.
   - When `CHARTS_LAYOUT=beside`, removes stale `.assetsignore` / `_redirects` and leftover `charts/{relay,contact}`.
   - Counts Wrangler-uploadable files and fails (`exit 4`) above `CF_ASSETS_MAX_FILES` (`100000`) or warns from `CF_ASSETS_WARN_FILES` (`98000`, or `60000` with `CHARTS_LAYOUT=charts`).
2. **Parallel upload launch:**
   - Starts the optional charts Worker (`allium-deploy-cfcharts.sh --upload-only`), main Worker (`allium-deploy-cfassets.sh --upload-only`), DO Spaces sync, and R2 sync concurrently.
3. **Immutable upload & promotion:**
   - Uploads run `wrangler versions upload --preview-alias` with bounded transient retries (`CF_ASSETS_UPLOAD_MAX_ATTEMPTS`).
   - Parses the version UUID and `workers.dev` preview URL from Wrangler's structured output, runs preview checks, records the exact UUID in `logs/cfassets-last-version`, and promotes via:
     ```bash
     wrangler versions deploy VERSION_ID@100% --yes --config wrangler.assets.toml
     ```
4. **Restore-priority ordering (`publish_in_restore_order`):**
   - With `CHARTS_LAYOUT=charts` (and `ALLIUM_NO_CHARTS=false`), the charts Worker promotes and passes `--check-route` on `SITE_URL/charts/` before the main Worker promotes.
   - The main Worker promotes as soon as its preview passes (and charts allows), without waiting for DO or R2.
   - DO Spaces and R2 are awaited afterward (keeping per-publisher durations), followed by Pages rollback cache purge.

| Failure point | Promotion attempted? | Live traffic effect |
|---|---|---|
| Local generation, discovery, or file-count gate | No | No publisher runs; previous Worker and mirrors stay intact |
| Worker upload, preview check, or missing/malformed UUID | No | Previous healthy Worker version remains live at `100%` |
| `wrangler versions deploy` error | Yes (once) | Cloudflare preserves previous deployment; job fails if `CF_ASSETS_REQUIRED=true` |
| DO Spaces or R2 failure after Worker verification | Yes | Main Worker promotion proceeds; mirror failure is logged and retried |

---

## Split Charts Layout (`CHARTS_LAYOUT=charts`)

To stay well below the `100000`-asset per-version limit, `CHARTS_LAYOUT=charts` moves relay and contact chart PNGs into a dedicated assets-only Worker (`CF_CHARTS_WORKER_NAME`, [`wrangler.charts.toml.template`](../wrangler.charts.toml.template)) serving `<host>/charts/*`:

- **Stage & main overlays:** `allium-deploy-cfcharts.sh` builds `CF_CHARTS_STAGE_DIR` via same-filesystem hard links to `OUTPUT_DIR/charts/`, adding `charts/404.html`, a unique `charts/build-id.txt`, and `_headers` with `X-Allium-Origin: charts` added to the single `/*` rule. On the main Worker, `cloudflare-assets/.assetsignore.charts` excludes `/charts/` and `_redirects.charts` serves `302` redirects from `/relay/:fp/:name.png` and `/contact/:hash/:name.png` to `/charts/...`.
- **Live continuity & transitions:** `logs/cfcharts-live-charts` retains charts linked by the currently promoted main Worker across charts promotions until a new main version promotes. `logs/charts-layout-promoted` tracks the live layout, enforcing stricter checks on layout transitions and blocking route deletion. When using `DO_RCLONE_FAST_LIST_SUBTREES`, list `charts` first (`charts,relay,contact,...`) before switching layouts.
- **Route & config commands:** `allium-deploy-cfcharts.sh --check-config` validates charts settings before Allium runs; `--check-redirects` verifies old chart redirects after main promotion; `allium-deploy-charts-route.sh status|create|delete` manages `<host>/charts/*`.
- **Bootstrap before first switch (while `CHARTS_LAYOUT=beside`):**
  ```bash
  ./scripts/allium-deploy-cfcharts.sh --bootstrap-deploy
  ./scripts/allium-deploy-charts-route.sh create
  ./scripts/allium-deploy-cfcharts.sh --check-bootstrap-route
  ```
- **Resilience & emergency shedding:**
  - `CF_CHARTS_ALLOW_STALE=true` permits main promotion when the charts Worker fails on a non-transition build (still exiting non-zero).
  - `ALLIUM_NO_CHARTS=true` runs Allium with `--no-charts` to drop chart PNGs while leaving the charts Worker on its existing promoted version.

---

## Verification, Bounded TSV Logs & Toolchain Auto-Sync

- **Main preview verifier (`allium-deploy-verify-cfassets.sh`):**
  - Requires `CF_ASSETS_VERIFY_ATTEMPTS` (`3`) consecutive passes within `CF_ASSETS_VERIFY_MAX_ATTEMPTS` (`12`).
  - Verifies `/`, `/search-index.json`, a nested page, the largest file, a chart PNG (or `302` redirect in `charts` layout), `Cache-Control` + preview `noindex` headers, directory canonicalization, custom `404.html`, and `/search?q=<fingerprint>`.
- **Charts verifier (`allium-deploy-verify-cfcharts.sh`):**
  - Verifies preview `charts/build-id.txt`, page-linked and sampled chart PNGs byte-for-byte (`image/png`, `nosniff`, `noindex`, `X-Allium-Origin: charts`), ETag `304`, and `charts/404.html`.
  - After promotion, `--route` verifies `SITE_URL/charts/` live (exiting `75` if network errors, Cloudflare challenges, or `403`/`429`/`5xx` make the probe inconclusive).
- **Bounded TSV logs (`logs/`, no per-request logging):**
  - `logs/cfassets-shadow-summary.tsv` — verified immutable candidate uploads and file/byte counts
  - `logs/cfassets-promotion-summary.tsv` — attempted promotions (`timestamp_utc`, `version_id`, `exit_status`)
  - `logs/cfassets-uploads.tsv` — Wrangler file counts (`files`, `asked`, `uploaded`) and transfer durations
  - `logs/cfassets-stage2-job-summary.tsv` — whole-job duration, cadence (`CF_ASSETS_MAX_JOB_SECONDS=1800`), and streak
  - `logs/cfcharts-*` equivalents, `logs/cfcharts-job-timing.tsv`, and `logs/do-live-sync-summary.tsv`
- **Toolchain auto-sync (`allium-deploy-sync-toolchain.sh`):**
  - Runs `corepack pnpm install --frozen-lockfile` in an empty environment under GNU `timeout` whenever `package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, or `.npmrc` changes.
  - Verifies `wrangler --version` and a clean checkout, restoring the prior `node_modules` and `HEAD` manifests on failure.

---

## Rollback

- **Candidate or upload failure:** Automatic no-op; Cloudflare keeps the previous verified Worker version live at `100%`.
- **Pause promotions immediately:** Set `CF_ASSETS_ALLOW_PROMOTION=false` (re-read on every `--promote`, including by a running job) and optionally `CF_ASSETS_REQUIRED=false`.

### Roll Back Worker Version

Set `CF_ASSETS_ALLOW_PROMOTION=false` in `config.env` to freeze scripted `--promote` runs, pick a known-good UUID from `logs/cfassets-promotion-summary.tsv`, and verify chart routing and availability before running a direct `wrangler versions deploy` (which bypasses `--promote`):

- **`CHARTS_LAYOUT=beside` versions:** Bundle charts inline, so rolling back the main Worker UUID is self-contained.
- **`CHARTS_LAYOUT=charts` versions:** Deploying an older main Worker UUID restores only the main Worker, not older charts. If a `beside` build is currently live, `<host>/charts/*` may have been deleted; check and re-create it first with `./scripts/allium-deploy-charts-route.sh status` and `./scripts/allium-deploy-charts-route.sh create`, then verify the target UUID's linked `/charts/...` URLs resolve on the **production host** (`SITE_URL/charts/...`), not just a preview URL or `logs/cfcharts-live-charts`.
- **If those charts are missing on production:** Do **not** deploy an older charts Worker version that drops charts still linked by the currently live main Worker or cached pages. Instead, either [roll back to Cloudflare Pages](#roll-back-to-cloudflare-pages) (`functions/[[path]].js` resolves chart keys across both layouts from DO/R2), or restore a matching backup snapshot into `OUTPUT_DIR`, temporarily set `CF_ASSETS_ALLOW_PROMOTION=true` for a recovery publish (which keeps `logs/cfcharts-live-charts` for the live version while uploading restored charts before promoting the main Worker), and set `CF_ASSETS_ALLOW_PROMOTION=false` afterward.

```bash
pnpm exec wrangler versions deploy <VERSION_ID>@100% --yes --config wrangler.assets.toml
```

### Roll Back to Cloudflare Pages

- Delete the production `<host>/*` Worker route in Cloudflare so traffic routes directly to the Pages deployment kept warm behind `PAGES_PURGE_URL` (backed by every-build DO Spaces and daily R2).
- Keep `<host>/charts/*` active while any live or cached pages link to `/charts/` (or until a `beside` build is live and `logs/charts-layout-promoted` reflects `beside`).
