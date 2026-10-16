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

# 4. Install cron (uses /etc/cron.d/ drop-in for isolation)
sudo cp ~/allium-deploy/allium.cron /etc/cron.d/allium && sudo chmod 644 /etc/cron.d/allium

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

### Workers Static Assets shadow (Stages 1–2)

The migration plan is tracked in
[`docs/WORKERS_STATIC_ASSETS_MIGRATION_PLAN.md`](docs/WORKERS_STATIC_ASSETS_MIGRATION_PLAN.md).
During Stages 1–2, Workers Static Assets receives and verifies an immutable
candidate after every build, while `metrics.1aeo.com` continues using the
existing Pages/DO/R2 path.

```bash
CF_ASSETS_ENABLED=true
CF_ASSETS_REQUIRED=false
CF_ASSETS_ALLOW_PROMOTION=false
CF_ASSETS_WORKER_NAME=1aeo-metrics-assets-stage2
CF_ASSETS_PREVIEW_ALIAS=allium-stage2
CF_ASSETS_VERIFY_ATTEMPTS=3
CF_ASSETS_VERIFY_MAX_ATTEMPTS=12
CF_ASSETS_VERIFY_RETRY_DELAY=10
CF_ASSETS_VERIFY_CURL_TIMEOUT=60
```

Safety properties in shadow mode:

- `wrangler.assets.toml` is generated separately from the Pages configuration.
- The generated Worker configuration contains no zone route or custom domain.
- Normal scheduled runs use `wrangler versions upload`; they do not promote a
  version or change production traffic.
- `_headers` and `404.html` are installed before any publisher reads the output
  tree. A root `.assetsignore` or `_redirects`, which this code writes only
  for `CHARTS_LAYOUT=charts` (see below), is removed at the same point
  otherwise. `_headers`, `.assetsignore` and `_redirects` are excluded from DO
  and R2 synchronization.
- Each upload first counts the files Wrangler would upload. It refuses above
  `CF_ASSETS_MAX_FILES` (100000, Cloudflare's limit per Worker version) and
  warns from `CF_ASSETS_WARN_FILES` (98000; 60000 with
  `CHARTS_LAYOUT=charts`, see below).
- Candidate root, search index, a nested page, the largest file, a chart PNG
  (when the tree has one), headers, redirects, static 404, and dynamic search
  are checked three times.
- A shadow failure is recorded but remains non-blocking while
  `CF_ASSETS_REQUIRED=false`.

### Workers Static Assets production promotion (Stage 4)

After the production route and two-hour gate pass, enable automatic promotion
only with the complete Stage 4 controls:

```bash
CF_ASSETS_ENABLED=true
CF_ASSETS_REQUIRED=true
CF_ASSETS_ALLOW_PROMOTION=true
PAGES_PURGE_URL=https://1aeo-metrics.pages.dev
```

Each scheduled job uploads an immutable version, requires the complete preview
verifier to pass, records that exact version ID, and then runs:

```bash
wrangler versions deploy VERSION_ID@100% --yes --config wrangler.assets.toml
```

The Workers upload, the DO Spaces sync and the R2 sync start together. The job
acts on them in restore-priority order: it promotes the verified Workers
version as soon as its upload and preview checks finish, without waiting for
the storage syncs, then waits for DO Spaces and then R2. Each sync's logged
duration is its own. Promotion does not depend on the storage syncs, and the
job still waits for all of them before deciding its exit status.

The version file is accepted only when it contains one valid Worker version
UUID. Missing or malformed state, upload failure, preview-verification failure,
or Wrangler deployment failure leaves the previous healthy production version
active and fails the required Workers publication. Attempted promotions append
one bounded timestamp/version/status row to
`logs/cfassets-promotion-summary.tsv`; normal request logging remains disabled.

While the Worker route fronts `SITE_URL`, the legacy Pages purge endpoint is
not reachable through that hostname. `PAGES_PURGE_URL` therefore targets the
canonical Pages deployment directly, while every purge body uses absolute
`SITE_URL` cache keys. This keeps Pages usable as a fresh route-removal rollback
without purging Workers Static Assets or making purge part of Worker version
activation.

Run `pnpm test` before activation. It includes the Node tests and every shell
behavior suite, including enabled promotion, failure propagation, and the
guarantee that an unverified candidate never reaches the promoter. Full
activation and rollback details are in
[`docs/WORKERS_STATIC_ASSETS_STAGE4_READINESS.md`](docs/WORKERS_STATIC_ASSETS_STAGE4_READINESS.md).

A brand-new shadow Worker needs one route-free bootstrap deployment before its
version preview URLs can serve the assets binding. Generate and inspect the
configuration first, enable Workers Preview URLs for that Worker, and bootstrap
only the dedicated `*-stage2`/`*-shadow` service on `workers.dev`. Do not attach
a zone route, custom domain, or production DNS record. The normal scheduled
path never repeats this bootstrap. Cloudflare otherwise returns error 1042 for
asset-binding preview requests when the Worker has versions but no deployment
record.

Deployment evidence is bounded in:

- `logs/cfassets-shadow-summary.tsv`
- `logs/cfassets-shadow-consecutive-successes`
- `logs/cfassets-last-version`

These are deployment summaries, not request logs. Stage 3 production routing
remains disabled until explicit review.

`logs/cfassets-uploads.tsv` adds one row per Wrangler upload: the files the
version holds, the files Wrangler asked for (its "Found N new or modified
static assets" line), the files it reported uploaded, the seconds from that
line to the last upload line, and the seconds of the whole command. The two
Wrangler counts need `WRANGLER_LOG=info`; `-` marks a hidden value. Wrangler
keeps already uploaded files per Worker, but only for a bounded volume of
recent uploads, so these rows show how many files each upload really sends.

### Workers Static Assets chart layout

The relay and contact chart PNGs are most of the output tree's files. With
`CHARTS_LAYOUT=charts` they move to a second, charts-only Worker, which keeps
the main Worker's versions well below the per-version file limit. The default,
`CHARTS_LAYOUT=beside`, changes nothing.

```bash
CHARTS_LAYOUT=charts
CF_CHARTS_WORKER_NAME=...        # required; no default
CF_CHARTS_PREVIEW_ALIAS=allium-charts-candidate
CF_CHARTS_STAGE_DIR=...          # outside OUTPUT_DIR, on the same filesystem
```

In that layout `/charts/relay/<fingerprint>/<name>.png` and
`/charts/contact/<hash>/<name>.png` are the permanent chart URLs. The old ones,
`/relay/<fingerprint>/<name>.png` and `/contact/<hash>/<name>.png`, answer
with a 302 to them for as long as the layout is `charts`: crawlers and other
sites keep requesting them. They stay 302, not 301, while going back to
`beside` is possible, as browsers keep a 301 with no expiry.

With `CHARTS_LAYOUT=charts`:

- Before Allium runs, the job checks the charts Worker's settings
  (`scripts/allium-deploy-cfcharts.sh --check-config`) and that Allium has
  `--chart-layout`. An Allium pulled by that job without it, or whose
  `allium.py --help` fails, is set back to the previous checkout for the
  build, logged with the reason and sent to the heartbeat as a warning;
  otherwise the job stops before anything is generated or published.
- Allium runs with `--chart-layout charts --chart-format png`: charts go to
  `charts/relay/<fingerprint>/` and `charts/contact/<hash>/`, pages link to
  them as `../../charts/...`, and a build without working PNG support fails
  instead of switching to SVG charts.
- The main Worker's assets directory gets two deploy-owned root files,
  installed from `cloudflare-assets/.assetsignore.charts` and
  `cloudflare-assets/_redirects.charts`: `.assetsignore` drops `/charts/`, and
  `_redirects` sends the old chart URLs to their `/charts/` paths. Both are
  present together or not at all, and `CHARTS_LAYOUT=beside` removes them. The
  rendered `wrangler.assets.toml` does not change. The main Worker refuses a
  tree that is not in this layout (a chart beside its page, or none below
  `charts/`), and its verifier fails one without a chart below `charts/`.
- `scripts/allium-deploy-cfcharts.sh` publishes the charts Worker from
  `wrangler.charts.toml.template`: assets only, no Worker code, no route, a
  missing chart answered with `charts/404.html`. Its directory,
  `CF_CHARTS_STAGE_DIR`, is rebuilt every build as hard links to
  `OUTPUT_DIR/charts/`, plus `404.html` as `charts/404.html`,
  `charts/build-id.txt`, a new value in every stage, and the main Worker's
  `_headers` (its rules match the full paths, `/charts/...` included) with
  the marker header `X-Allium-Origin: charts` added to its `/*` rule.
  Cloudflare keeps one rule per path, so a second `/*` rule would replace the
  first and its security headers. A partition check requires every file of
  the output tree to be uploaded by exactly one Worker, and the stage build
  logs the charts per period (`1m`, `6m`, ...). Its state and summaries are
  `logs/cfcharts-*`, never the main Worker's files.
- Production reaches the charts Worker only through the zone route
  `<host>/charts/*`, which is more specific than the main Worker's
  `<host>/*`. Preview URLs have no route, so a main Worker preview cannot show
  charts: its verifier checks instead that an old chart URL redirects to
  `/charts/`. The charts Worker's own preview is verified against its stage:
  the build ID must match, charts the new pages link to (relay, contact and
  vanity-domain pages) and charts sampled from the stage must match byte for
  byte, with nosniff, noindex and the marker; a repeat with the ETag must get
  304, and a missing chart the 404 page with the marker. Pages that link to no
  chart, or to a chart the stage lacks, fail.
- Every build uploads the charts Worker alongside the other publishers. Its
  stage also keeps the charts that the live main Worker version's pages link
  and this build dropped (listed in `logs/cfcharts-live-charts` at each main
  promotion), so a main promotion that fails or is withheld after the charts
  promotion leaves no live page without its charts. It is promoted first,
  then `--check-route` checks production:
  `SITE_URL/charts/build-id.txt` must return the stage's build ID, which
  proves that the route reaches the version just promoted; the charts that a
  relay, a contact and a vanity-domain page link to, the stage's first and
  largest charts and a missing chart must get the stage's bytes or the 404
  page; and every answer must carry the marker, which the main Worker's
  otherwise identical 404 page lacks, and no `X-Robots-Tag`. Network errors,
  Cloudflare challenges and 403, 429 or 5xx answers make the check
  inconclusive (exit 75) instead of failed, unless another attempt got a
  wrong answer. One passing attempt is enough; it shows what the location
  that answers the build server serves. Only then is the main Worker
  promoted, and an old chart URL on `SITE_URL` is checked for its redirect (a
  failure there only warns).
- `logs/charts-layout-promoted` records the layout of the last promoted main
  Worker version; a missing file means `beside`. A build whose
  `CHARTS_LAYOUT` differs from it is a transition build. A charts failure
  (preparation, upload, verification, promotion or route check) withholds
  the main Worker's promotion: the withheld promotion is recorded in
  `logs/cfassets-promotion-summary.tsv` with the charts Worker's exit status,
  and the version is removed from `logs/cfassets-last-version`, so that no
  later `--promote` deploys it. With `CF_ASSETS_REQUIRED=true` that fails the
  job, as any Workers failure does. In a build that keeps the promoted layout
  two cases promote the main Worker anyway, after which the job publishes
  everything and exits non-zero: an inconclusive route check, and
  `CF_CHARTS_ALLOW_STALE=true` (default `false`), which accepts that charts
  new since the charts Worker's last good promotion fail until it recovers.
  A transition build has no exception.
- Before any publisher starts, the job checks the output tree. In this layout
  no chart may be beside its page; in either layout every PNG link on the
  pages must fit the layout (with `charts`, below `charts/` or `static/`;
  with `beside`, not below `charts/`). A chart beside its page always stops
  the job. Links that do not fit, and a failed Workers preparation (a version
  over `CF_ASSETS_MAX_FILES` included, which the preparation already
  refuses), stop a transition build and otherwise only warn. Stopping there
  holds every publisher, DO and R2 included, so that all of them keep their
  last build.
- `logs/cfassets-shadow-summary.tsv` counts the files the main Worker's
  version holds, without `charts/`, so its `file_count` drops at the switch
  (the soak audit's file-count delta check flags that build). The main Worker
  warns from 60000 files in this layout unless `CF_ASSETS_WARN_FILES` is set;
  the charts Worker warns from `CF_CHARTS_WARN_FILES` (85000).
- Each build that publishes the charts Worker appends a row to
  `logs/cfcharts-job-timing.tsv`: the seconds to build its stage, when it was
  promoted, and how long the main Worker's verified version waited for it.
- DO and R2 mirror the output tree as before, `charts/` included. The first
  build after switching the layout either way moves almost every chart key
  once. If `DO_RCLONE_FAST_LIST_SUBTREES` is set, list `charts` first
  (`charts,relay,contact,...`) before switching, and the job warns until it
  is: each switch then uploads the new chart keys before the `relay/` and
  `contact/` passes delete the old ones. When the Pages rollback function
  misses a chart key in a backend, it reads the same chart's key in the other
  layout from that backend before trying the next one, so both URLs work in
  either layout; such an answer has `X-Served-From: <backend>; alias`.
- `scripts/run-stage6-worker-domain-cutover.sh` accepts exactly one more zone
  route, `<host>/charts/*` to `CF_CHARTS_WORKER_NAME`, and keeps it. That a
  route outranks a Custom Domain on the same host is documented by
  Cloudflare but untested here.
- `scripts/run-cfassets-remediation-audit.sh` also checks that the charts
  Worker serves its last successful promotion.

`ALLIUM_NO_CHARTS=true` (default `false`) sheds the charts in an emergency, in
either layout: Allium runs with `--no-charts`, so pages show no charts and the
tree has no chart PNG, far below the file limit even beside the pages. In the
charts layout such a build does not publish the charts Worker, which keeps
serving its promoted version, so both kinds of chart URL keep working once a
build with charts has published it. A main Worker version without charts
leaves `logs/charts-layout-promoted` as it was, so the next build with charts
after a layout switch is still a transition build.

Before setting `CHARTS_LAYOUT=charts`, the charts Worker must exist with a
deployment and the route `<host>/charts/*` must point at it. While the layout
is still `beside`:

- `scripts/allium-deploy-cfcharts.sh --bootstrap-deploy` creates the Worker
  with `wrangler deploy` (the first upload of a new Worker cannot be a version
  upload) from a stage of two files: the `_headers` with the marker and
  `charts/404.html`. The first build in the charts layout uploads the charts.
  It uses the pinned toolchain and the usual token files, starts from an
  empty environment as the scheduled job does, refuses a configuration with a
  route, logs Wrangler's upload counts, and fails if it leaves the checkout
  unclean, which the scheduled job would refuse. It refuses, without
  changing the stage, unless `CHARTS_LAYOUT` and
  `logs/charts-layout-promoted` both say `beside`, and when the Worker
  already has a deployment. Run it while no scheduled job runs, holding the
  job's lock.
- `scripts/allium-deploy-charts-route.sh status|create|delete` manages the
  route with the Workers token, which it never prints or puts on a command
  line. `create` requires exactly one route in the zone before and two after,
  and prints the new route's ID. `delete` refuses while `CHARTS_LAYOUT=charts`
  or while `logs/charts-layout-promoted` says `charts`.
- `SITE_URL/charts/404.html` then answers with the 404 page and
  `X-Allium-Origin: charts`. `scripts/allium-deploy-cfcharts.sh
  --check-bootstrap-route` checks that, and that a missing chart gets that
  page as a 404, without `X-Robots-Tag`; it exits 75 when Cloudflare
  answers with a challenge, 403, 429 or 5xx, or the network fails. Until the
  layout changes, nothing links to `/charts/`.

Rules for operating the chart layout:

- Never delete the `<host>/charts/*` route or the charts Worker while live or
  cached pages link to `/charts/`: every chart would fail. Rolling the main
  Worker back to a version from before the switch serves its own charts
  again; then write `beside` to `logs/charts-layout-promoted`, so that the
  next build in the charts layout is a transition build again.
- Switch only once a build has run this version of the update job: an older
  job runs Allium without `--chart-layout`, and the main Worker refuses that
  tree.
- Each job keeps the `CHARTS_LAYOUT`, `ALLIUM_NO_CHARTS`,
  `CF_CHARTS_WORKER_NAME` and `CF_ASSETS_ENABLED` it started with, whatever
  `config.env` says later, and reads `CF_CHARTS_ALLOW_STALE` once.
  `CF_ASSETS_ALLOW_PROMOTION` is read at each promotion, so setting it to
  `false` also stops the promotions of a job that is already running.
- To go back, set `CHARTS_LAYOUT=beside`, again a transition build: Allium
  writes the charts beside their pages again, the deploy removes
  `.assetsignore` and `_redirects`, and any `charts/relay` and
  `charts/contact` that Allium left, and the main Worker serves the charts
  again, as long as the whole tree stays within `CF_ASSETS_MAX_FILES`. Keep
  the route and the charts Worker for `/charts/` URLs already handed out, and
  keep `CF_CHARTS_WORKER_NAME` set while the route exists: the Stage 6
  cutover accepts the route only for that Worker.
- A charts Worker version rolled back by hand is replaced at the next build.
  Freeze both Workers with `CF_ASSETS_ALLOW_PROMOTION=false` first.
- With `CHARTS_LAYOUT=charts`, an Allium without `--chart-layout` is never
  built: a pulled one is set back for each build, and one already checked
  out stops every build until Allium has the option again or the layout is
  set back to `beside`.
- A broken PNG install (for example after an operating system upgrade)
  stops every build in this layout instead of switching to SVG charts:
  reinstall the packages rather than changing the layout.
- Keep the removal of a stale root `.assetsignore` or `_redirects` (see the
  shadow section above): it is what undoes this layout's control files when
  the layout, or this code, goes back.

### Heartbeat

`HEALTHCHECK_URL`, unset by default, names a healthchecks.io-style check that
expects a ping per scheduled job. Each job pings `<url>/start` when it
starts, `<url>` when it succeeds and `<url>/fail` when it fails, with
`class=<class> exit=<status>` as the body. The class is one of `allium`,
`setup`, `charts_config`, `local`, `storage`, `cap`, `main_prepare`,
`main_upload`, `main_promote`, `charts_prepare`, `charts_upload`,
`charts_promote`, `route_definitive`, `route_inconclusive` and `charts_stale`
(see the chart layout above), or `other`. A Workers failure (`cap`, `main_*`,
`charts_*`, `route_*`) pings `<url>/fail` even when the job exits 0, as it
does unless `CF_ASSETS_REQUIRED=true`. A failed DO upload, a failed old-URL
redirect check and an Allium held back for the charts layout ping
`<url>/log` without failing the job. The URL goes to curl on standard input
and is never logged, a failed ping never changes the job, and an endpoint
that does not answer delays it by about ten seconds per ping at most.

### Workers toolchain updates

`package.json` and `pnpm-lock.yaml` pin Wrangler and, through
`devEngines.runtime`, the Node.js release it runs on. pnpm installs that
Node.js into `node_modules/.bin/node` and the `wrangler` shim prefers it, so
the host's Node.js only has to run pnpm through corepack (Wrangler 4.87.0 and
later refuse to start on Node.js 20). When a guarded auto-pull changes either
file, the next job runs `scripts/allium-deploy-sync-toolchain.sh` before the
Workers upload. It moves the current `node_modules` aside, runs
`pnpm install --frozen-lockfile` within `CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT`
seconds, and accepts the result only if `wrangler --version` equals the pin and
the checkout is still clean. Any failure restores the previous `node_modules`
and restores the toolchain manifests that exist in HEAD (`package.json`,
`pnpm-lock.yaml`, `pnpm-workspace.yaml`, `.npmrc`) if the install changed
them. Any other change, including a newly added manifest such as `.npmrc`, is
reported in the job log and left in place, never deleted: inspect it before
the next attempt. The job then continues with the previous toolchain.

The install runs `corepack pnpm`, so the `packageManager` pin and its
`allowBuilds` list apply; a `pnpm` on `PATH` is used only if it reports that
exact version. pnpm, the build scripts it allows and the new Wrangler start
from an empty environment that keeps only `PATH`, `HOME`, user, locale, temp,
proxy and cache-directory variables, so they inherit none of the deploy job's
environment variables. They still run as the deploy user in the checkout and
can read any file that user can read, including `config.env`; the exact pins,
lockfile integrity and the `allowBuilds` list are what guard against a
compromised package. GNU `timeout` is required, because it stops the whole
install process group when `CF_ASSETS_TOOLCHAIN_INSTALL_TIMEOUT` expires. The same lockfile is retried after
`CF_ASSETS_TOOLCHAIN_RETRY_SECONDS` (default 3600); a different lockfile is
tried at once. `pnpm-workspace.yaml` and `.npmrc` count as part of the
lockfile. Set `CF_ASSETS_TOOLCHAIN_AUTO_SYNC=false` to install manually with
`corepack pnpm install --frozen-lockfile`.

`patches/wrangler@<version>.patch`, listed under `patchedDependencies` in
`pnpm-workspace.yaml` and pinned by hash in `pnpm-lock.yaml`, makes Wrangler's
asset upload find each requested file through a hash index instead of scanning
the whole asset manifest once per file. It chooses exactly the same files and
removes up to a minute of single-threaded work before uploads start. The patch
applies to one exact Wrangler version. When you upgrade Wrangler, re-create the
patch with `pnpm patch wrangler@<new version>` and `pnpm patch-commit`, or drop
it once Wrangler includes the fix; `node --test` fails while the pin and the
patch disagree, and pnpm refuses a patch it cannot apply, so the sync keeps the
previous toolchain.

To roll back a toolchain change, revert only the `package.json` and
`pnpm-lock.yaml` change: the next job reinstalls the previous pin, offline
when the local pnpm store still has it. Reverting this sync step itself does
not reinstall anything; run `corepack pnpm install --frozen-lockfile` by hand
afterwards.

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

## Search Functionality

Server-side search for Tor relay metrics without client-side JavaScript.

### How It Works

1. **Search Form** (on any page) → `/search?q=...` GET request
2. **Pages Function** (`functions/search.js`) → Loads `search-index.json`
3. **302 Redirect** → Direct to matching relay/family/AS/country page

### Supported Query Types

| Query Type | Example | Result |
|------------|---------|--------|
| Fingerprint (full) | `ABCD1234...` (40 hex) | Direct to relay page |
| Fingerprint (partial) | `ABCD12` (6-39 hex) | Direct or disambiguation |
| Nickname | `MyTorRelay` | Direct to relay page |
| AS Number | `AS24940` or `24940` | Direct to AS page |
| Country | `Germany` or `de` | Direct to country page |
| IP Address | `1.2.3.4` | Direct to relay page |
| Contact/AROI | `example.org` | Direct to contact page |
| Platform | `linux`, `freebsd` | Direct to platform page |
| Flag | `exit`, `guard` | Direct to flag page |

### CIISS Version Indicators (v1.6+ index)

Search disambiguation pages display **CIISS v2 / v3** indicators next to relay names when the operator's ContactInfo declares a `ciissversion`. v3 indicators are green; v2 indicators are grey; relays without an AROI declaration show no indicator. This requires `search-index.json` schema **v1.6+** (Allium build with [PR #207](https://github.com/1aeo/allium/pull/207) or later, which adds the per-relay `vn` field). Older indexes (≤ v1.5) continue to work unchanged with no indicators shown.

### Security Features

- **Input Validation:** Query length limit (100 chars), character allowlist
- **XSS Prevention:** All output HTML-escaped
- **Open Redirect Prevention:** Path allowlist validation
- **Security Headers:** CSP, X-Frame-Options, X-Content-Type-Options
- **ReDoS-Safe Patterns:** All regex patterns are O(n) complexity
- **Error Handling:** Generic messages to users, detailed server logs

### Requirements

The search function requires `search-index.json` to be generated by allium and deployed with the site. This is handled automatically when running allium with search index generation enabled.

---

## Architecture

The diagram below is the production request path retained through Stage 2.
Workers Static Assets publishes in parallel to it, but only its `workers.dev`
candidate and non-production rehearsal hostname are reachable.

```
┌─────────────────────────┐
│  Allium Generator       │
│  (Python + Jinja2)      │
│  ~4 min / ~21k files    │
│  + search-index.json    │
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
         │  ├─ [[path]].js (content)
         │  └─ search.js (search)  │
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

# Force backup even if done today or its frequency is off
~/allium-deploy/scripts/allium-deploy-upload-r2.sh --force-backup

# Take a DO snapshot now, even if done today or DO_BACKUP_FREQUENCY=off
~/allium-deploy/scripts/allium-deploy-upload-do.sh --remote-backup-only --force-backup

# === Other Commands ===

# Manual update (runs allium + upload)
~/allium-deploy/scripts/allium-deploy-update.sh

# View logs
tail -f ~/allium-deploy/logs/update.log

# Deploy Pages function
~/allium-deploy/scripts/allium-deploy-cfpages.sh

# Generate and inspect the route-free Workers Assets configuration only
CF_ASSETS_DIRECTORY="$HOME/metrics-output" \
  ~/allium-deploy/scripts/allium-deploy-cfassets.sh --generate-only

# Upload and verify one immutable shadow version (never promotes)
~/allium-deploy/scripts/allium-deploy-cfassets.sh --upload-only

# Inspect the bounded Stage 1/2 soak result
tail -n 5 ~/allium-deploy/logs/cfassets-shadow-summary.tsv
cat ~/allium-deploy/logs/cfassets-shadow-consecutive-successes

# Check cron status
~/allium-deploy/scripts/allium-cron-check.sh
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
├── wrangler.assets.toml.template # Route-free Workers Assets template
├── wrangler.assets.toml # Generated shadow config (gitignored)
├── wrangler.charts.toml.template # Charts-only Worker template (chart layout)
├── wrangler.charts.toml # Generated charts config (gitignored)
├── cloudflare-assets/  # Workers _headers, static 404 and chart layout overlays
├── functions/
│   ├── [[path]].js     # Pages function (multi-storage + failover)
│   └── search.js       # Search function (query → redirect)
├── workers/
│   └── search.js       # Workers /search entry point + ALLIUM_ASSETS binding
├── scripts/
│   ├── allium-deploy-install.sh      # One-time setup
│   ├── allium-deploy-update.sh       # Runs every 30 min via cron
│   ├── allium-cron-check.sh          # Verify cron is installed
│   ├── allium-deploy-upload-r2.sh    # R2 upload with backups
│   ├── allium-deploy-upload-do.sh    # DO Spaces upload with backups
│   ├── allium-deploy-upload-common.sh # Shared upload functions
│   ├── allium-deploy-prune.sh        # Remove old backups
│   ├── allium-deploy-cfpages.sh      # Deploy Pages function
│   ├── allium-deploy-cfassets.sh     # Upload route-free Worker versions
│   ├── allium-deploy-cfcharts.sh     # Charts-only Worker (chart layout)
│   ├── allium-deploy-charts-route.sh # Its zone route (chart layout)
│   ├── allium-deploy-verify-cfassets.sh # Candidate health gate
│   └── allium-deploy-verify-cfcharts.sh # Chart checks (chart layout)
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

**Automatic backups (once daily by default):**
- Local: `~/metrics-backups/backup-YYYY-MM-DD_HHMMSS/`
- R2: `r2:bucket/_backups/YYYY-MM-DD_HHMMSS/`
- DO Spaces: `spaces:bucket/_backups/YYYY-MM-DD_HHMMSS/`

`LOCAL_BACKUP_FREQUENCY`, `R2_BACKUP_FREQUENCY` and `DO_BACKUP_FREQUENCY` in
`config.env` set how often each one runs:

| Value | Behavior |
|-------|----------|
| `daily` (default) | Once per day; later runs that day skip it |
| `every-run` | On every upload run, copying the whole bucket each time |
| `off` | Never on scheduled runs; a manual forced run still takes it (see below) |

The older `DAILY_LOCAL_BACKUP`, `DAILY_R2_BACKUP` and `DAILY_DO_BACKUP`
settings still work while the new setting is unset, and each run logs a
deprecation notice. `true` there means `daily` and `false` means `every-run`,
not `off`. When both are set, the new setting wins. Any other value stops the
upload before it starts.

`--force-backup` on an upload script takes that run's backups even when they
are off or already done today. With `DO_REMOTE_BACKUP_INLINE=false` the upload
does not take the DO snapshot, so `--force-backup` there forces only the local
backup. The hourly `scripts/run-do-remote-backup.sh` takes the DO snapshot
instead: it does nothing when DO is off and takes at most one snapshot per day
otherwise. To take one now, run
`scripts/allium-deploy-upload-do.sh --remote-backup-only --force-backup`.

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

**Search not working:**
- Verify `search-index.json` exists in your output directory
- Enable search index generation in allium (see allium docs)
- Check browser console for 404 errors on `/search-index.json`
- Search requires allium to generate the index file during build

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
