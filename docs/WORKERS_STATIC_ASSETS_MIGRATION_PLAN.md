# Allium Workers Static Assets Migration Plan

**Status:** Approved plan; Stages 1–3 are complete; Stage 4 remains blocked on
review

**Approved:** 2026-07-26

**Production site:** `https://metrics.1aeo.com`

**Implementation repository:** `1aeo/allium-deploy`

**Production checkout:** `/home/aeo1/allium-deploy` on `hostedopen`

**Generator checkout:** `/home/aeo1/allium`

Stage 1–2 measurements, safety findings, soak counters, and route-rehearsal
evidence are tracked in
[`WORKERS_STATIC_ASSETS_STAGE1_STAGE2_EXECUTION.md`](WORKERS_STATIC_ASSETS_STAGE1_STAGE2_EXECUTION.md).

The production cutover, two-hour gate, bounded invocation experiment, and
post-cutover control-plane state are tracked in
[`WORKERS_STATIC_ASSETS_STAGE3_EXECUTION.md`](WORKERS_STATIC_ASSETS_STAGE3_EXECUTION.md).

## Decisions that apply to every stage

- Allium is the priority. Do not migrate any non-Allium project until Allium has completed its rollout and billing-validation stages.
- Keep AI crawling and indexing enabled on production. Do not block AI bots merely to reduce request volume. Preview and staging hostnames must be `noindex, nofollow` so they do not create duplicate indexed sites.
- Keep the architecture serverless. Do not add a $24 Droplet or another always-on server.
- Make Cloudflare Workers Static Assets the production serving layer.
- Keep DigitalOcean Spaces synchronized after every successful Allium build as the hot independent mirror.
- Reduce the R2 live content synchronization to once daily only after the Workers production cutover and soak succeed.
- Preserve the existing R2, DigitalOcean, and local backup retention policies for now. Do not delete backups or shorten retention without separate approval.
- Do not perform a normal cache purge after a Workers Static Assets version deployment. The cache experiment proved that version activation replaces still-fresh content without a purge.
- Use immutable Worker version previews, health gates, promotion, and rollback rather than activating an unverified upload.
- Perform the initial production cutover at 100%, not 50/50. Keep the current Pages deployment fresh and available behind the Worker route as the immediate rollback target during the production soak.
- Do not add per-request logs. Persist only rare non-primary-source or total-failure events, plus bounded deployment summaries.
- Do not put DigitalOcean or R2 into the normal request path for valid static assets. An external `fetch()` invokes billable Worker code and adds origin latency; Workers Static Assets delivery does neither.

## Codebase and files

All implementation work belongs in [1aeo/allium-deploy](https://github.com/1aeo/allium-deploy), deployed at:

`/home/aeo1/allium-deploy` on `hostedopen`

The Allium generator in `/home/aeo1/allium` remains unchanged. It continues generating `~/metrics-output` at `:15` and `:45` through the existing cron unless a later, separately reviewed requirement genuinely belongs in the generator.

Primary files and planned responsibilities:

| File | Planned responsibility |
|---|---|
| `scripts/allium-deploy-update.sh` | Add Workers Assets to the existing parallel publication jobs; later make Workers the required production target and schedule R2 daily |
| New `scripts/allium-deploy-cfassets.sh` | Generate Workers configuration, upload a version without promoting it, return preview/version information, and optionally promote |
| New `scripts/allium-deploy-verify-cfassets.sh` | Preview health gate, hashes, headers, routing, search, and multi-colo checks |
| New `wrangler.assets.toml.template` | Separate Workers Static Assets configuration; it does not replace the existing Pages configuration during migration |
| New `cloudflare-assets/_headers` | Security and caching headers copied into the generated output before Workers upload |
| `functions/search.js` and `functions/_shared.js` | Refactor reusable search logic into a Workers entry point while retaining Pages compatibility during migration |
| New `workers/search.js` | Workers entry point for `/search`; accesses the version-matched `search-index.json` through the assets binding |
| `scripts/allium-deploy-upload-r2.sh` | Later add a daily live-content sync schedule distinct from the existing daily backup controls |
| `scripts/allium-deploy-upload-common.sh` | Shared scheduling/marker and verification helpers |
| `config.env.example` | Document feature gates, worker names, preview alias, R2 schedule, and promotion policy |
| Host-only `config.env` | Actual account/project settings; remains uncommitted |
| `README.md` | Update architecture, deployment, rollback, backup, and cost documentation |
| New files under `tests/` | Shadow-mode safety, no-production-route guarantee, health gating, promotion, rollback, search parity, and daily R2 retry behavior |

The existing Pages files remain active until the cleanup stage:

- `functions/[[path]].js`
- `functions/search.js`
- `scripts/allium-deploy-cfpages.sh`
- `wrangler.toml.template`
- `purge_cdn()` in `scripts/allium-deploy-update.sh`

The implementation pins Wrangler `4.86.0` and pnpm `10.34.5`, which are
compatible with `hostedopen`'s Node.js 20 runtime and remain above
Cloudflare's minimum versions for Workers Assets, Preview URLs, and the Paid
100,000-static-asset limit. Wrangler `4.110.0` and pnpm 11 were rejected during
the host test because their toolchain requires Node.js 22; the host is not
being upgraded as an incidental part of this migration.

## Completed prerequisite experiment and measured evidence

The required staging experiment is complete. Production was not changed.

### Full-build practicality

| Measurement | Result |
|---|---:|
| Stable Allium output | 29,695 generated files plus `_headers` |
| Fresh isolated Allium output | Approximately 29,349 files including `_headers` |
| Output size | Approximately 4.2 GiB |
| Largest file | 23,674,109 bytes, approximately 22.58 MiB |
| Cloudflare Workers Paid file limit | 100,000 assets per version |
| Cloudflare individual asset limit | 25 MiB |
| First cold full deployment | 7 minutes exactly |
| Fresh isolated Allium generation | 2 minutes 56 seconds |
| Realistic fresh deployment | 5 minutes 45 seconds |
| Sequential generation plus deployment | 8 minutes 41 seconds |
| Two-file deployment | 48–50 seconds total |
| Two-file asset upload portion | Under 1 second |
| Full preview-only version creation with already-uploaded assets | 47 seconds |

The first cold deployment found 29,687 new or modified assets and reused 8 already-uploaded assets. Asset upload took 370.95 seconds, the Worker upload completed in 417.41 seconds, and the total measured command took 420 seconds.

The fresh isolated Allium build was generated separately from production output. Comparing it to the prior build found:

- 313 files unchanged
- 29,035 files different
- 1 file only in the new output
- 348 files only in the old output
- 98.9% of the new files changed

Cloudflare found 29,031 new or modified assets and reused 317. Asset upload took 298.89 seconds, the Worker upload completed in 342.30 seconds, and the total command took 345 seconds. This is the realistic deployment measurement because nearly the entire Allium output changes on each build.

### Static routing and no-purge cache behavior

The exact Workers Static Assets deployment verified:

- Root and directory indexes return the correct content.
- Directory canonicalization works.
- A missing URL returns the custom static `404.html` with status 404.
- Normal pages receive `Cache-Control: public, max-age=0, must-revalidate`.
- A controlled TTL route receives the configured TTL.
- Static responses include Cloudflare cache status and asset ETags where applicable.
- No Pages Function is involved in valid static delivery.

The decisive cache test used a dedicated path with a deliberately stronger five-minute TTL:

1. Version D was confirmed as a Cloudflare `HIT` with `Cache-Control: public, max-age=300, must-revalidate`.
2. Only that HTML file was changed to version E.
3. No purge was issued.
4. The new version deployment completed in 48 seconds.
5. Version E was returned four seconds after the Wrangler CLI completed.
6. The response remained `CF-Cache-Status: HIT`.
7. Roughly four minutes remained before version D's browser TTL could have expired.

This proves that Worker version activation changes the asset mapping and does not require a normal build purge. Production HTML and JSON will use the safer default `max-age=0, must-revalidate` behavior rather than the experimental five-minute TTL.

### Preview health gate and propagation finding

One transient inconsistency occurred only after the first cold deployment was activated directly: an immediate request for `search-index.json` briefly returned 404 from one request, even though another hash request succeeded. About one minute later, five repeated requests all returned 200 with the correct body, size, hash, ETag, and cache status.

This does not invalidate the deployment method, but it requires a preview-first promotion gate. The final experiment therefore used `wrangler versions upload` without production promotion. It produced a version-specific preview and a stable alias. The preview returned exact SHA-256 matches for:

- `/`
- `/search-index.json`
- `/torservers.net/`
- `/flag/running/`, the approximately 22.58 MiB largest file

The same four hashes were verified through Cloudflare SJC and LAS colos. This validates the planned `versions upload -> preview health gate -> versions deploy` workflow.

Cloudflare references:

- [Workers Static Assets billing and limitations](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/)
- [Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
- [Static Asset headers](https://developers.cloudflare.com/workers/static-assets/headers/)
- [Versions and deployments](https://developers.cloudflare.com/workers/versions-and-deployments/)
- [Preview URLs](https://developers.cloudflare.com/workers/versions-and-deployments/preview-urls/)

## Stage 1 — Add Workers Assets in parallel with zero production traffic

This is the first implementation stage.

After each existing Allium generation:

1. Copy the version-controlled `cloudflare-assets/_headers` file into `~/metrics-output`.
2. Exclude `_headers` from DO and R2 object synchronization. Workers parses it as configuration and does not expose it as an asset; it does not need to become a public Spaces object.
3. Start the following publication jobs concurrently:
   - Cloudflare Workers version upload
   - DigitalOcean live sync
   - Existing R2 live sync
4. Keep the current Pages deployment, origin order, cache, purge, and `metrics.1aeo.com` routing unchanged.

The Workers job runs:

`wrangler versions upload --preview-alias allium-candidate`

It must not run `wrangler deploy`, `wrangler versions deploy`, attach a production route, attach a production custom domain, or modify production DNS during this stage.

Implementation finding: a brand-new Worker with uploaded versions but no
deployment record returned Cloudflare error 1042 when its preview accessed the
Assets binding. A one-time bootstrap deployment was therefore required on the
dedicated route-free `1aeo-metrics-assets-stage2.workers.dev` service before
scheduled shadow publishing began. This bootstrap did not attach a zone route,
custom domain, production DNS record, or `metrics.1aeo.com` traffic. It is a
service-initialization prerequisite, not candidate promotion; normal scheduled
Stage 1–2 runs continue to obey the prohibition above and use only
`wrangler versions upload` plus preview verification.

### Stage 1 configuration

Add explicit feature gates such as:

- `CF_ASSETS_ENABLED=true`
- `CF_ASSETS_PROMOTE=false`
- `CF_ASSETS_WORKER_NAME=1aeo-metrics-assets`
- `CF_ASSETS_PREVIEW_ALIAS=allium-candidate`
- `CF_ASSETS_REQUIRED=false` during shadow mode
- A bounded preview verification attempt count and timeout
- No production route in the shadow configuration

The generated Workers configuration remains separate from the Pages `wrangler.toml`. Generate it from `wrangler.assets.toml.template` without dirtying tracked files or embedding account credentials in Git.

Workers Assets configuration includes:

- Approximately 29,350 assets from `~/metrics-output`
- `not_found_handling = "404-page"`
- Existing directory behavior with `html_handling = "auto-trailing-slash"`
- Default HTML/JSON behavior: `public, max-age=0, must-revalidate`
- Cloudflare-generated content-hash `ETag`
- No long immutable TTL for non-fingerprinted assets
- Long immutable caching only for assets that are genuinely content fingerprinted
- Security headers from `_headers`
- `X-Robots-Tag: noindex, nofollow` on preview/staging hostnames only
- Production AI indexing remains allowed

### Stage 1 orchestration and failure semantics

The integration in `scripts/allium-deploy-update.sh` is initially non-blocking:

- A Workers shadow failure is recorded and surfaced.
- A Workers shadow failure does not prevent the current DO/R2 publication from succeeding.
- It does not increment the existing production consecutive-failure counter if the current Pages system remains healthy.
- It uses a separate shadow failure counter and deployment log.
- The current Pages purge still runs after DO/R2 because Pages remains production.
- The existing `flock` and twice-hourly cron remain unchanged.
- All publication processes read the completed, stable output only after generation succeeds.

### Search during Stage 1

Search is tested in the same candidate version but does not replace production search yet.

The Workers search entry point must:

- Handle only `/search` and the exact required search route variants.
- Reuse the current validation, redirect, escaping, security, and schema-compatibility logic.
- Read the version-matched `search-index.json` through the dedicated
  `env.ALLIUM_ASSETS.fetch()` binding rather than R2 or an external HTTP
  fetch. The dedicated name must not collide with Pages' built-in `ASSETS`
  binding while both implementations coexist.
- Ensure search code and index belong to the same uploaded Worker version.
- Preserve all current query behavior and redirects.
- Avoid running Worker code for valid static assets.
- Return the configured static 404 behavior for unrelated missing navigation requests.

Cloudflare serves matching assets without invoking Worker code. Requests requiring dynamic behavior can use the assets binding:

- [Static Asset bindings](https://developers.cloudflare.com/workers/static-assets/binding/)
- [Static Asset Worker script routing](https://developers.cloudflare.com/workers/static-assets/routing/worker-script/)
- [Static Site Generation and custom 404 behavior](https://developers.cloudflare.com/workers/static-assets/routing/static-site-generation/)

### Stage 1 acceptance gates

Every shadow build must verify:

- Worker upload completes within the 30-minute generation interval.
- Root page status and SHA-256 match local output.
- `search-index.json` status, content length, and SHA-256 match local output.
- A representative directory index matches local output.
- The largest generated file matches local output.
- Directory canonicalization and redirects match production.
- The custom static 404 returns 404, not 200.
- HTML and JSON have the intended cache behavior.
- Preview responses contain `noindex`.
- Search results match the Pages search function across a fixed test corpus.
- No production route, domain, or DNS record is changed.

The search parity corpus includes:

- Full fingerprints
- Partial fingerprints
- Nicknames
- AS numbers and AS names
- Country names and country codes
- IP addresses
- Contact and AROI values
- Platforms
- Flags
- Ambiguous matches and disambiguation pages
- Invalid characters
- Excessively long input
- Missing results
- Open-redirect attempts
- Older and newer supported search-index schema versions

## Stage 2 — Shadow soak and production-route rehearsal

Workers publishing must soak without production traffic for at least 10
consecutive scheduled builds, approximately five hours. This is a deployment-
practicality gate: it proves repeated full-tree generation, upload, propagation,
and verification fit the 30-minute interval before the separately reversible
production stage. It is not intended to estimate a rare long-term failure rate.
The initial 100-build proposal would have covered approximately 50 hours and,
under an independent-failure model, zero failures would place a rough 95%
upper bound near 3% per build; 10 failures-free samples place that rough bound
near 30%. The user accepted the smaller sample because Stage 2 also requires
the exact route-and-rollback rehearsal, Pages remains the immediate rollback,
and every-build DO and R2 redundancy remains through the later seven-day
production soak. Shadow builds may continue beyond 10 while other gates are
pending, but 10 is the formal Stage 2 soak threshold.

Success requires:

- No failed candidate uploads.
- No hash mismatches.
- No missing representative assets.
- No deployment exceeding the 30-minute interval.
- Search parity across every candidate version.
- No unexplained version-size or file-count growth.
- No production route mutations.
- At least three consecutive successful representative checks per version.
- Checks from two Cloudflare colos, initially SJC locally and LAS from `hostedopen`.

Before production, create a non-production hostname such as `metrics-next.1aeo.com` and rehearse the exact zone-level route, TLS, redirects, WAF behavior, caching, search, and rollback procedure. This hostname remains `noindex, nofollow`.

The rehearsal is intentionally a zone route, not a Worker Custom Domain, so it
exercises the same routing primitive planned for production without touching
`metrics.1aeo.com`:

1. Snapshot the existing `metrics.1aeo.com` DNS record, Pages custom-domain
   state, Workers routes, current production representative hashes, and current
   Stage 2 Worker deployment.
2. Re-run the full verifier against the latest immutable preview alias and
   deploy that exact verified version at 100% only on the dedicated
   `1aeo-metrics-assets-stage2` Worker. Do not deploy a floating or unverified
   version and do not change the route-free Wrangler configuration.
3. Create a temporary proxied `A` record for `metrics-next.1aeo.com` pointing to
   the reserved originless address `192.0.2.0`. Cloudflare requires a proxied
   DNS record before a zone route can invoke a Worker. Universal SSL covers
   this first-level subdomain.
4. Add only the exact route `metrics-next.1aeo.com/*` targeting the dedicated
   Stage 2 Worker. Refuse to continue if that hostname already has a different
   DNS record or route. Never add, edit, or delete a `metrics.1aeo.com` record,
   route, or Pages custom domain during Stage 2.
5. Require TLS and three consecutive complete verifier passes for the root,
   `/index.html`, `search-index.json`, `/1aeo.com/`, the largest generated page,
   canonical redirects, custom 404, and version-matched server-side search.
   Exact SHA-256 values must match the verified local output.
6. Request a static asset twice and verify `ETag`,
   `Cache-Control: public, max-age=0, must-revalidate`, and Cloudflare's
   `CF-Cache-Status`. Send a matching `If-None-Match` request and verify
   revalidation behavior. Do not purge either before or after activation.
7. Verify security headers, a Cloudflare `CF-Ray`, benign browser traffic, and
   an AI-crawler user agent all reach the rehearsal site without a WAF block.
   Verify `X-Robots-Tag: noindex, nofollow` on both static responses and every
   Worker-generated `/search` response. The production hostname must continue
   to omit `X-Robots-Tag` so AI and ordinary indexing remain allowed.
8. Repeat representative checks through `hostedopen` and a second Cloudflare
   colo. Record only bounded response metadata and hashes; do not enable normal
   request logging.
9. Rehearse rollback by deleting the exact temporary route, confirming via the
   API that it is absent and that the placeholder hostname no longer serves the
   Worker asset, then deleting only the exact temporary DNS record. Confirm the
   DNS record is absent, retain the workers.dev preview alias, and re-run the
   production root and search checks.
10. Compare the post-rehearsal production DNS, Pages custom-domain, route, and
    representative-hash snapshot with the pre-rehearsal snapshot. Any
    difference fails Stage 2 and must be resolved before review.

The temporary credential must have Account / Workers Scripts / Edit plus Zone /
DNS / Edit, Zone / Workers Routes / Edit, and Zone / Zone / Read, restricted to
the one account and the `1aeo.com` zone. Cloudflare references:

- [Workers routes](https://developers.cloudflare.com/workers/configuration/routing/routes/)
- [Workers Routes API](https://developers.cloudflare.com/api/resources/workers/subresources/routes/)
- [Universal SSL hostname coverage](https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/limitations/)
- [Static Asset response headers](https://developers.cloudflare.com/workers/static-assets/headers/)

### Sparse historical source telemetry

During this stage, add the requested historical evidence to the existing Pages Function:

- Write one Workers Analytics Engine point only if Pages serves from R2, serves from the final failover origin, or every source fails.
- Do not write an event for an ordinary DO response.
- Do not write events for normal static requests once Workers Assets is production.
- Store source, status category, route category, and Cloudflare colo.
- Do not store full URLs, queries, IP addresses, or user agents.
- Do not await the Analytics Engine write.
- Keep the existing `X-Served-From` response header for immediate diagnostics.
- Retain the dataset for Cloudflare's normal three-month Analytics Engine retention period.

This resolves the evidence gap behind the statement: "We cannot prove it never happened because `X-Served-From` was never persisted in historical request logs." It does so without creating massive logs.

Cloudflare references:

- [Analytics Engine pricing](https://developers.cloudflare.com/analytics/analytics-engine/pricing/)
- [Analytics Engine limits and retention](https://developers.cloudflare.com/analytics/analytics-engine/limits/)

## Stage 3 — Switch production 100%, not 50/50

Use a gated 100% route switch.

A 50/50 Pages/Workers rollout is not recommended for two independent reasons:

1. The two sides are different products: the current Cloudflare Pages project and the new Workers service. Workers gradual deployments split traffic between two versions of the same Worker; they do not natively split traffic between Pages and Workers. A Pages/Workers split would require another front-door Worker or a paid load-balancing layer, adding complexity and recreating a Worker invocation on every request.
2. Cloudflare gradual deployments randomly select a version per request unless version affinity is configured. A user can receive HTML from one version and a linked asset or JSON file from another. Allium changes approximately 98.9% of files per build and does not consistently use content-fingerprinted filenames, making version skew especially undesirable.

Cloudflare explicitly documents this version-skew behavior:

- [Gradual deployments](https://developers.cloudflare.com/workers/versions-and-deployments/gradual-deployments/)
- [Version affinity](https://developers.cloudflare.com/workers/versions-and-deployments/gradual-deployments/version-affinity/)

Version affinity through IP, cookie, or Transform Rule would add machinery solely to make a less-useful 50/50 migration safe. Preview validation plus an immediate route rollback is simpler and provides stronger consistency.

### Production cutover procedure

1. Generate the current Allium output.
2. Upload an immutable Worker version without promoting it.
3. Pass all preview health gates from two colos.
4. Confirm DO and R2 have also received the build.
5. Record the current Pages deployment, DNS, and route state for rollback.
6. Add a broad Worker route for `metrics.1aeo.com/*`, placing the new Worker in front of the existing proxied Pages hostname.
7. Send 100% of production traffic to the validated Worker version.
8. Leave the Pages project, Pages custom domain, DNS, DO mirror, R2 mirror, and current purge pipeline intact behind the route.
9. If health checks fail, remove the Worker route so requests return immediately to the still-current Pages deployment.

Worker routes are designed to sit in front of an existing proxied hostname. Cloudflare selects the most-specific matching route:

- [Workers routes](https://developers.cloudflare.com/workers/configuration/routing/routes/)
- [Routes and domains](https://developers.cloudflare.com/workers/configuration/routing/)

### Production cutover gate

Verify:

- Production root page
- Search index
- Representative directory page
- Largest generated file
- Server-side search and redirects
- Static 404
- Cache and security headers
- Directory and HTML canonical redirects
- `robots.txt` and production indexing behavior
- No accidental `noindex` on production
- No widespread new Worker invocations for valid static assets
- Exact representative SHA-256 matches

Require three consecutive passes before declaring the cutover successful. Continue active checks at 5, 15, 30, 60, and 120 minutes.

Rollback immediately on:

- Sustained 5xx responses
- Hash mismatch
- Widespread asset or navigation 404s
- Search regression
- Incorrect cache or security headers
- Unexpected Worker invocation volume indicating static requests are reaching code
- Route or TLS inconsistency

Do not purge during or after Workers version activation. The completed cache experiment proved version activation replaces still-fresh content without a purge.

### Stage 3 execution status

Stage 3 completed successfully on `2026-07-27`. The exact immutable version
`2e0e4acb-f737-411f-9e76-8affdb2d45db` is deployed at 100%, and route
`metrics.1aeo.com/*` sends production traffic to the dedicated Workers Static
Assets service. Three consecutive immediate checks and the 5-, 15-, 30-, 60-,
and 120-minute checks passed through both SJC and LAS. The full bounded result
is in the
[`Stage 3 execution record`](WORKERS_STATIC_ASSETS_STAGE3_EXECUTION.md).

Stage 4 has not started. Production remains pinned to that verified candidate;
scheduled builds upload and verify new shadow candidates without promoting
them because `CF_ASSETS_REQUIRED=false` and
`CF_ASSETS_ALLOW_PROMOTION=false` remain set. Pages, its purge pipeline, DO,
and R2 remain current behind the route, and DO/R2 continue every build.

## Stage 4 — Production soak with all current redundancy retained

Keep production on Workers for seven days before changing R2 frequency.

During this soak:

- Cloudflare Workers Assets publishes every build.
- DigitalOcean remains synchronized every build.
- R2 remains synchronized every build.
- Existing Pages remains deployed and current.
- Existing Pages purges continue so route removal remains a rollback to fresh content.
- No backup retention changes or deletions occur.
- AI indexing remains allowed.
- Monitor static asset delivery, search invocations, 404s, deployment duration, route health, R2/failover telemetry, DO/R2 synchronization, and Cloudflare billing.

The Workers deployment becomes a required success at this stage:

- A failed candidate is never promoted.
- The previous deployed Worker version continues serving production.
- Preview health-gate failure blocks promotion but does not take down the current version.
- DO remains the per-build independent mirror.
- R2 remains recovery storage.
- Failed mirror uploads retry on the next cron run.
- Alerts distinguish publication failure from production-serving failure.

Do not automatically replace a healthy Worker version merely because a DO or R2 mirror upload failed. Cloudflare candidate success plus preview health controls Worker promotion; mirror failures are reported and retried separately.

## Stage 5 — Change R2 live replication to daily

Only after the production soak passes should the live R2 sync move from every build to daily.

The existing `DAILY_R2_BACKUP` flag controls backup creation only. It does not stop `upload_content` from synchronizing the live R2 bucket every 30 minutes. Therefore, add separate behavior:

- `R2_CONTENT_SYNC_INTERVAL=daily`
- `logs/last-r2-content-sync-date`
- A successful-sync marker written only after upload and verification
- Retry on every subsequent cron run if the daily attempt fails
- A manual force-sync option for recovery or pre-maintenance use
- Object count, total size, and representative-hash validation before marking the daily synchronization successful

The daily schedule must work as follows:

1. If today's live R2 synchronization marker exists, skip the live R2 content sync.
2. If the marker is missing, run the existing backup steps according to their independent settings.
3. Synchronize the current generated output to the live R2 location.
4. Verify the result.
5. Write the daily marker only after all required R2 steps succeed.
6. If any required step fails, leave the marker absent so the next twice-hourly Allium run retries.

Steady state after this stage:

- Workers Static Assets: every build, production
- DigitalOcean Spaces: every build, hot independent mirror
- R2 live copy: once daily
- R2 remote recovery snapshot: continues according to the existing backup policy
- Local and DO backup behavior: unchanged
- No retention deletion

### R2 operation and storage math

Approximately 29,350 live objects synchronized daily produces about:

`29,350 * 30 = 880,500` live-object writes per 30-day month.

However, the existing daily R2 remote recovery snapshot also copies approximately 29,350 objects. Keeping both creates approximately:

`29,350 * 2 * 30 = 1,761,000` live-plus-backup object mutations per 30-day month.

After the one-million Class A allowance and Cloudflare billing-unit rounding, this likely produces approximately $4.50 per month in R2 Class A charges, plus small list or verification usage. This is still dramatically below the current approximately $153 Class A invoice line.

Keeping daily snapshots without retention changes means storage continues growing by approximately 4.2 GiB per day, or roughly 126 GiB per 30-day month. At R2 Standard storage pricing, that is roughly $1.89 more full-month storage cost for every additional retained 126 GB, with first-month average accrual depending on daily billing. DigitalOcean backup storage grows similarly and is billed according to Spaces storage allowances and overage rates.

This continuing growth is why retention deserves a later inventory and restore-value review. It is not authorization to delete or shorten retention.

References:

- [R2 pricing](https://developers.cloudflare.com/r2/pricing/)
- [DigitalOcean Spaces pricing](https://docs.digitalocean.com/products/spaces/details/pricing/)

## Stage 6 — Retire the Pages request path and purge machinery

After at least seven stable production days, and preferably after keeping the old Pages rollback target for 14–30 days:

1. Stop deploying or purging the Pages catch-all.
2. Remove production use of:
   - `functions/[[path]].js`
   - `/_purge`
   - `PURGE_SECRET`
   - `CACHE_TTL_HTML`
   - `CACHE_TTL_STATIC`
   - `purge_cdn()` and the approximately 29,000-URL purge loop
3. Preserve the old implementation in Git history or a clearly documented legacy location until the migration is fully accepted.
4. Move `metrics.1aeo.com` from a Worker route over the Pages hostname to a Worker Custom Domain so the Worker becomes the permanent origin.
5. Detach the Pages custom domain only after the Worker Custom Domain passes the full production health gate.
6. Keep the last Pages deployment temporarily without production traffic, then archive the Pages project after the rollback window.
7. Make Worker version rollback, rather than Pages route removal, the normal long-term rollback method.
8. Continue DO every-build and R2 daily redundancy.

The Pages purge remains during the production soak solely to keep the old rollback target fresh. It is removed only when Pages is no longer the active rollback target.

## Stage 7 — Security, experiment cleanup, and billing validation

After the migration is accepted:

- Revoke the temporary API token that was pasted into chat.
- Replace it with a fresh least-privilege automation token.
- Store the automation token only in the existing mode-`600` Cloudflare credential file on `hostedopen`.
- Remove the experiment Worker `1aeo-metrics-assets-staging`.
- Remove only the staging Pages preview deployment; do not remove the production Pages project before its rollback window closes.
- Remove the following explicit remote experiment directories only after confirming they are not referenced:
  - `~/allium-assets-staging`
  - `~/allium-full-assets-staging-complete`
  - `~/allium-next-assets-output-20260726`
- Remove local scratch under `/Users/joey/tor/1aeo/tmp/allium-assets-staging`.
- Add simple rotation for `logs/cfassets-deploy.log`; retain summaries and failure records, not request logs.
- Update README architecture and disaster-recovery instructions.
- Compare one complete Cloudflare and DigitalOcean billing cycle to the June baseline.

No cleanup command may delete a broad directory, bucket, backup collection, or production project. Resolve and verify every cleanup target explicitly before removal.

### Expected initial steady-state cost

Based on the June Cloudflare and DigitalOcean invoices and current published prices:

- Workers Paid: approximately $5 per month
- Existing R2 storage: approximately $25 per month, continuing to grow with retained snapshots
- Daily live R2 copy plus daily recovery copy: likely approximately $4.50 Class A per month
- Very small R2 Class B usage because R2 is no longer in the normal serving path
- Expected Cloudflare total initially around $35–40 per month rather than $195.83
- DigitalOcean should remain near its storage/base cost and may fall as normal production-serving bandwidth moves away from DO
- No $24 Droplet or other always-on compute is added

Workers Static Assets is cheaper than either DO or R2 as the primary serving layer because valid static requests are free and unlimited. DO remains the per-build mirror because it has no per-object operation charge. R2 remains the daily recovery copy because its operation pricing makes every-build replication comparatively expensive.

The original cost estimate is a forecast, not a promise. Validate it against a complete post-migration billing month and retain the measured invoice comparison in the repository.

## Stage 8 — Other projects and retention review

Only after Allium is stable and its first complete billing cycle is understood:

- Apply the tested Workers Static Assets pattern to non-Allium projects.
- Prioritize projects by Worker invocation volume and storage cost.
- Inventory DO and R2 backup ages, counts, sizes, restore usefulness, and monthly growth.
- Test restoration from both DO and R2.
- Define recovery-point and recovery-time objectives before proposing retention changes.
- Propose retention changes separately.
- Make no retention changes or deletions without explicit approval.

## Milestone tracking checklist

- [x] Workers Paid enabled.
- [x] Full 29,000-plus-file cold deployment completed.
- [x] Fresh isolated build and realistic 98.9%-changed deployment completed.
- [x] Static routing, directory handling, custom 404, and headers verified.
- [x] Still-fresh five-minute cached asset update verified without purge.
- [x] Preview-only full version upload and multi-colo hash gate verified.
- [x] Stage 1 code reviewed, tested, committed, and deployed in shadow-only mode.
- [x] At least 10 consecutive shadow builds pass.
- [x] Non-production hostname route rehearsal passes.
- [x] Production candidate passes preview health gate.
- [x] Production switches 100% to the Worker route.
- [x] Immediate two-hour production checks pass.
- [ ] Seven-day production soak passes with current R2 frequency unchanged.
- [ ] R2 live synchronization changes to daily with retry-safe markers.
- [ ] Pages rollback window completes.
- [ ] Pages catch-all and purge path retire.
- [ ] Worker Custom Domain becomes the permanent origin.
- [ ] Temporary API token is revoked and replaced.
- [ ] Explicit experiment artifacts are removed safely.
- [ ] One complete post-migration billing cycle is compared with June.
- [ ] Non-Allium migrations begin only after the Allium gates above pass.

## Rollback principles

- Before the initial production cutover, production rollback means no action because Pages remains active.
- During the Worker-route production soak, rollback means removing the broad Worker route and returning traffic to the still-current Pages deployment.
- Never promote a candidate that fails preview checks.
- Never replace a healthy active Worker version because a mirror upload failed.
- After Pages retirement, rollback means deploying the previous known-good Worker version.
- Keep version IDs, local build hashes, deployment timestamps, and representative verification results in bounded deployment summaries.
- Do not use a purge as a normal rollback or freshness mechanism.
- Do not delete DO, R2, Pages, Worker versions, or backups as part of rollback unless a separately approved incident procedure specifically requires it.

## Final target architecture

```text
Allium generator (twice hourly)
        |
        +--> Workers version upload
        |       |
        |       +--> immutable preview
        |       +--> multi-colo hash/search/header gate
        |       +--> promote verified version to production
        |
        +--> DigitalOcean Spaces live mirror (every build)
        |
        +--> R2 live recovery copy (daily after production soak)
                |
                +--> existing daily recovery snapshot policy

Production requests
        |
        +--> valid static asset: Workers Static Assets, no Worker code invocation
        |
        +--> /search: narrow Worker logic using version-matched assets binding
        |
        +--> missing navigation: static 404 behavior

Recovery
        |
        +--> previous Worker version rollback
        +--> DigitalOcean per-build mirror
        +--> R2 daily copy and retained snapshots
```
