# Workers Static Assets Stage 3 Execution Record

**Scope:** Execute the approved migration through Stage 3 only.

**Cutover status:** Successful. `metrics.1aeo.com/*` is routed 100% to the
dedicated Workers Static Assets service.

**Observation window:** `2026-07-27T05:03:03Z` through
`2026-07-27T07:04:02Z`.

**Implementation repository:** `1aeo/allium-deploy`

**Host:** `/home/aeo1/allium-deploy` on `hostedopen`

**Worker:** `1aeo-metrics-assets-stage2`

**Production version:** `2e0e4acb-f737-411f-9e76-8affdb2d45db`

**Deployment ID:** `9037ea23-c75c-4fe1-b77a-07e50574cc34`

**Production route:** `metrics.1aeo.com/*`

**Route ID:** `fd0972982982407694b039c23e498258`

## Stage boundary and guardrails

Stage 3 changed only the production route and the deployment receiving that
route. It did not begin the Stage 4 production-promotion workflow.

- The one immutable candidate described below remains deployed at 100%.
- `CF_ASSETS_REQUIRED=false` and `CF_ASSETS_ALLOW_PROMOTION=false` remain in
  the host-only configuration.
- Scheduled builds continue uploading and verifying route-free shadow
  candidates, but do not promote them.
- The Pages project, Pages custom domain, production DNS record, DigitalOcean
  mirror, R2 mirror, and Pages purge pipeline remain intact and current behind
  the Worker route.
- DigitalOcean and R2 continue synchronizing every build.
- No R2 cadence, storage retention, or backup retention setting changed.
- No manual cache purge or Worker asset purge was run for the cutover.
- Production remains indexable, including by AI crawlers. Preview and staging
  hosts remain `noindex`.
- Normal per-request logging remains disabled. All evidence below is bounded
  control-plane state, hashes, response metadata, and scheduled-build
  summaries.

This intentional pin means the production content did not move to the four
new candidates created during the two-hour observation window. That is the
correct Stage 3 behavior: automatic promotion of each verified scheduled
candidate, including its failure semantics, is a Stage 4 change that requires
separate review.

## Selected immutable candidate

The selected candidate came from the scheduled job that began at
`2026-07-27T04:45:01Z` and completed at `2026-07-27T04:58:33Z`:

| Measurement | Result |
|---|---:|
| Whole-job exit status | 0 |
| Whole-job duration | 812 seconds |
| Within 30-minute cadence | true |
| Consecutive scheduled success | 19 |
| Worker version | `2e0e4acb-f737-411f-9e76-8affdb2d45db` |
| Worker upload plus verification | 448 seconds |
| Asset files | 29,551 |
| Prepared bytes | 4,410,189,627 |
| Stable preview alias | `allium-stage2-1aeo-metrics-assets-stage2.ceo-8f4.workers.dev` |

Before production mutation, the full preview verifier passed three consecutive
times through LAS. An independent SJC check matched the same four exact
representative hashes. The gate also passed the exact cache header, preview
`noindex`, directory and HTML redirects, custom static 404, and
version-matched search behavior.

| Representative route | Bytes | Frozen candidate SHA-256 |
|---|---:|---|
| `/` | 880,742 | `c0451e858b197ac115f8811f21a366293508f9f689f9c9b87e081fe3e5f61766` |
| `/search-index.json` | 11,909,870 | `854ec59242516a527c3cb816caaefea65ffec5c43a60a360c1c78a2778070e3c` |
| `/1aeo.com/` | 2,872,446 | `fabbcd7fd241d5fce51f334f0adbfd4af1d7d5429e263dab57f52e084022e6cd` |
| `/flag/running/` | 23,642,130 | `e31f517579f8db9d41f816555b21215fc683f2e6f13834075a9a2563690aed65` |

The full-fingerprint search input used by the gate was
`DB1629B59707F744A0C7933E56B6802786FFC317`. The candidate returned the exact
expected relay redirect.

Direct reads of the current DigitalOcean live mirror and private R2 live copy
matched all four frozen candidate hashes before cutover. This confirmed that
both independent mirrors had received the same build before production moved.

## Pre-cutover rollback snapshot

The rollback/control-plane snapshot was captured at
`2026-07-27T05:00:25Z`:

| Control | Pre-cutover state |
|---|---|
| Cloudflare zone | `1aeo.com`, zone ID `0f12270eed2413ee9af27d505035dad4` |
| Production DNS record ID | `849a2f2f09b433df5e325efb0828bf96` |
| Production DNS | Proxied `CNAME metrics.1aeo.com -> 1aeo-metrics.pages.dev`, automatic TTL |
| Existing zone Worker routes | none |
| Pages project | `1aeo-metrics` |
| Pages canonical deployment | `c22ea1d7-7b34-46fe-9f63-2a9847890034` |
| Pages domains | `1aeo-metrics.pages.dev`, `metrics.1aeo.com` |
| Pages production branch | `production` |
| Pages sparse telemetry | `SOURCE_EVENTS` -> `allium_source_events` |

Pre-cutover production also matched the four frozen candidate hashes. The
Pages rollback path showed the expected mixed cached source markers from its
existing DO-first/R2-fallback implementation: the root and index were observed
from DigitalOcean, while two nested cached responses carried R2 markers. This
was not a candidate mismatch and did not change the rollback procedure.

Rollback for Stage 3 was therefore one bounded operation: delete exact route
ID `fd0972982982407694b039c23e498258`, wait for route withdrawal to propagate,
and verify that the unchanged proxied CNAME again reached the current Pages
deployment. The DNS record and Pages custom domain were not rollback mutation
targets.

## Deployment and 100% route switch

The exact verified version was deployed at 100% with the route-free Workers
configuration. Cloudflare created deployment
`9037ea23-c75c-4fe1-b77a-07e50574cc34` at
`2026-07-27T05:02:41.579181Z`.

At `2026-07-27T05:03:03Z`, one zone route was created:

| Field | Value |
|---|---|
| Route ID | `fd0972982982407694b039c23e498258` |
| Pattern | `metrics.1aeo.com/*` |
| Worker | `1aeo-metrics-assets-stage2` |
| Request-limit fail-open | false |

No DNS, Pages, DO, R2, purge, custom-domain, or retention setting changed.

Route activation was eventually consistent across edges, as expected. The
first SJC observation already returned Workers Static Assets metadata while
the first LAS observation still returned the Pages response and its
DigitalOcean source marker. The next polling interval found both colos on the
Worker. This bounded propagation window produced no content mismatch and
completed before the formal consecutive-pass gate began.

## Production verifier

Every full production check asserted all of the following:

- Exact SHA-256 matches for the frozen root, search index, nested directory,
  and largest generated page.
- Root status 200.
- Exact `Cache-Control: public, max-age=0, must-revalidate`.
- `CF-Cache-Status: HIT` for the tested static asset.
- Stable static asset ETag `"498876eb25ac569067608d79e2ea6ff4"`.
- A matching `If-None-Match` returns 304.
- A `CF-Ray` from the expected SJC or LAS colo.
- No legacy `X-Served-From` header on the Worker-served static response.
- No production `X-Robots-Tag` header.
- Content Security Policy containing `default-src 'self'`.
- `X-Frame-Options: DENY`.
- `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: strict-origin-when-cross-origin`.
- `/1aeo.com` redirects with 307 to `/1aeo.com/`.
- `/index.html` redirects with 307 to `/`.
- A nonexistent path returns the custom static 404 with status 404.
- `/search` returns 302 to the exact version-matched relay result.
- `/search` does not add a production robots header.
- `/robots.txt` retains the pre-existing 404 behavior and does not introduce a
  crawler exclusion.
- A `GPTBot/1.0` request returns 200 rather than a WAF block.

The first local verifier draft parsed an absolute redirect location by every
colon and therefore truncated it at `https:`. The service response itself was
correct. The verifier was corrected to split a header only at its first colon
before any gate result was accepted.

## Immediate and timed production gates

After both colos converged on the Worker, the immediate gate passed three
consecutive complete verifier runs through each colo:

| Gate | SJC pass times UTC | LAS pass times UTC | Result |
|---|---|---|---|
| Immediate, pass 1 | `05:05:55` | `05:05:55` | pass |
| Immediate, pass 2 | `05:05:57` | `05:05:57` | pass |
| Immediate, pass 3 | `05:05:59` | `05:05:59` | pass |

The required timed checkpoints then repeated the complete verifier through
both colos:

| Checkpoint | SJC UTC | LAS UTC | Result |
|---|---|---|---|
| 5 minutes | `2026-07-27T05:08:25Z` | `2026-07-27T05:08:26Z` | pass |
| 15 minutes | `2026-07-27T05:18:28Z` | `2026-07-27T05:18:29Z` | pass |
| 30 minutes | `2026-07-27T05:33:32Z` | `2026-07-27T05:33:33Z` | pass |
| 60 minutes | `2026-07-27T06:03:43Z` | `2026-07-27T06:03:44Z` | pass |
| 120 minutes | `2026-07-27T07:04:01Z` | `2026-07-27T07:04:02Z` | pass |

Between full checkpoints, a lightweight root probe ran every 30 seconds. Every
emitted sample from `2026-07-27T05:08:41Z` through
`2026-07-27T07:02:48Z` returned status 200, `CF-Cache-Status: HIT`, and no
legacy source marker. No rollback condition occurred.

## Static request invocation experiment

A bounded live Wrangler tail was connected to the production deployment. The
test sent 12 valid static requests across the root, search index, and directory
paths, followed by three `/search` requests.

The tail emitted exactly the three redacted `/search` events and zero events
for the 12 valid static requests. This directly confirms the intended runtime
routing: valid assets are delivered by Workers Static Assets without invoking
Worker code, while only the narrow dynamic search route invokes the Worker.
The tail was terminated immediately after the bounded test and was not
retained as a request log.

## Scheduled builds during the gate

Four complete scheduled jobs ran after cutover. Every job exited 0, remained
inside the 30-minute cadence, refreshed the existing storage and Pages
rollback path, and uploaded and verified a new immutable shadow candidate.
Because Stage 4 was not authorized, none replaced the production deployment.

| # | Start–finish UTC | Whole job | Counter | Shadow version | Worker upload + verify | Assets | Prepared bytes |
|---:|---|---:|---:|---|---:|---:|---:|
| 20 | `05:15:01–05:31:53` | 1,012 s | 20 | `31b9e589-0f47-435b-afa1-4d6c31e5140b` | 526 s | 29,549 | 4,410,387,502 |
| 21 | `05:45:01–05:56:41` | 700 s | 21 | `568dd307-ebb8-456d-8559-dd23d2e26dc9` | 462 s | 29,601 | 4,417,108,866 |
| 22 | `06:15:02–06:26:00` | 658 s | 22 | `77a2abc5-384e-4895-90f6-83fdc86a1b01` | 414 s | 29,600 | 4,407,464,863 |
| 23 | `06:45:01–06:57:09` | 728 s | 23 | `b8f46a41-55fd-4348-b1f6-34fbdd256828` | 455 s | 29,600 | 4,407,204,366 |

After job 23, the current generated output, DigitalOcean live mirror, and
private R2 live copy matched these exact hashes:

| Representative file | Current local/DO/R2 SHA-256 |
|---|---|
| `index.html` | `d67682b9931a1feb6dd8ce5d5d3cefe03f8b08463a88a0699d3ab2b0b7ea4c4e` |
| `search-index.json` | `0a47de5e5239234e4984b6933841daaf4100808970eab2bd2c5a3f2a9b9e50da` |
| `1aeo.com/index.html` | `31551c6b1693bc2eca4db86078a66734a7553c731a182be8786cee9c9fe513ed` |
| `flag/running/index.html` | `c086d03c4342c750c89d5f0a4d2c752f564ac1bd8cfcb626d786ee9523d6b677` |

The active Cloudflare deployment still contained only
`2e0e4acb-f737-411f-9e76-8affdb2d45db@100%`. This proves that scheduled
shadow uploads did not implicitly promote or alter production.

## Final control-plane state

The final Stage 3 control-plane audit at `2026-07-27T07:04:01Z` found:

- Exactly one production route, ID `fd0972982982407694b039c23e498258`,
  pattern `metrics.1aeo.com/*`, targeting
  `1aeo-metrics-assets-stage2`.
- The production DNS record unchanged as the same proxied CNAME to
  `1aeo-metrics.pages.dev`.
- Deployment `9037ea23-c75c-4fe1-b77a-07e50574cc34` still assigning exactly
  candidate `2e0e4acb-f737-411f-9e76-8affdb2d45db@100%`.
- The Pages project, canonical deployment, custom domains, production branch,
  and sparse telemetry binding unchanged.
- `CF_ASSETS_REQUIRED=false` and
  `CF_ASSETS_ALLOW_PROMOTION=false` unchanged.
- DigitalOcean and R2 still configured for every-build synchronization.

## Stage 3 completion gates

- [x] A current immutable scheduled candidate passed the complete preview gate
  through two colos.
- [x] The candidate matched DigitalOcean and R2 before cutover.
- [x] Production DNS, Pages, routes, deployment, and representative hashes
  were captured for rollback.
- [x] The exact verified candidate was deployed at 100%.
- [x] One exact broad production route was created without changing DNS.
- [x] Both colos converged after the bounded route-propagation window.
- [x] Three consecutive immediate full production checks passed through both
  SJC and LAS.
- [x] Complete checks passed at 5, 15, 30, 60, and 120 minutes.
- [x] All intervening 30-second root health samples passed.
- [x] Production hash, redirects, search, custom 404, cache behavior, security
  headers, and indexing behavior passed.
- [x] AI crawler traffic remained allowed.
- [x] A bounded tail proved valid static requests do not invoke Worker code.
- [x] Four post-cutover scheduled jobs succeeded without implicitly promoting
  a shadow candidate.
- [x] Pages, DNS, DO, R2, purge, and retention rollback infrastructure remains
  intact.
- [x] No rollback condition occurred and no purge was used for Worker
  activation.

## Repository and post-push verification

After the execution record was fast-forwarded to the production checkout and
pushed to GitHub, the complete 14-test Node suite passed. `git diff --check`
passed, the hosted checkout was clean, and its `main` and `origin/main` refs
were aligned. The commit author and committer identity was
`1aeo <github@1aeo.com>`.

At `2026-07-27T07:12:12Z` and `07:12:13Z`, the complete production verifier
passed once more through SJC and LAS respectively. All four frozen hashes,
cache and security headers, ETag revalidation, redirects, search, custom 404,
indexing behavior, and GPTBot status still matched the accepted candidate.

The final Cloudflare API read confirmed:

- The route list contains exactly route
  `fd0972982982407694b039c23e498258`, pattern `metrics.1aeo.com/*`, targeting
  `1aeo-metrics-assets-stage2`, with request-limit fail-open disabled.
- DNS record `849a2f2f09b433df5e325efb0828bf96` remains the same proxied CNAME to
  `1aeo-metrics.pages.dev` with automatic TTL.
- The latest deployment remains
  `9037ea23-c75c-4fe1-b77a-07e50574cc34`, created by Wrangler, containing
  exactly version `2e0e4acb-f737-411f-9e76-8affdb2d45db@100%`.
- The Stage 4 gates remain disabled:
  `CF_ASSETS_REQUIRED=false` and
  `CF_ASSETS_ALLOW_PROMOTION=false`.

## Stop point before Stage 4

Stage 3 is complete, but the system is deliberately not yet in its intended
long-term every-build production-promotion mode. Production is pinned to the
verified Stage 3 candidate while scheduled jobs continue generating newer
shadow versions and keeping Pages, DO, and R2 current.

Stage 4 requires a separately reviewed implementation and activation of:

- Workers Assets becoming a required production publication target.
- Promotion of only the exact immutable version that passed the complete
  preview gate.
- Failure behavior that leaves the previous healthy version deployed when a
  candidate fails upload or verification.
- Continued every-build DO and R2 synchronization and current Pages/purge
  rollback behavior throughout the seven-day soak.
- Seven days of production monitoring before any R2-frequency, Pages,
  retention, cleanup, or non-Allium work.

No Stage 4, R2-daily, Pages-retirement, custom-domain, cleanup, retention, or
non-Allium change is included in this execution record.

### Post-Stage 3 rollback-purge correction

The Stage 4 readiness audit later confirmed that, although the Pages purge
code and secret remained configured, POST requests through
`metrics.1aeo.com/_purge` returned HTTP 405 after the Worker route became
active. This did not affect Worker content, version activation, or the Stage 3
acceptance checks, but it meant the dormant Pages cache was not being actively
purged as originally stated. Stage 4 corrects the endpoint to the canonical
Pages hostname while retaining absolute production-host cache keys. See the
[`Stage 4 readiness record`](WORKERS_STATIC_ASSETS_STAGE4_READINESS.md).
