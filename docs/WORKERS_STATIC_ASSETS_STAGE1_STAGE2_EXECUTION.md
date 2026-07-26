# Workers Static Assets Stage 1–2 Execution Record

**Scope:** Execute the approved migration through Stage 2 only.

**Production cutover:** Not authorized. `metrics.1aeo.com`, its DNS, Pages
custom domain, and production request path remain unchanged until Stage 3 is
reviewed and explicitly approved.

**Implementation repository:** `1aeo/allium-deploy`

**Host:** `/home/aeo1/allium-deploy` on `hostedopen`

**Shadow Worker:** `1aeo-metrics-assets-stage2`

**Stable preview alias:**
`https://allium-stage2-1aeo-metrics-assets-stage2.ceo-8f4.workers.dev`

## Guardrails in force

- The generated Wrangler configuration has no zone route or custom domain.
- `CF_ASSETS_ALLOW_PROMOTION=false` remains set through Stage 2.
- The scheduled Worker job uploads immutable versions and verifies their
  preview alias; it does not deploy candidates to production traffic.
- The existing Pages, DigitalOcean, R2, purge, DNS, and production request
  path remain active.
- Worker shadow failures remain non-blocking while
  `CF_ASSETS_REQUIRED=false`.
- Preview and rehearsal traffic is `noindex`; production indexing, including
  AI indexing, remains allowed.
- DO remains an every-build mirror and R2 remains an every-build mirror until
  after the separately reviewed production soak.
- No backup retention or deletion change is included.

## First full-size Stage 1 run

The isolated candidate at `~/allium-next-assets-output-20260726` measured:

| Measurement | Result |
|---|---:|
| Files exposed as assets (excludes `_headers`) | 29,353 |
| Files in the prepared tree (includes `_headers`) | 29,354 |
| Prepared tree bytes | 4,272,076,946 |
| Largest file | `flag/running/index.html` |
| Largest file bytes | 23,674,109 |
| Wrangler asset entries | 51,914 |
| New or modified assets uploaded | 29,036 |
| Assets deduplicated | 317 |
| Asset upload time | 241.95 seconds |
| Worker version upload time | 294.29 seconds |

This completed well inside the 30-minute Allium interval and below the Paid
plan's 100,000-file and 25 MiB individual-file limits.

After account-level asset deduplication, a subsequent immutable upload and the
complete three-pass health gate took 58 seconds. The bounded result was
recorded as consecutive success 1 at `2026-07-26T17:33:42Z`.

## Full preview health result

Three consecutive passes verified:

- Exact local/remote SHA-256 for `/`.
- Exact local/remote SHA-256 for `/search-index.json`.
- Exact local/remote SHA-256 for the nested `/1aeo.com/` page.
- Exact local/remote SHA-256 for `/flag/running/`, the 23,674,109-byte largest
  page.
- `Cache-Control: public, max-age=0, must-revalidate`.
- Effective preview `X-Robots-Tag: noindex`.
- Directory canonicalization with HTTP 307.
- Custom static 404 with HTTP 404.
- Version-matched dynamic search and the expected relay redirect.

Cloudflare injects its own preview `X-Robots-Tag: noindex`, which supersedes
the overlay's requested `noindex, nofollow`. `noindex` is the required control:
the shadow copy is excluded from indexing while the production hostname has no
`noindex` rule.

## First-run platform finding

A brand-new Worker with uploaded versions but no deployment record returned
Cloudflare error 1042 when a preview tried to access the Assets binding.
Enabling `workers.dev`/Preview URLs was not sufficient by itself. One explicit
bootstrap deployment was required on the dedicated route-free shadow Worker;
after that, immutable version previews and the stable alias served the version
correctly.

This bootstrap affected only `1aeo-metrics-assets-stage2.workers.dev`. It did
not add a zone route, custom domain, production DNS record, or
`metrics.1aeo.com` traffic. Normal scheduled Stage 1–2 runs do not repeat the
bootstrap or call `wrangler versions deploy`.

## Safety findings and fixes

The first full-size wrapper attempt revealed that an explicit
`CF_ASSETS_DIRECTORY` was ignored in favor of `OUTPUT_DIR`. It began scanning
`~/metrics-output` and was interrupted before completing an asset upload. It
had copied only the planned `_headers` and `404.html` overlays into that tree.

Both exact files were moved to the recoverable directory
`~/allium-stage2-recovery/accidental-output-overlay-20260726-101533`.
Read-only checks confirmed that neither exact key existed in DigitalOcean
Spaces nor R2, so no remote deletion was required. No production route or
Cloudflare deployment changed.

The fix makes `CF_ASSETS_DIRECTORY` take precedence and adds a regression test
that sets it to a different tree from `OUTPUT_DIR`. Overlay preparation now
runs synchronously before any publisher starts and is idempotent, so DO, R2,
and Workers all read one stable completed tree.

The full tree also exposed SIGPIPE exit 141 in the verifier's `sort | awk`
first-record selection under `pipefail`. The selector now consumes the full
stream and has passed against all 29,354 prepared files.

The first production-output shadow candidate then reproduced the documented
edge-propagation window: immediately after version upload, `/` matched the new
local hash while `search-index.json` briefly returned an older hash. The
verifier previously exited on that first failure despite its attempt setting.
It now permits at most 12 bounded attempts, waits 10 seconds between them, and
requires three complete consecutive passes before incrementing the soak
counter. Any later failure resets the within-version pass count.

The first Pages telemetry deployment exposed a binding-name collision during
the immediate production smoke test. Cloudflare Pages provides its own
`ASSETS` binding for the Pages static bundle. Search incorrectly treated that
binding as the Worker's version-matched Allium assets and returned
`INDEX_404`. Root and content delivery remained healthy, but `/search` returned
503. The last known-good Pages commit was redeployed immediately; three
consecutive production fingerprint searches then returned the expected 302.

The Worker binding is now named `ALLIUM_ASSETS`. Pages' built-in `ASSETS`
binding is deliberately ignored, and a regression test supplies a 404 Pages
binding while requiring search to load the external Pages index successfully.
Telemetry is redeployed only after this regression and the full production
search smoke test pass.

The live Cloudflare Pages control plane was checked again at
`2026-07-26T20:07:33Z`. The Pages Projects API reported project
`1aeo-metrics`, canonical production deployment
`c22ea1d7-7b34-46fe-9f63-2a9847890034`, environment `production`, and the
`SOURCE_EVENTS` Analytics Engine binding targeting dataset
`allium_source_events`. The telemetry tests independently prove that a
successful R2 fallback emits one bounded point, a DigitalOcean response emits
none, an all-source failure emits one point without a URL or client identity,
and a binding write failure cannot affect the content response. Normal request
logging remains disabled.

## First scheduled Stage 2 build and scheduler cadence

Manual experiment evidence was moved to dated `stage1-manual` files before the
scheduled soak began, so the scheduled counter started from zero. The first
real `:15` cron build began at `2026-07-26T18:15:01Z`, generated a fresh Allium
tree, and published the same completed output to R2, DigitalOcean, and the
route-free Workers shadow in parallel.

The Workers candidate contained 29,686 asset files and 4,657,186,619 prepared
bytes. Wrangler uploaded 29,287 changed assets, reused 399 account-level assets,
and produced version `ce63217c-27da-45ca-ad1b-5aca8c837452`. During bounded
propagation, verification attempts 1–3 observed transient representative hash
mismatches. Attempts 4–6 then passed every check, producing the required three
consecutive complete passes. The scheduled result was recorded at
`2026-07-26T18:27:01Z` in 473 seconds as consecutive success 1.

That first scheduled result remains valid upload, propagation, hash, routing,
and search evidence, but it is deliberately excluded from the final 10-build
counter. A rehearsal runbook audit found that Cloudflare `_headers` rules apply
to static assets but not to `/search` responses generated by Worker code.
Cloudflare's workers.dev preview injected its own `noindex`, masking the gap;
the future `metrics-next.1aeo.com` route would not have received that automatic
preview header. Commit `21cf65b` now adds `X-Robots-Tag: noindex, nofollow` to
Worker-generated search responses only on `metrics-next.1aeo.com` and
workers.dev hosts, while explicitly testing that `metrics.1aeo.com` receives no
such header and remains indexable.

The original scheduled row and counter were moved intact to
`logs/cfassets-stage2-20260726-prefinal-wrapper-*`, and the authoritative
scheduled counter was reset to zero before the next cron build. All 10 final
soak entries will therefore exercise both the finalized hostname-specific
indexing behavior and the scheduler-cadence correction.

The integrated run also exposed a pre-existing scheduler bottleneck unrelated
to Workers: DigitalOcean's hot-mirror sync took 50–58 minutes even when it
reported zero bytes transferred. The shared upload options forced
`--fast-list`, which recursively enumerated the retained `_backups` object tree
before applying its exclusion. Because the host cron runs at `:15` and `:45`
under a single non-blocking lock, that enumeration caused scheduled Allium
builds to be skipped and would have stretched the nominal 50-hour soak toward
six days. This is the behavior documented in rclone's
[directory-recursion filtering rules](https://rclone.org/filtering/#how-filter-rules-are-applied-to-directories):
directory pruning is available for a non-recursive `sync` only when
`--fast-list` is not used.

No retention setting or backup object was changed. A full read-only
DigitalOcean `sync --dry-run` kept the same source, destination, excludes,
comparison, and stale-object deletion semantics but omitted `--fast-list` so
rclone could prune the excluded backup directory before recursion. It exited 0
in 145 seconds. The resulting backend-specific setting defaults
`DO_RCLONE_FAST_LIST=false`; R2 retains `--fast-list` and its approximately
four-minute behavior. `DO_RCLONE_FAST_LIST=true` remains an explicit rollback
override. The option builder rejects invalid boolean values, and
`tests/test-rclone-options.sh` covers both modes and the DigitalOcean default.

This is a traversal optimization only. DigitalOcean remains an every-build hot
mirror, R2 remains an every-build mirror through the production soak, remote
and local backup cadence remains daily, retention remains unchanged, and the
full `rclone sync` stale-object comparison remains enabled.

## First finalized scheduled Stage 2 build

The first build counted toward the final-code soak started from the host's
`:45` cron entry at `2026-07-26T19:45:01Z`; no manual upload preceded it. Fresh
Allium generation completed in 3 minutes 45 seconds with search-index schema
1.6. The three publishers began together at `19:49:09Z` against the same
completed output tree.

The live DigitalOcean process omitted `--fast-list`, while the simultaneous R2
process retained it. DigitalOcean's own progress reached the full 4.324 GiB at
`19:51:49Z`, about 2 minutes 40 seconds after publisher start. Because the
parent script waits for R2 before collecting the already-finished DigitalOcean
child, its intentionally coarse aggregate log reports both storage publishers
at R2's later 4 minute 38 second completion point. No backup or retention
setting changed.

The route-free Worker upload produced version
`f747c2c0-312e-4bee-830b-2d17de468c70`. Wrangler uploaded 29,276 changed assets
and reused 399 account-level assets. The first verification attempt observed a
bounded `search-index.json` propagation mismatch; attempts 2, 3, and 4 then
passed the root, index, nested directory, largest page, headers, canonical
redirect, custom 404, and version-matched search checks consecutively.

The authoritative summary recorded the result at `2026-07-26T19:54:56Z`:

| Measurement | Result |
|---|---:|
| Worker upload plus verification | 345 seconds |
| Asset files | 29,675 |
| Prepared bytes | 4,656,928,482 |
| Consecutive finalized scheduled successes | 1 |
| Total generation, publishing, verification, and purge | 12 minutes 13 seconds |

The complete job ended at `19:57:14Z`, leaving 17 minutes 47 seconds before the
next scheduled slot. Immediate production checks still returned HTTP 200 for
the root and `/index.html` from `digitalocean-spaces`, and a full-fingerprint
search returned the expected HTTP 302 relay redirect. Production responses had
no `X-Robots-Tag`; no production DNS, route, custom domain, or request path
changed.

The same finalized alias was then checked independently through SJC and LAS.
SJC matched the exact local SHA-256 for the root, search index, `/1aeo.com/`,
and the largest `/flag/running/` page; search returned the version-matched relay
redirect. Both colos returned `CF-Cache-Status: HIT` and preview `noindex`.
An SJC conditional request using the returned asset ETag produced HTTP 304 with
the same ETag and `Cache-Control: public, max-age=0, must-revalidate`. A request
using the `GPTBot/1.0` user agent returned HTTP 200 rather than a WAF block and
remained `noindex` on the non-production alias. The temporary zone route will
repeat these checks on `metrics-next.1aeo.com`, including the stricter
Worker-generated `noindex, nofollow` value that workers.dev itself normalizes
to `noindex`.

## Non-production route rehearsal result

At `2026-07-26T20:32:56Z`, the current Cloudflare API documentation and the
installed Wrangler 4.86.0 command help were checked against the rehearsal
runbook. They agree on `POST` and `DELETE` operations under
`/zones/{zone_id}/dns_records` and `/zones/{zone_id}/workers/routes`, and on
the non-interactive deployment form
`wrangler versions deploy VERSION_ID@100% --yes`.

The exact deployment command was first run with `--dry-run` against the
generated route-free `wrangler.assets.toml`. After the token was restricted to
the documented Account / Workers Scripts / Edit, Zone / DNS / Edit, Zone /
Workers Routes / Edit, and Zone / Zone / Read permissions, live list calls for
the DNS-record and Workers-route endpoints both succeeded. The preflight found
no `metrics-next.1aeo.com` record and no zone Worker route.

At `2026-07-26T22:32:53Z`, immutable version
`efc84e15-6228-48fd-954c-16dcfce437bf` was reverified against the stable local
output and deployed at 100% only on the dedicated
`1aeo-metrics-assets-stage2` Worker. The route-free configuration itself was
not changed. The rehearsal then created one temporary proxied `A` record for
`metrics-next.1aeo.com` at reserved address `192.0.2.0` and one exact
`metrics-next.1aeo.com/*` route to that Worker. No production record, Pages
domain, route, or hostname was mutated.

Initial record creation exposed expected DNS propagation behavior: the hosted
recursive resolver briefly alternated between NXDOMAIN, the originless
placeholder, and Cloudflare anycast. The gate therefore required three
consecutive public DNS/TLS requests serving the exact root hash, then pinned
the resulting Cloudflare edge address for content verification so transient
recursive-cache state could not be mistaken for a Worker failure. This did not
bypass TLS, the hostname route, or Cloudflare; it removed only repeated DNS
resolution from the remaining bounded checks.

The full route verifier passed three consecutive times from LAS. A separate
SJC run matched the same exact SHA-256 values:

| Representative route | SHA-256 |
|---|---|
| `/` | `7bdc557cdc876db8d0368b87f9cad2a211a7f21279cb258e69646d2bb2ff4451` |
| `/search-index.json` | `cb122b8a115d4b1eef582ba79bf1f86d71af7a2c8766cfcac6ccc5c70e2d2132` |
| `/1aeo.com/` | `32250494b6ebb952d2c26b867d1029bb9921cc329c3a3294afcf0d8be3d56e90` |
| `/flag/running/` | `2df8d535344b3aec2dfb0b7095859399e743839e68e2fc5118789c92a02ea0c3` |

Both colos returned HTTP 200 for browser and `GPTBot/1.0` user agents, the
custom missing probe returned 404, `/index.html` returned the expected 307
canonical redirect, and server-side search returned the version-matched 302
relay redirect. Static and Worker-generated search responses returned exact
`X-Robots-Tag: noindex, nofollow`; production continued to omit that header.
The intended security headers and `CF-Ray` were present. Two static requests
returned `CF-Cache-Status: HIT`, the exact
`Cache-Control: public, max-age=0, must-revalidate`, and a stable ETag; a
matching `If-None-Match` request returned 304. No purge was run before or after
the rehearsal.

Rollback deleted the exact route ID and confirmed its absence through the API.
The first immediate pinned-edge request still served the Worker, proving route
withdrawal is eventually consistent rather than instantaneous. The final gate
therefore polled until that same edge stopped serving the Worker asset, then
deleted only the exact temporary DNS record and confirmed its absence. A final
pre/post comparison found production DNS, Pages project and canonical
deployment state, all Worker routes, and representative production status,
hashes, redirects, and indexing headers byte-for-byte unchanged. The
`workers.dev` alias remains available for review. Bounded evidence is retained
at `/home/aeo1/stage2-route-rehearsal-20260726T223253Z`; duplicate source files
and failed-attempt scratch directories were removed.

## Complete scheduled-job evidence

The first two finalized runs proved total end-to-end durations of 12 minutes 13
seconds and 14 minutes 37 seconds, but the original bounded TSV recorded only
the Worker upload-plus-verifier child duration. The original counter also reset
on a Worker child failure but could not see an earlier generator or storage job
failure. Both runs remain valid because their complete logs were inspected and
proved successful and below the 30-minute interval.

Commit-time tests now cover one additional bounded runtime record:
`logs/cfassets-stage2-job-summary.tsv` receives exactly one row at process exit
with start and finish UTC timestamps, original exit status, total duration,
cadence result, and resulting shadow counter. With Workers shadow publishing
enabled, any nonzero scheduled-job exit or total duration over the configured
1,800-second interval atomically resets the consecutive counter to zero. A
successful job at or below the interval preserves the verifier-managed count.
The recorder preserves the original process exit status and adds only one
aggregate log line; it does not collect requests, URLs, clients, or response
bodies. It does not alter generation, asset preparation, search, storage,
purging, routing, DNS, or production traffic.

The read-only `pnpm audit:cfassets-soak` command performs the repeatable gate
audit over those two bounded files and the authoritative counter. It selects
only the current consecutive suffix after any earlier reset, checks sequential
counters and unique Worker versions, correlates each candidate verification
timestamp with its complete job, requires real `:15`/`:45` scheduled starts
without a missed slot, enforces successful sub-1,800-second jobs, checks the
100,000-file platform ceiling, and flags adjacent file-count or prepared-byte
changes above 10% for investigation. `--require-complete` makes the command
fail until the configured target (10 by default) is reached. The audit is
read-only and cannot upload, deploy, purge, route, or reset the streak.

The original soak proposal required 100 consecutive builds, approximately 50
hours. After four finalized builds had exercised cached and fresh inputs,
bounded upstream API failures, multiple edge-propagation orderings, and both
fast and slow DigitalOcean tails, the user reduced the formal gate to 10 builds
(approximately five hours). Ten is sufficient for the narrow deployment-
practicality question before a reversible route change; it is not presented as
strong evidence about rare long-term failures. Under the simple independent-
failure rule of three, zero failures in 100 samples gives a rough 95% upper
bound near 3%, while zero in 10 gives a rough bound near 30%. Residual risk is
instead bounded by the exact non-production route-and-rollback rehearsal,
keeping Pages immediately recoverable, retaining every-build DO and R2 copies,
and deferring any R2 cadence reduction until after the later seven-day
production soak. The first four valid builds remain in the same consecutive
segment; changing this evidence threshold does not change runtime code and does
not reset them.

## Stage 2 completion gates

- [x] Feature branch reviewed, committed, pushed, and fast-forwarded to
  production `main`.
- [x] Route-free configuration rechecked after production merge.
- [x] Sparse Pages source telemetry enabled and its failure-isolation behavior
  verified.
- [x] Scheduled shadow publication enabled with
  `CF_ASSETS_REQUIRED=false`.
- [ ] At least 10 consecutive scheduled candidate builds pass.
- [ ] No candidate exceeds the generation interval.
- [ ] No candidate hash mismatch, missing representative asset, search
  regression, or unexplained size/count growth.
- [x] Representative checks pass from both the hosted LAS path and a second
  Cloudflare colo.
- [x] `metrics-next.1aeo.com` rehearses the exact zone-level route, TLS,
  redirects, WAF behavior, caching, search, and rollback.
- [x] Rehearsal hostname remains `noindex`.
- [x] Rehearsal route is removed after the rollback test, with the shadow
  `workers.dev` alias retained for review.
- [x] Production DNS, Pages domain, and `metrics.1aeo.com` route remain
  unchanged.
- [ ] Final Stage 1–2 evidence committed for review before Stage 3.

## Evidence locations

- Approved plan: `docs/WORKERS_STATIC_ASSETS_MIGRATION_PLAN.md`
- Bounded shadow summary: `logs/cfassets-shadow-summary.tsv`
- Consecutive counter: `logs/cfassets-shadow-consecutive-successes`
- Last verified version: `logs/cfassets-last-version`
- Main update log: `logs/update.log`
- Bounded route-rehearsal evidence:
  `/home/aeo1/stage2-route-rehearsal-20260726T223253Z`
- Unit/integration tests: `tests/`

The host log and counter files are runtime evidence and are intentionally not
request logs or committed credentials. The final review record will contain a
bounded aggregate of the 10-build soak rather than the full verbose upload log.
