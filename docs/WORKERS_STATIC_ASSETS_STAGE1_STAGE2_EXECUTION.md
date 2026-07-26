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
and search evidence, but it is deliberately excluded from the final 100-build
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
scheduled counter was reset to zero before the next cron build. All 100 final
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

## Non-production route rehearsal readiness

At `2026-07-26T20:32:56Z`, the current Cloudflare API documentation and the
installed Wrangler 4.86.0 command help were checked against the rehearsal
runbook. They agree on `POST` and `DELETE` operations under
`/zones/{zone_id}/dns_records` and `/zones/{zone_id}/workers/routes`, and on
the non-interactive deployment form
`wrangler versions deploy VERSION_ID@100% --yes`.

The exact deployment command was then run with `--dry-run` against the generated
route-free `wrangler.assets.toml`. Wrangler fetched the live deployment,
selected verified version `53164b95-f100-4289-8098-a71b92a7950a` at 100%, and
exited without creating a deployment. It also proved that the dedicated
Worker's active deployment remains the route-free bootstrap version
`2678d1f7-b756-40b5-9728-03a630cc7d4b`. The config contains only the expected
workers.dev and preview-URL settings; it has no zone route or custom domain.
The latest candidate must be re-verified and substituted for this dry-run
version immediately before the real rehearsal.

A direct read-only permission check resolved the `1aeo.com` zone successfully,
but the exact DNS-record and Workers-route list calls both returned Cloudflare
authentication error 10000. No DNS record, Worker route, deployment, or custom
domain mutation was attempted. The live rehearsal therefore remains pending
until the host's temporary Worker token is replaced with the plan's restricted
DNS Write and Workers Routes Write permissions.

## Stage 2 completion gates

- [x] Feature branch reviewed, committed, pushed, and fast-forwarded to
  production `main`.
- [x] Route-free configuration rechecked after production merge.
- [x] Sparse Pages source telemetry enabled and its failure-isolation behavior
  verified.
- [x] Scheduled shadow publication enabled with
  `CF_ASSETS_REQUIRED=false`.
- [ ] At least 100 consecutive scheduled candidate builds pass.
- [ ] No candidate exceeds the generation interval.
- [ ] No candidate hash mismatch, missing representative asset, search
  regression, or unexplained size/count growth.
- [x] Representative checks pass from both the hosted LAS path and a second
  Cloudflare colo.
- [ ] `metrics-next.1aeo.com` rehearses the exact zone-level route, TLS,
  redirects, WAF behavior, caching, search, and rollback.
- [ ] Rehearsal hostname remains `noindex`.
- [ ] Rehearsal route is removed after the rollback test, with the shadow
  `workers.dev` alias retained for review.
- [ ] Production DNS, Pages domain, and `metrics.1aeo.com` route remain
  unchanged.
- [ ] Final Stage 1–2 evidence committed for review before Stage 3.

## Evidence locations

- Approved plan: `docs/WORKERS_STATIC_ASSETS_MIGRATION_PLAN.md`
- Bounded shadow summary: `logs/cfassets-shadow-summary.tsv`
- Consecutive counter: `logs/cfassets-shadow-consecutive-successes`
- Last verified version: `logs/cfassets-last-version`
- Main update log: `logs/update.log`
- Unit/integration tests: `tests/`

The host log and counter files are runtime evidence and are intentionally not
request logs or committed credentials. The final review record will contain a
bounded aggregate of the 100-build soak rather than the full verbose upload
log.
