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

## Stage 2 completion gates

- [ ] Feature branch reviewed, committed, pushed, and fast-forwarded to
  production `main`.
- [ ] Route-free configuration rechecked after production merge.
- [ ] Sparse Pages source telemetry enabled and its failure-isolation behavior
  verified.
- [ ] Scheduled shadow publication enabled with
  `CF_ASSETS_REQUIRED=false`.
- [ ] At least 100 consecutive scheduled candidate builds pass.
- [ ] No candidate exceeds the generation interval.
- [ ] No candidate hash mismatch, missing representative asset, search
  regression, or unexplained size/count growth.
- [ ] Representative checks pass from both the hosted LAS path and a second
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
