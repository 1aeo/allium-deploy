# Workers Static Assets Stage 4 Readiness Record

**Scope:** Make every-build production promotion safe and testable, then
activate the Stage 4 gates without changing the production route, DNS, Pages,
DigitalOcean, R2, purge, backup, or retention architecture.

**Production hostname:** `https://metrics.1aeo.com`

**Worker:** `1aeo-metrics-assets-stage2`

**Implementation repository:** `1aeo/allium-deploy`

**Production checkout:** `/home/aeo1/allium-deploy` on `hostedopen`

**Readiness status:** Complete. The seven-day production soak is active from
`2026-07-28T02:56:35Z` and cannot complete before
`2026-08-04T02:56:35Z`.

## Activation boundary

Stage 4 starts only when a scheduled job completes all of these operations:

1. Generate one stable Allium output tree.
2. Publish the same completed tree to DigitalOcean, R2, and an immutable
   Workers Static Assets preview version.
3. Pass the complete bounded preview verifier, including three consecutive
   representative checks.
4. Persist that exact verified Worker version ID.
5. Deploy only that recorded version as `VERSION_ID@100%`.
6. Complete the scheduled job successfully with Workers Assets configured as
   a required publisher.

Merely setting the feature gates does not start the seven-day soak. The soak
clock begins at the first successful automatic production deployment recorded
in `logs/cfassets-promotion-summary.tsv` and confirmed through Cloudflare's
deployment API.

## First scheduled automatic promotion

The first enabled Stage 4 job began from the real `:45` cron entry at
`2026-07-28T02:45:01Z`. It ran corrected commit
`007e40e54c7ed69dd8b18bb93ea572b04fb5a070`, whose author and committer are
both `1aeo <github@1aeo.com>`, with these host-only controls:

```text
CF_ASSETS_ENABLED=true
CF_ASSETS_REQUIRED=true
CF_ASSETS_ALLOW_PROMOTION=true
PAGES_PURGE_URL=https://1aeo-metrics.pages.dev
```

Generation completed normally, then DO, R2, and Workers received the same
stable tree. The immutable Worker result was:

| Measurement | Result |
|---|---:|
| Verified version | `7e69dc8b-1800-430c-920d-21ab7d272800` |
| Worker upload plus verification | 488 seconds |
| Asset files | 29,473 |
| Prepared bytes | 4,451,771,979 |
| Changed assets uploaded by Wrangler | 29,074 |
| Account-level assets reused | 399 |
| Consecutive verified candidates | 13 |

The first preview attempt observed the already documented alias-propagation
hash mismatch. No promotion occurred. The next three complete attempts passed
consecutively, after which the script wrote that exact UUID to the verified
version file.

At `2026-07-28T02:56:35Z`, Wrangler deployed only
`7e69dc8b-1800-430c-920d-21ab7d272800@100%` in 0.38 seconds. The bounded
promotion row recorded exit status 0. Cloudflare's deployment API independently
reported deployment `430cce99-cb5f-4328-a78a-dee84668c909`, created at
`2026-07-28T02:56:35.052887Z`, containing exactly that one version at 100%.

Production through LAS and SJC matched the same generated output:

| Representative route | SHA-256 |
|---|---|
| `/` | `1e575b2fd1db8286362a864db4f52e26eba6d325a0ea80fc8bd0588cef3373c5` |
| `/search-index.json` | `256e12673dc58c1bcba1d1e40bb398bfbb5d6f398f9cfe70e8ebf460c34b72b0` |
| `/1aeo.com/` | `df9be5497c465b85ad503f344f7484b3382835135b5b34e58bc3fa574f630efa` |
| `/flag/running/` | `d8a8657176b1899183af426ada253162b202bdd05999eca5a281a7185a43192b` |

Both colos returned status 200, `CF-Cache-Status: HIT`, exact
`Cache-Control: public, max-age=0, must-revalidate`, and ETag
`"53e264bb5cae45a87ecaecb0477c3090"`. Production omitted both the legacy
source marker and `X-Robots-Tag`. Search returned 302, the custom missing probe
returned 404, and `GPTBot/1.0` returned 200.

The production route remained exactly
`fd0972982982407694b039c23e498258`, pattern `metrics.1aeo.com/*`, targeting
`1aeo-metrics-assets-stage2`, with request-limit fail-open disabled. DNS record
`849a2f2f09b433df5e325efb0828bf96` remained the same proxied CNAME to
`1aeo-metrics.pages.dev`.

The corrected Pages purge endpoint returned no 405 responses and deleted three
matching HTML cache entries. The complete job ended at
`2026-07-28T02:59:13Z` with exit status 0 in 852 seconds, inside the 1,800-second
cadence. The whole-job counter advanced to 13. This successful job and the
independent production checks start the Stage 4 seven-day clock at the
deployment timestamp, `2026-07-28T02:56:35Z`.

## Corrected promotion implementation

The first proposed activation commit was reviewed before any enabled cron run.
Its `--promote` branch used Bash `local` at script top level, so it would have
failed before calling Wrangler. The host gates were returned to false before
the next `:15` job, leaving the healthy Stage 3 version active while the repair
was developed and tested.

The corrected implementation provides these guarantees:

- `--upload-only` writes `CF_ASSETS_LAST_VERSION_FILE` only after the immutable
  upload and complete preview verification succeed.
- `--promote` refuses to run unless `CF_ASSETS_ALLOW_PROMOTION=true`.
- The recorded version file must exist and contain exactly one lower-case
  Cloudflare UUID-shaped version ID.
- Promotion calls the non-interactive command
  `wrangler versions deploy VERSION_ID@100% --yes` with the separate,
  route-free Workers configuration.
- A missing or malformed version file fails before Wrangler is invoked.
- Upload or preview-verification failure prevents the orchestrator from
  invoking the promotion script.
- Wrangler deployment failure propagates to the orchestrator. With
  `CF_ASSETS_REQUIRED=true`, the scheduled job fails and the prior production
  version remains active.
- Only explicit `true` or `false` values are accepted for Workers Assets
  feature gates.
- Each attempted production promotion writes one bounded row containing only
  UTC timestamp, version ID, and exit status. No request, URL, client, query,
  IP, or user-agent logging is added.

The readiness audit also found that the retained Pages purge requests had
started returning HTTP 405 after the Stage 3 Worker route was attached: POST
requests to `metrics.1aeo.com/_purge` were correctly intercepted by Workers
Static Assets rather than reaching Pages. Stage 4 now sends purge-control
requests to the canonical `1aeo-metrics.pages.dev/_purge` endpoint and supplies
absolute `metrics.1aeo.com` cache keys in every body. This purge is solely for
the dormant Pages rollback target; Worker version activation still uses no
purge.

## Failure matrix

| Failure | Promotion attempted? | Production result | Scheduled result |
|---|---|---|---|
| Generation fails | No | Previous Worker version remains active | Fail |
| Worker upload fails | No | Previous Worker version remains active | Fail when Workers is required |
| Preview verification fails | No | Previous Worker version remains active | Fail when Workers is required |
| Verified-version file missing or malformed | No Wrangler call | Previous Worker version remains active | Fail when Workers is required |
| Wrangler promotion fails | Yes, once | Cloudflare keeps the previous deployment | Fail when Workers is required |
| DO or R2 mirror fails but Worker candidate passes | Yes | Verified Worker version may become active; mirror failure is reported and retried | Existing mirror failure policy applies |
| Candidate and promotion pass | Yes, once | Exact verified version becomes active at 100% | Continue through Pages purge and bounded job summary |

There is no automatic fallback deployment to a different, floating, or
unverified version.

## Test coverage

The canonical `pnpm test` command now runs both the 14 Node tests and every
`tests/test-*.sh` behavioral suite. Promotion-specific coverage proves:

- Disabled promotion never calls Wrangler.
- A successful verified candidate invokes exactly
  `versions deploy VERSION_ID@100% --yes --config ...`.
- A failed upload or preview result never invokes the promoter.
- Missing and malformed verified-version files fail closed.
- Wrangler's nonzero status propagates unchanged.
- The bounded promotion summary records both success and failure.
- The orchestrator invokes the promoter exactly once for a successful
  candidate and never retries or chooses another version.
- Invalid boolean values are rejected.

GitHub's required `Shell Syntax` job now also runs the full behavior suite in
addition to Bash parsing and ShellCheck. This prevents a top-level Bash runtime
error from passing solely because `bash -n` accepts it.

## Stage 4 host configuration

After the corrected commit is present on both GitHub `main` and the clean
`hostedopen` checkout, the intended host-only values are:

```bash
CF_ASSETS_ENABLED=true
CF_ASSETS_REQUIRED=true
CF_ASSETS_ALLOW_PROMOTION=true
PAGES_PURGE_URL=https://1aeo-metrics.pages.dev
```

The credential and account values remain only in the ignored, mode-controlled
host configuration. They are not copied into Git or this record.

## Controls retained during the seven-day soak

- The existing exact route `metrics.1aeo.com/*` remains the production front
  door. No DNS or custom-domain migration is included.
- DigitalOcean continues synchronizing every build.
- R2 live content continues synchronizing every build.
- Pages remains deployed and current behind the route.
- The Pages purge pipeline remains active so route removal returns to a fresh
  rollback target. Its control request bypasses the production Worker route,
  while its cache keys continue naming the production hostname.
- AI and ordinary indexing remain allowed on production.
- Preview/staging copies remain `noindex`.
- No backup retention, content retention, R2 cadence, Pages retirement,
  custom-domain, cleanup, or non-Allium change is included.

## Evidence and monitoring

Bounded host evidence is retained in:

- `logs/cfassets-shadow-summary.tsv`: verified immutable candidates.
- `logs/cfassets-last-version`: exact most recently verified candidate.
- `logs/cfassets-promotion-summary.tsv`: attempted automatic promotions and
  status.
- `logs/cfassets-stage2-job-summary.tsv`: whole scheduled-job status and
  duration. The historical filename remains unchanged during the migration.
- `logs/update.log`: operational job output with no normal request logging.

The first successful automatic promotion must be checked against the
Cloudflare deployment API, production representative hashes, search,
redirects, cache/security headers, indexing behavior, and the unchanged route
and DNS state before the seven-day soak is considered active.

## Rollback during Stage 4

- Candidate failure requires no serving rollback because the prior healthy
  Worker version remains active.
- Repeated publication failures can be contained by setting
  `CF_ASSETS_ALLOW_PROMOTION=false` and `CF_ASSETS_REQUIRED=false` while
  leaving shadow verification enabled for diagnosis.
- A production-serving regression rolls back immediately by deleting only the
  exact `metrics.1aeo.com/*` Worker route and returning to the current Pages
  deployment.
- Do not use a purge as a Worker version activation or rollback mechanism.
- Do not delete Worker versions, Pages, DO, R2, or backups as part of this
  stage.

## Readiness checklist

- [x] Broken pre-activation promotion branch identified before an enabled cron
  run.
- [x] Host promotion and required gates returned to false during repair.
- [x] Exact verified-version promotion implemented without top-level Bash
  declarations.
- [x] Strict version-ID and boolean validation implemented.
- [x] Upload/verification/promotion failure semantics covered by tests.
- [x] Bounded promotion summaries implemented.
- [x] `pnpm test` includes Node and shell behavior tests.
- [x] GitHub required CI includes the complete behavior suite.
- [x] Pages rollback purge bypasses the Worker route and retains absolute
  production-host cache keys.
- [x] Corrected commit is pushed as `1aeo` and required GitHub checks pass.
- [x] `hostedopen` is clean and exactly aligned with corrected `origin/main`.
- [x] Stage 4 feature gates are enabled on the corrected checkout.
- [x] First scheduled automatic promotion succeeds and matches production.
- [ ] Seven-day production soak completes with DO/R2 every-build redundancy.

Stage 5 remains blocked until the final checklist item completes.
