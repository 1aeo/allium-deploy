# Workers Static Assets Stage 4 Readiness Record

**Scope:** Make every-build production promotion safe and testable, then
activate the Stage 4 gates without changing the production route, DNS, Pages,
DigitalOcean, R2, purge, backup, or retention architecture.

**Production hostname:** `https://metrics.1aeo.com`

**Worker:** `1aeo-metrics-assets-stage2`

**Implementation repository:** `1aeo/allium-deploy`

**Production checkout:** `/home/aeo1/allium-deploy` on `hostedopen`

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
- [ ] Corrected commit is pushed as `1aeo` and required GitHub checks pass.
- [ ] `hostedopen` is clean and exactly aligned with corrected `origin/main`.
- [ ] Stage 4 feature gates are enabled on the corrected checkout.
- [ ] First scheduled automatic promotion succeeds and matches production.
- [ ] Seven-day production soak completes with DO/R2 every-build redundancy.

Stage 5 remains blocked until the final checklist item completes.
