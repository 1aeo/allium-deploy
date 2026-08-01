# Workers Static Assets reliability remediation

## Status

The post-Stage-5 reliability remediation was activated at
`2026-08-01T09:57:20Z` from commit `efc650d547f04b66a1e039e7411a504594cd8d9a`.
Production routing, the active Worker deployment, Pages, DigitalOcean, R2,
backup cadence, and retention were not changed during activation.

The authoritative clean-window marker was restarted at
`2026-08-01T11:26:48Z` after an operational deployment invalidated the first
two-job segment. The reason and fail-closed result are recorded below. No
production route, active Worker version, Pages project, mirror policy, backup,
or retention setting changed during the restart.

Stage 6 remains blocked until both of these independent conditions pass:

1. The fresh post-fix validation window described below is clean.
2. The original seven-day production boundary,
   `2026-08-04T02:56:35Z`, has passed.

## Reason for the remediation

The production soak remained available and every failed candidate failed
closed, but it exposed two avoidable failure modes:

- Candidate checks used the persistent preview alias. Reassigning that alias
  on every upload allowed different edge locations to briefly return different
  Worker versions.
- A transport-level `curl` failure exited the verifier before its existing
  bounded attempt loop could retry. A transient Wrangler API failure also had
  no narrowly classified retry at the upload boundary.

The soak also revealed unbounded operational logging. Wrangler created a new
large debug log for every invocation and `update.log` had no size rotation.

## Implemented behavior

### Immutable candidate identity

`scripts/allium-deploy-cfassets.sh` now sets a private temporary
`WRANGLER_OUTPUT_FILE_PATH` for each upload attempt and reads the version from
Wrangler's NDJSON `version-upload` record. It requires all of the following
before candidate verification can begin:

- A syntactically valid Worker version UUID.
- A syntactically valid HTTPS `workers.dev` preview URL.
- A hostname beginning with the first eight characters of that exact version
  UUID and the configured Worker name.
- A root-only URL with no extra path.

The human-readable alias is no longer parsed or written to candidate evidence.
The bounded soak audit independently rejects an alias or a reused version URL.

### Bounded transient retries and fail-closed promotion

Wrangler uploads allow three attempts by default. A retry occurs only for
classified Cloudflare `5xx`, network, timeout, socket, DNS, internal, or
malformed-response failures. Authentication and other permanent failures stop
immediately. A zero-exit upload with missing, malformed, aliased, or mismatched
structured metadata also exhausts the same bounded retry budget.

Every representative `curl` call now converts a network/transport failure into
a failed verification attempt. The existing full check set then retries up to
its configured bound and still requires three consecutive complete passes.

No candidate writes `cfassets-last-version`, increments the consecutive
counter, or becomes eligible for promotion until upload metadata and all
representative checks pass. Exhaustion leaves the previously active production
version at 100%.

### Bounded logs

Wrangler runs with sanitized, error-level console diagnostics. Live testing
proved that Wrangler writes every debug-level message to `WRANGLER_LOG_PATH`
regardless of that console threshold, so the managed default path is
`logs/wrangler-debug-sink.log`, a guarded symlink to `/dev/null`. Actual
Wrangler errors remain in `update.log`, which rotates at 32 MiB and retains
three compressed archives. A deliberately configured real Wrangler debug file
still has an 8 MiB/two-archive bound. The compact candidate, job, promotion,
R2, and backup markers are separate and are not rotated by this mechanism.

The legacy per-command debug directory was removed only after preserving:

- The complete prior `update.log` as compressed local failure history.
- Three compressed Wrangler logs corresponding to the failed-candidate
  windows under the ignored local `logs/wrangler-failure-evidence/` directory.
- All compact TSV summaries and success markers.

No request logging, IP address, user agent, search query, or full URL logging
was added.

## Deterministic verification

The repository suite covers:

- Structured immutable URL and version parsing.
- Rejection of mutable aliases and reused version URLs.
- One transient Cloudflare `522` followed by recovery.
- Immediate stop on a permanent authentication failure.
- Bounded exhaustion of malformed structured responses.
- A network-level `curl` failure followed by verifier recovery.
- Fail-closed behavior after exhausted verifier attempts.
- Error-log and update-log rotation, compression, and archive bounds.
- Existing upload, promotion, search, R2, Pages rollback, backup, and guarded
  checkout behavior.

The complete suite passed both in the development worktree and on hostedopen
after activation.

## Live activation evidence

The first scheduled job after the remediation marker ran from
`2026-08-01T10:15:01Z` through `2026-08-01T10:35:16Z` and completed with status
zero inside the 1,800-second cadence bound. It uploaded version
`dc6753fa-ea61-4cfe-a51a-737bef2d7e07`, derived the immutable preview URL
`https://dc6753fa-1aeo-metrics-assets-stage2.ceo-8f4.workers.dev` from Wrangler's
structured output, passed all three complete preview-verification attempts,
and promoted that exact version at 100%.

The same job kept the other approved properties intact:

- The DigitalOcean hot mirror completed.
- The direct Pages rollback deployment and purge completed.
- R2 live replication skipped because the already-verified daily marker was
  current; no other publication or verification stage was skipped.
- Production root, search, missing-path, GPTBot, local-output hash,
  DigitalOcean hash, Pages rollback hash, R2 marker, and active Worker version
  checks passed in the subsequent read-only audit.

The next scheduled job ran from `2026-08-01T10:45:01Z` through
`2026-08-01T11:07:30Z`. It completed with status zero in 1,349 seconds,
verified the distinct immutable version
`de283c7f-d4c7-4d69-9ed6-3109899daec7` at
`https://de283c7f-1aeo-metrics-assets-stage2.ceo-8f4.workers.dev`, and promoted
that exact version at 100%. DigitalOcean completed in 16 minutes 50 seconds;
R2 alone skipped its already-verified daily live sync; Pages rollback remained
current. The subsequent read-only audit passed every production, mirror,
rollback, hash, AI-indexing, R2, and active-version check.

The following `:15` job uploaded and fully verified a third distinct immutable
candidate, but a Stage 6 readiness commit advanced `origin/main` while that job
was already running. The promotion process correctly rechecked repository
freshness and refused to promote because hostedopen's checkout still held the
previous commit. The whole job exited with status one and reset the counter to
zero. The previously active production Worker continued returning `200`,
search `302`, missing-path `404`, and GPTBot `200`; the unpromoted candidate
never received production traffic.

This was an operator sequencing error, not a preview, upload, verifier, or
production-serving failure. The Stage 6 commit was then fast-forwarded only
while the deployment lock was idle, the complete hosted suite passed, and
`PAGES_ROLLBACK_MAINTENANCE_ENABLED=true` was added explicitly without
changing behavior. The clean marker and counter were restarted after that
failed row, at `2026-08-01T11:26:48Z`. Existing summaries and the failure row
remain intact. Repository publication and hosted checkout changes must now be
performed together while holding the deployment lock; advancing only
`origin/main` during a job intentionally triggers the freshness guard.

The first live run also demonstrated that Wrangler's file sink receives debug
records independently of the configured console level. That 7.4 MB raw file
was preserved as a verified 1.6 MB gzip, and commit
`803240a30682a5d383553dd19e6cde986c0f2f90` changed the default file sink to a
guarded `/dev/null` symlink. The complete repository suite passed on hostedopen
after that runtime sink was installed. The next complete scheduled job left the
symlink intact, created no replacement debug file, and grew the bounded main
`update.log` only to approximately 69 KB. Main deployment errors remain
captured there.

Three read-only one-shot audits are installed in hostedopen's user crontab:

- Recovery audit: `2026-08-01T12:12:00Z`, after the first normal post-restart
  job should restore production and Pages rollback hashes.
- Smoke audit: `2026-08-01T17:05:00Z`, after enough 30-minute jobs should exist
  to satisfy the 10-job count.
- Full audit: `2026-08-02T12:05:00Z`, after more than 24 hours and at least 48
  scheduled jobs should exist.

Each audit removes only its own tagged crontab entry after running. Neither
audit can advance Stage 6 or mutate Cloudflare, mirrors, backups, cadence, or
retention.

## Fresh validation gates

Activation, and the later operational restart described above, reset only
`logs/cfassets-shadow-consecutive-successes` to zero and wrote
`logs/cfassets-remediation-start-utc`. Existing historical summaries were not
truncated or rewritten. The full audit filters every job, candidate, and
promotion by the current marker, so the invalidated segment cannot be mistaken
for part of the new clean window.

### Smoke gate

Require at least 10 consecutive scheduled jobs after the marker. Every job
must:

- Produce one unique immutable version preview URL matching its version ID.
- Complete three consecutive representative preview passes.
- Promote exactly that verified version at 100%.
- Finish successfully inside 1,800 seconds.
- Keep production, DigitalOcean, Pages rollback freshness, daily R2 mode, and
  AI indexing healthy.

The read-only command is:

```bash
scripts/run-cfassets-remediation-audit.sh --smoke
```

### Full 24-hour gate

After the smoke gate, require at least 24 clean hours and 48 scheduled jobs
from the remediation marker. Any failed job, failed promotion, candidate and
promotion mismatch, job over 1,800 seconds, or missing 30-minute scheduler slot
fails this gate even if a later 10-job streak recovers.

The read-only command is:

```bash
scripts/run-cfassets-remediation-audit.sh --full
```

The full audit also verifies production HTTP behavior and hashes, GPTBot
access, the current DigitalOcean hot mirror, the fresh direct Pages rollback
target, daily R2 configuration and marker, and that the latest verified Worker
version serves 100% of production.

Both audit modes are read-only. They cannot change DNS, routes, deployments,
Pages, mirrors, cadence, backups, or retention.

## DigitalOcean runtime follow-up

The clean-window gate intentionally retains the 30-minute whole-job limit.
DigitalOcean remains the approved every-build hot independent mirror. If the
fresh window fails only because a DigitalOcean sync crosses that limit, first
measure transfer/checker saturation and object churn from the bounded job
summaries. Do not reduce redundancy, change retention, or decouple the mirror
without a separately reviewed implementation and rollback plan.

## Path to Stage 6

If the smoke and full validation reports are clean and the original seven-day
boundary has passed, proceed with Stage 6 exactly as already approved:

1. Prepare and verify the Worker Custom Domain control-plane change.
2. Stop Pages deployment and purge work only when the custom domain passes the
   complete production health gate.
3. Keep the final Pages deployment dormant through the selected 14–30-day
   rollback window.
4. Use the previous known-good Worker version as the normal rollback target.

The Stage 6 control-plane sequence must preserve availability while replacing
the current Pages CNAME and broad Worker route:

1. Record the current DNS record, route, active Worker version, Pages custom
   domain, and direct Pages rollback URL.
2. Remove the existing `metrics.1aeo.com` Pages CNAME immediately before
   attaching `metrics.1aeo.com` as a Worker Custom Domain. Keep the existing
   Worker route during this control-plane transition.
3. Run the complete production status, behavior, hash, AI-indexing, mirror,
   rollback, and active-version checks through the new custom domain.
4. Remove the now-redundant broad Worker route only after those checks pass,
   then repeat the complete health gate.
5. Detach the custom domain from the Pages project only after the Worker Custom
   Domain is healthy. Keep the direct Pages deployment dormant for the chosen
   rollback window.

The current API token can inspect and change Worker routes/domains and DNS, but
the Pages domain endpoint currently returns authorization failure. Before
Stage 6, add the account-level Cloudflare Pages Edit permission (named Pages
Write by the API) to the existing short-lived credential without posting the
token in documentation or chat.

No Pages project deletion, backup deletion, or retention reduction is part of
this remediation or its validation.
