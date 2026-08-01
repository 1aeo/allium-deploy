# Workers Static Assets reliability remediation

## Status

The post-Stage-5 reliability remediation was activated at
`2026-08-01T09:57:20Z` from commit `efc650d547f04b66a1e039e7411a504594cd8d9a`.
Production routing, the active Worker deployment, Pages, DigitalOcean, R2,
backup cadence, and retention were not changed during activation.

An operational deployment invalidated the first two-job segment, so the marker
was restarted at `2026-08-01T11:26:48Z`. Recovery then exposed a separate
direct-Pages cache-key mismatch described below. Commit
`e83b42c404bebd6386a50150fc6daacf2fc1b7d0` corrected that mismatch, the
deployed Pages rollback function passed a live cache/purge trial, and the
clean-window marker was restarted at `2026-08-01T12:02:27Z` with a counter of
zero.

Five subsequent jobs were clean. The sixth completed every publication and
promotion successfully, but a 26-minute 7-second DigitalOcean sync made the
whole job 1,926 seconds. The fixed 1,800-second cadence gate correctly rejected
that row and reset the counter. Commit
`635572771c89b2b20a67944c9ae7cffb2b87a779` added the bounded DigitalOcean
request-rate remediation described below. Its first scheduled trial completed
successfully, but left too little cadence margin. Commit
`92630c461a847ff98645da4155c7aaba5eb4b1c2` then isolated DigitalOcean
transfers onto small HTTP/1.1 connections while preserving the request cap.
The current authoritative marker is `2026-08-01T16:14:14Z`. Its first normal
scheduled job completed in 1,071 seconds and the tenth completed at
`2026-08-01T21:04:25Z`. The immediate smoke audit passed 10 of 10 with zero
errors. No production route, active Worker service, mirror policy, backup, or
retention setting changed during these restarts.

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

The exact candidate that had already passed its immutable preview gate,
`cc748779-ed28-43eb-869a-ebed3aee1d42`, was manually promoted at
`2026-08-01T11:33:42Z` while holding the deployment lock. This restored the
Worker, local output, and DigitalOcean mirror to the same build without
pretending the manual recovery was a scheduled-job success. The marker moved
to `2026-08-01T11:35:40Z` and the counter remained zero.

That recovery audit found that the direct `pages.dev` rollback URL could still
serve the previous cached hashes even after the Pages purge loop reported
success with zero deletions. The old Pages Function used the incoming request
origin as its cache key. A direct Pages read therefore used a `pages.dev` key,
while the purge body correctly named production `metrics.1aeo.com` URLs and
deleted a different key. This did not affect Worker production traffic, but it
made direct rollback freshness impossible to prove until the unrelated
30-minute HTML TTL expired.

Commit `e83b42c404bebd6386a50150fc6daacf2fc1b7d0` adds a validated
`CACHE_KEY_ORIGIN` generated from `SITE_URL`. Direct Pages reads and
production-host purge requests now address the same canonical cache entries;
malformed optional configuration safely falls back to the request origin. A
unit test proves both the shared key and fallback behavior. The complete
25-test JavaScript suite and every shell integration test passed on hostedopen
before the Pages function was deployed at `2026-08-01T12:00:15Z`.

The bounded live trial then proved the deployed behavior for `/` and
`/search-index.json`:

- Both first reads were `MISS`, served from the DigitalOcean hot mirror, and
  matched the current generated SHA-256 values.
- Both second reads were `HIT` with the same current hashes.
- One authenticated purge naming the two production URLs returned HTTP `200`,
  `success=true`, `requested=2`, `purged=2`, and no errors.
- Both post-purge reads returned `MISS` and still matched the current hashes.

The trial completed at `2026-08-01T12:01:50Z`. It proves the existing purge
works without doubling the URL list or adding extra Pages Function
invocations. The clean marker was then reset to
`2026-08-01T12:02:27Z`, ensuring no pre-correction build can satisfy the new
gate at that point. The preceding normal job, from `2026-08-01T11:45:01Z` through
`2026-08-01T11:56:40Z`, had otherwise succeeded in 699 seconds, verified and
promoted version `d59addaf-9c7e-44b0-ae8b-59e8358e0e22`, and demonstrated
normal recovery from the guarded refusal; it is intentionally outside the
final clean window.

The first ordinary job after the final marker ran from
`2026-08-01T12:15:01Z` through `2026-08-01T12:33:21Z`. It completed with status
zero in 1,100 seconds, inside the 1,800-second cadence limit. R2 alone skipped
its already-verified daily live sync; DigitalOcean finished its every-build
mirror in 8 minutes 8 seconds. The Worker phase uploaded and verified the
unique immutable version `22d316bb-6fbb-413a-b5b5-9a1647e8caba` at
`https://22d316bb-1aeo-metrics-assets-stage2.ceo-8f4.workers.dev` in 752
seconds, passed three consecutive complete check sets, and promoted that exact
version at 100% with status zero. The retained Pages loop deleted one actual
cached HTML key out of 29,213 requested URLs rather than reporting zero for
every key.

The read-only audit at `2026-08-01T12:33:34Z` found exactly one expected
failure: the smoke count was only 1 of 10. Production root, search, missing
path, GPTBot, generated hashes, DigitalOcean hashes, direct Pages hashes,
daily R2 configuration and marker, and the exact active Worker version all
passed. This job is the first row in the authoritative final window.

The first live run also demonstrated that Wrangler's file sink receives debug
records independently of the configured console level. That 7.4 MB raw file
was preserved as a verified 1.6 MB gzip, and commit
`803240a30682a5d383553dd19e6cde986c0f2f90` changed the default file sink to a
guarded `/dev/null` symlink. The complete repository suite passed on hostedopen
after that runtime sink was installed. The next complete scheduled job left the
symlink intact, created no replacement debug file, and grew the bounded main
`update.log` only to approximately 69 KB. Main deployment errors remain
captured there.

The first five ordinary rows after the Pages cache correction completed in
1,100, 729, 844, 868, and 831 seconds. Each row promoted its exact immutable
candidate, retained the DigitalOcean every-build mirror and Pages rollback
target, skipped only the already-current R2 daily live replication, and kept
production healthy. The sixth row, from `2026-08-01T14:45:01Z` through
`2026-08-01T15:17:07Z`, also exited zero and promoted exact version
`145412d2-c21d-4560-91d9-9cf8f5ee4b8e` at 100%. Its DigitalOcean upload,
however, took 26 minutes 7 seconds and the whole job took 1,926 seconds. The
counter therefore reset to zero exactly as designed; the necessarily
overlapping `:15` scheduler slot could not start a second deployment.

The DigitalOcean trace showed no integrity or publication failure. The same
approximately 4 GiB and 29,000-object payload had completed in as little as 3
minutes 12 seconds, while the failed-cadence run repeatedly fell below 1
MiB/second. At the existing 56 transfers and 80 checkers, a fast run averaged
about 151 completed files/second before counting the separate PUT, HEAD, LIST,
and comparison operations. DigitalOcean recommends managing request patterns
above roughly 150 operations/second, and rclone documents a transaction-rate
limiter for provider throttling.

Commit `635572771c89b2b20a67944c9ae7cffb2b87a779` therefore adds a
DigitalOcean-only `--tpslimit=120 --tpslimit-burst=1`. It deliberately keeps
the 56 transfer workers, 80 checkers, every-build sync, stale-object deletion,
post-upload integrity HEAD, retry policy, backup cadence, and retention
unchanged. R2 receives an explicit unlimited default, so its behavior is also
unchanged. Invalid rate or burst settings fail before rclone runs. The complete
25-test JavaScript suite and every shell integration test passed both locally
and on hostedopen. Hostedopen runs rclone 1.72.0, which exposes both limiter
flags.

The first capped trial ran from `2026-08-01T15:45:02Z` through
`2026-08-01T16:13:13Z`. It exited zero, promoted its exact verified Worker
candidate, and kept R2, Pages, DigitalOcean, and production healthy. The
DigitalOcean phase nevertheless required 21 minutes 27 seconds and the whole
job required 1,691 seconds. That technically met the 1,800-second gate but
left only 109 seconds before the next scheduler slot, which is not adequate
margin for a 48-job acceptance window.

Live transport inspection explained why the request cap alone was
insufficient. With HTTP/2 enabled, rclone used one established connection for
the 56 transfer workers while CPU, memory, disk, and network capacity on
hostedopen remained idle. The transfer rate repeatedly fell below 1 MiB/second
without a logged `429` or `503`. DigitalOcean's performance guidance recommends
several small parallel connections, and rclone 1.72.0 exposes
`--s3-disable-http2` for this S3 transport behavior.

Commit `92630c461a847ff98645da4155c7aaba5eb4b1c2` adds a validated generic
`RCLONE_S3_DISABLE_HTTP2` option and enables it only for DigitalOcean by
default through `DO_RCLONE_DISABLE_HTTP2=true`. R2 retains HTTP/2 and its
unlimited transaction-rate default. DigitalOcean still uses 56 transfers, 80
checkers, the 120-transaction/second cap and burst one, every-build mirroring,
stale-object deletion, post-upload integrity verification, and the existing
retry policy. Invalid boolean values fail before rclone runs. The complete
repository suite passed locally before deployment and again on hostedopen at
the exact deployed commit.

The first normal HTTP/1.1-isolated job ran from
`2026-08-01T16:15:01Z` through `2026-08-01T16:32:52Z`. It opened 77 observed
established transfer connections rather than one. DigitalOcean completed the
same approximately 4 GiB, 29,000-object every-build mirror in 12 minutes 2
seconds: 9 minutes 25 seconds faster than the immediately preceding capped
HTTP/2 trial. The whole job completed in 1,071 seconds, 10 minutes 20 seconds
faster, leaving 729 seconds of scheduler margin. It uploaded and passed three
complete immutable-preview checks for version
`9ab14a1b-fe6b-4b4b-8fd8-28d28d6e6112`, promoted that exact version at 100%,
skipped only the already-current daily R2 live sync, and completed the retained
Pages deployment and purge.

The immediate read-only audit at `2026-08-01T16:33:23Z` passed production root
`200`, search `302`, missing-path `404`, GPTBot `200`, generated-output hashes,
DigitalOcean hashes, direct Pages rollback hashes, daily R2 configuration and
marker, and the exact active Worker version. Its only expected failure was the
incomplete count: one of ten required post-marker jobs. This is the first row
of the authoritative replacement window.

The second normal job ran from `2026-08-01T16:45:02Z` through
`2026-08-01T17:04:22Z`. DigitalOcean completed in 13 minutes 22 seconds, the
whole job completed in 1,160 seconds with 640 seconds of cadence margin, and
the counter advanced to two. The distinct immutable candidate
`c9f2a48a-5783-4932-881d-4f5ff4850fda` passed all three complete preview
checks and was promoted at 100%. The audit at `2026-08-01T17:04:54Z` again
passed every live production, mirror, rollback, R2, hash, AI-indexing, and
active-version check. Its only incomplete condition was the expected two-of-ten
count. Across the first two isolated-connection jobs, the DigitalOcean mirror
took 12 minutes 2 seconds and 13 minutes 22 seconds; neither job missed a slot.

The remaining eight smoke-window jobs also exited zero, finished inside the
1,800-second cadence limit, used distinct version-specific preview URLs, and
promoted exactly their verified versions at 100%. The tenth job was a realistic
full-build stress case: it mirrored 4.150 GiB across 29,254 changed files to
DigitalOcean in 12 minutes 51 seconds, completed the whole job in 1,164
seconds, and retained 636 seconds before the next scheduler slot. Across all
ten jobs, total duration ranged from 1,071 to 1,178 seconds and the Worker
upload-and-verification phase ranged from 387 to 516 seconds. Prepared outputs
contained 29,541–29,743 assets and 4,285,750,937–4,517,268,979 bytes; the
largest adjacent changes were 0.674% by file count and 5.390% by bytes.

The read-only smoke audit at `2026-08-01T21:05:05Z` passed 10 of 10 with zero
errors. It confirmed ten unique immutable version preview URLs and all ten
successful cadence-bounded job rows. Production root `200`, search `302`,
missing-path `404`, GPTBot `200`, generated-output hashes, DigitalOcean hot-
mirror hashes, direct Pages rollback hashes, daily R2 configuration and
`2026-08-01` success marker, and the latest verified Worker version at 100%
all passed. This completes the post-fix smoke gate but does not substitute for
the independent 24-hour/48-job audit.

Two replacement read-only one-shot audits are installed in hostedopen's user
crontab from the current marker:

- Smoke audit: `2026-08-01T21:35:00Z`, after enough 30-minute jobs should exist
  to satisfy the 10-job count. The immediate audit already passed; this
  unattended run remains installed as an independent confirmation.
- Full audit: `2026-08-02T16:35:00Z`, after more than 24 hours and at least 48
  scheduled jobs should exist.

Each audit removes only its own tagged crontab entry after running. Neither
audit can advance Stage 6 or mutate Cloudflare, mirrors, backups, cadence, or
retention.

## Fresh validation gates

Activation and each explicitly recorded restart described above reset only
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
DigitalOcean remains the approved every-build hot independent mirror. The
live transport now combines the 120-transaction/second limiter with
DigitalOcean-only HTTP/1.1 connection isolation. The first job recovered 729
seconds of scheduler margin, but the new 10-build and 24-hour window must prove
that result across complete changing builds. If a later job still crosses the
limit, preserve the failed evidence and reassess the cap or a redundancy-
preserving decoupling design before any architectural change. Do not reduce
redundancy, change retention, disable integrity checks, or decouple the mirror
without a separately reviewed implementation and rollback plan.

References:

- [DigitalOcean Spaces performance best practices](https://docs.digitalocean.com/products/spaces/concepts/best-practices/)
- [DigitalOcean Spaces limits](https://docs.digitalocean.com/products/spaces/details/limits/)
- [rclone transaction-rate limiting](https://rclone.org/docs/#tpslimit-float)
- [rclone S3 options](https://rclone.org/s3/)

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

Stage 6 now keeps two existing least-privilege credentials path-scoped. Worker
Custom Domain, DNS, and route requests use the Worker/DNS credential; only the
Pages domains API uses the separate Pages deployment credential. No token is
stored in Git or emitted by the tool. The read-only preflight at
`2026-08-01T12:09:45Z` authenticated both API paths and validated the exact
control-plane shape. Its only blockers were the fixed seven-day boundary and
the intentionally incomplete fresh smoke/24-hour window. A successful Pages
`GET` proves current API access but is not by itself a destructive permission
test; live execution still requires the reviewed Pages Edit scope and the
explicit hostname confirmation.

No Pages project deletion, backup deletion, or retention reduction is part of
this remediation or its validation.
