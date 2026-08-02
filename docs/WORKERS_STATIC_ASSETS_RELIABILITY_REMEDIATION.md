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
The resulting window began at `2026-08-01T16:14:14Z`. Its first normal job
completed in 1,071 seconds, its smoke audit passed, and it reached 15 clean
scheduled jobs. A separately discovered temporary-credential expiration then
invalidated that acceptance window. The replacement credential was installed
and verified without changing its reviewed scope. Three recovery jobs then
passed, but a fourth exposed a separate mid-job branch-movement race. Commit
`d0580c4da88c481f36606753276da31ff335b879` now pins one clean, current deploy
checkout SHA before generation and uses that immutable identity through
upload and promotion. DigitalOcean remote-backup decoupling then restored the
required scheduler margin. A later Allium generator update exposed stale
unsupported sort pages left in the reused output tree; the failed generator
never reached any publisher. Allium commit
`e829a5dd2f2431c1d09ef744cb4a5cc97970c9ca` removes those exact obsolete files
before discovery validation. The current authoritative marker is
`2026-08-02T10:04:15Z`. No production route, active Worker service, mirror
policy, backup cadence, or retention setting changed during these restarts.

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

### Immutable deployment-checkout snapshot

The scheduled orchestrator now fetches `origin/main` after its guarded pulls,
requires the deploy checkout to be current and clean, and captures the exact
40-character `HEAD` before generation. It exports that SHA only to child work
for the current job. Worker upload and promotion independently require the
checkout to remain clean and to match that pinned SHA.

This separates two different safety questions:

- At job start, the selected checkout must match the fetched, reviewed branch
  tip. A stale, dirty, malformed, or unavailable checkout fails before the
  expensive generator and publishers run.
- After generation starts, a later `origin/main` commit belongs to the next
  scheduled job. It does not invalidate the immutable checkout and output
  snapshot already being published. Any local checkout mutation still fails
  closed before Worker upload or promotion.

Direct/manual Worker upload or promotion has no parent-job pin, so it retains
the stricter live `origin/main` fetch and equality check. The change therefore
does not allow an operator to deploy an arbitrary stale checkout.

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

Two replacement read-only one-shot audits were scheduled in hostedopen's user
crontab from the current marker:

- Smoke audit: the unattended run started at `2026-08-01T21:35:01Z`, passed
  with 11 clean jobs, 11 unique immutable previews, and zero errors, then
  removed only its own tagged crontab entry. All production, mirror, rollback,
  R2, AI-indexing, hash, and active-version checks passed.
- Full audit: the original `2026-08-02T16:35:00Z` one-shot was removed after
  the later credential-expiry failure invalidated this window.

Each audit removes only its own tagged crontab entry after running. Neither
audit can advance Stage 6 or mutate Cloudflare, mirrors, backups, cadence, or
retention.

### Credential-expiry invalidation and recovery

The temporary Worker/DNS/routes credential expired at
`2026-08-01T23:59:59Z`. The first affected job began at `23:45:01Z`, completed
its immutable candidate verification before expiration, and then failed closed
when production promotion crossed the expiration boundary. Nine subsequent
scheduled jobs rejected the expired credential at the Worker upload boundary.
All ten rows exited nonzero and kept the counter at zero. No unverified version
received production traffic. The last verified Worker remained available while
DigitalOcean and Pages continued receiving their required every-build updates;
the read-only audit correctly reported that production no longer matched the
latest generated output.

A replacement least-privilege credential was installed atomically outside a
deployment at `2026-08-02T04:37:59Z`. It is stored only in the existing
mode-`600` ignored credential file. Token verification, account discovery,
zone DNS, Worker routes, Worker Custom Domains, and the complete Stage 6
control-plane read set passed without printing or committing the secret. The
replacement still requires the separately stored Pages credential for Pages
API paths. Because the replacement credential was supplied through an exposed
channel, the planned Stage 7 rotation remains required.

The credential-recovery marker and counter were reset at
`2026-08-02T04:38:59Z`; historical summaries and failure rows were preserved.
The first three normal recovery jobs passed independently. The first two were:

- `04:45:01Z`–`05:03:00Z`: status zero in 1,079 seconds, DigitalOcean in 12
  minutes 13 seconds, and exact verified version
  `f50fa97d-c7f5-4f06-b6e8-ea4d8916e30f` promoted at 100%.
- `05:15:01Z`–`05:34:25Z`: status zero in 1,164 seconds, DigitalOcean in 13
  minutes 2 seconds, and distinct exact verified version
  `e01a4dfb-7961-4abb-ab26-0fe343a61dc1` promoted at 100%.

The third ran from `05:45:01Z` through `06:02:34Z`, exited zero in 1,053
seconds, and promoted exact verified version
`a2ab2833-b4f4-4808-af06-b0ffa6de247d` at 100%.

The immediate audit after the first recovery job passed production root,
search, missing-path, GPTBot, generated hashes, DigitalOcean hashes, direct
Pages hashes, the August 2 R2 daily marker, and exact active-version checks.
Its sole expected incomplete condition was one of ten new jobs.

### Mid-job branch movement and snapshot recovery

The fourth credential-recovery job started normally at
`2026-08-02T06:15:01Z` on deploy commit
`e470d07285884ccc4604661bd7354b4021cc39c1`. Commit
`6f055ac4c21da635acd9a5fbdb0f2e2d31981b65` reached `origin/main` after
generation began. The old Worker freshness guard fetched the moving branch
tip at upload time and refused the unchanged checkout. Cloudflare was never
called, no candidate or promotion was created, and the previous verified
Worker remained at 100%. DigitalOcean still completed its independent hot
mirror. The final job row exited one in 998 seconds and reset the counter to
zero.

That behavior was safe but treated a normal branch update as if the selected
job checkout had mutated. Commit
`d0580c4da88c481f36606753276da31ff335b879` implements the immutable
deployment-checkout snapshot described above. Its regression coverage proves:

- A job-start-pinned checkout remains eligible after the remote branch
  advances.
- A mismatched pin or working-tree change fails before Wrangler.
- An unpinned manual promotion still fetches and requires current
  `origin/main`.
- A stale or dirty checkout cannot be pinned at job start, and a failed pin
  cannot leak a previous expected SHA.

The complete repository suite passed before deployment. The fix was pushed
and the production checkout was fast-forwarded while the scheduler was idle.
The authoritative marker and counter were then reset atomically at
`2026-08-02T06:41:22Z`; historical rows remain intact.

The first normal job from the new marker ran from `06:45:01Z` through
`07:04:42Z`. It pinned commit `d0580c4da88c481f36606753276da31ff335b879`
before generation, verified a unique immutable preview in 376 seconds,
completed DigitalOcean in 13 minutes 29 seconds, promoted exact version
`aa6c89b1-a27f-4781-9f7e-20e1716feb6e` at 100%, completed Pages maintenance,
and exited zero in 1,181 seconds. The immediate smoke audit passed production
root, search, custom 404, GPTBot, generated hashes, DigitalOcean hashes,
direct Pages hashes, daily R2 configuration/marker, and exact active-version
checks. Its only expected failure was the incomplete one-of-ten count.

### Daily backup critical path and retry-safe decoupling

The next scheduled job began at local midnight, so all four unchanged daily
backup policies became due at once. The job ran from `2026-08-02T07:15:01Z`
through `07:56:36Z`, exited zero, and completed every publication, immutable
preview, promotion, Pages maintenance, and backup operation. It nevertheless
took 2,495 seconds, failed the fixed 1,800-second cadence gate, reset the clean
counter to zero, and held the deployment lock across the `07:45Z` scheduler
slot.

The bounded log establishes the critical path rather than attributing the
delay to the Worker upload:

- R2 local and remote backups completed at `07:22:19Z` and `07:27:23Z`; R2
  required 8 minutes 43 seconds in total. Its already-current live-content
  marker correctly prevented a second August 2 live replication.
- The DigitalOcean local backup completed at `07:26:05Z`.
- The DigitalOcean remote snapshot then ran serially through `07:41:51Z`.
- Only after that remote snapshot did the every-build DigitalOcean live mirror
  run, completing at `07:54:39Z` after 35 minutes 59 seconds on the storage
  critical path.
- All four August 2 backup markers were current at completion. No backup was
  deleted, no configured retention was shortened, and no redundant storage
  copy was disabled.

Commit `739f2d58fcbaab87abf6e1e18a11aea72ca833da` preserves the same live
mirror, daily local backup, daily remote snapshot, integrity checks, and
retention while removing only the DigitalOcean remote snapshot from the
twice-hourly publication critical path:

- Normal publication keeps the DigitalOcean local backup inline. With
  `DO_REMOTE_BACKUP_INLINE=false`, it delegates only the remote snapshot to
  an independent retry runner and proceeds directly to the live mirror.
- `scripts/run-do-remote-backup.sh` runs hourly at minute 7. It is UTC-day
  idempotent: an already-current marker is a quiet no-op, while a failed or
  absent marker is retried at the next hourly slot.
- The independent snapshot uses 16 transfers, 32 checkers, a 30-operation/
  second limit, and burst 1. Normal DigitalOcean live publication retains 56
  transfers, 80 checkers, a 120-operation/second limit, burst 1, and isolated
  HTTP/1.1 connections.
- `/tmp/allium-do-spaces-io.lock` serializes the remote snapshot's object reads
  with live object mutation. Publication waits at most 180 seconds for that
  lock, so a stuck snapshot fails boundedly instead of consuming the complete
  scheduler interval. The two configured operation budgets never exceed the
  documented 150-operation/second optimization threshold when other safe
  local work overlaps.
- The independent runner uses the existing bounded-log helper with an 8 MiB
  active limit and two retained compressed archives. It writes one compact TSV
  row for an attempted snapshot and writes no noisy row for a same-day no-op.
- Tests cover normal-publication delegation, backup-only marker and throttle
  settings, the same-day no-op, bounded lock timeout, and bounded runner
  evidence. The complete repository test suite passed before activation.

Production was switched atomically while the scheduler was idle. The same-day
manual runner check left the August 2 marker unchanged and added no summary
row. The authoritative clean-window marker was then restarted at
`2026-08-02T08:04:11Z`, with all historical summaries preserved.

The first normal decoupled job ran from `08:15:01Z` through `08:33:29Z`. It
pinned commit `739f2d58fcbaab87abf6e1e18a11aea72ca833da`, skipped only already-
current daily backup/R2 live work, explicitly delegated the DigitalOcean
remote snapshot, and started the DigitalOcean live mirror immediately. That
mirror completed in 12 minutes 52 seconds instead of the preceding job's 35
minutes 59 seconds. The job verified immutable version
`f7c7244d-811d-4aa0-a45e-0c53d4545849` in three consecutive rounds, promoted
that exact version at 100%, completed Pages maintenance, and exited zero in
1,108 seconds with 692 seconds of cadence margin.

The immediate read-only smoke audit at `2026-08-02T08:33:57Z` passed every
production root, search, custom-404, GPTBot, generated-output hash,
DigitalOcean hot-mirror hash, direct Pages rollback hash, daily R2 marker, and
exact active-version check. Its sole expected nonzero condition was the new
window's intentionally incomplete one-of-ten count.

That window was later invalidated by an Allium generator failure described
below. Its historical rows remain intact but do not count toward the current
gate.

### Reused-output stale-page cleanup

The scheduled job beginning `2026-08-02T09:45:01Z` guardedly advanced the
Allium generator from `64d325be0f2af4943e233dabd5b1e0ce5286b7a0` to
`932d21f` and pinned deploy commit
`56e4048cd596e07992e4aa2e69d892ba7a399d29`. The generator failed discovery
validation in 248 seconds because the reused output tree still contained
`misc/contacts-by-unique-contact-count.html`, an old page with no canonical
link. The job stopped before Worker, DigitalOcean, R2, or Pages publication;
no candidate was uploaded or promoted, and the previous verified production
Worker remained active.

The upstream change intentionally stopped generating four unsupported misc
sort combinations but did not remove their base and paginated files from a
reused output directory. The validator was correct and was not weakened.
Allium commit `e829a5dd2f2431c1d09ef744cb4a5cc97970c9ca` adds a bounded,
explicit cleanup for only these obsolete combinations:

- contacts by unique-contact count;
- contacts by unique-family count;
- families by unique-contact count; and
- families by unique-family count.

Its regression fixture covers all four base files, their paginated descendants,
and supported neighboring files that must remain. The focused suite passed 27
tests. The complete non-slow Allium suite passed 1,132 tests with one skip and
55 explicitly deselected slow tests; critical lint, byte compilation, and
worktree-diff checks also passed.

A full manual generation then reused the actual `~/metrics-output` tree while
holding the normal deployment lock. It completed all 63 stages without calling
any publisher, generated 24,756 canonical sitemap URLs, and proved that all
four obsolete base files and every matching pagination descendant were absent.
The hosted Allium checkout was clean and exactly aligned with the hotfix SHA.

The counter and marker were reset atomically after that proof at
`2026-08-02T10:04:15Z`, preserving every historical summary row. Replacement
read-only one-shot audits target only this final window:

- Smoke, after ten natural scheduler jobs can finish:
  `2026-08-02T15:10:00Z`.
- Full 24-hour/48-job acceptance: `2026-08-03T10:10:00Z`.

Each new audit removes only its own uniquely tagged cron entry. The original
seven-day boundary remains `2026-08-04T02:56:35Z`.

The first normal post-hotfix job ran from `2026-08-02T10:15:01Z` through
`10:33:40Z`. It confirmed both repositories were already current, pinned
deploy commit `56e4048cd596e07992e4aa2e69d892ba7a399d29`, completed all 63
generator stages and discovery validation, and proved the cleanup under the
ordinary scheduled path. It uploaded and verified immutable version
`cce8e683-87af-4712-b21d-63db644f6a9d` at its version-specific preview URL in
368 seconds, promoted that exact version at 100%, completed the DigitalOcean
hot mirror in 12 minutes 21 seconds, and completed Pages rollback maintenance.
R2 skipped only its already-current daily live-content and backup operations.
The complete job exited zero in 1,119 seconds, leaving 681 seconds of cadence
margin and advancing the new counter to one.

The immediate lock-held audit at `2026-08-02T10:34:30Z` found one internally
consistent candidate, job, and promotion row with no row errors. Production
root, search, missing-path behavior, GPTBot access, generated hashes,
DigitalOcean hashes, direct Pages hashes, daily R2 configuration and marker,
and the exact active Worker version all passed. Both repository checkouts were
clean and aligned with their remotes, and all four local/DigitalOcean/R2
backup markers remained current for August 2. The audit's sole expected
nonzero condition was the intentionally incomplete one-of-ten smoke count.

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
DigitalOcean remains the approved every-build hot independent mirror. The live
transport combines the 120-transaction/second limiter with DigitalOcean-only
HTTP/1.1 connection isolation. The reviewed remote-backup decoupling preserves
the daily remote snapshot through an hourly retry-safe runner rather than
serializing it before the live mirror. The first job after activation recovered
1,387 seconds relative to the daily-backup job and restored 692 seconds of
scheduler margin, but the new 10-build and 24-hour window must prove that
result across complete changing builds and an independent snapshot retry. If a
later job crosses the limit, preserve the failed evidence and reassess the
bounded transport settings without reducing redundancy, changing retention,
or disabling integrity checks.

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
