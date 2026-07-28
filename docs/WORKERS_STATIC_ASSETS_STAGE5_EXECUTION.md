# Workers Static Assets Stage 5 Execution Record

**Scope:** Prepare and test daily R2 live-content replication without changing
the active R2 cadence before the 24-hour production gate passes.

**Production hostname:** `https://metrics.1aeo.com`

**Worker:** `1aeo-metrics-assets-stage2`

**Implementation repository:** `1aeo/allium-deploy`

**Production checkout:** `/home/aeo1/allium-deploy` on `hostedopen`

**Status:** Implementation ready behind the safe `every-build` default. Stage
5 activation remains blocked until at least `2026-07-29T02:56:35Z` and until
all 24-hour acceptance checks pass. No R2 cadence, Pages, route, DNS, purge,
backup, or retention setting changed during preparation.

## Why Stage 5 has a separate 24-hour gate

Changing R2 live replication from every build to daily is reversible and does
not change the production serving path. Workers Static Assets remains
production, DigitalOcean remains a hot every-build mirror, Pages remains a
fresh rollback target, R2 remains a daily live recovery copy, and existing
daily backups continue independently. It is therefore reasonable to activate
Stage 5 after 24 healthy hours and at least 48 scheduled jobs while continuing
the broader seven-day production soak.

Retiring Pages or purge/rollback infrastructure is materially different and
remains blocked until at least `2026-08-04T02:56:35Z`. The dormant Pages
project should preferably remain available for a 14–30-day rollback window
before archival.

## Prepared implementation

`scripts/allium-deploy-upload-r2.sh` now supports:

- `R2_CONTENT_SYNC_INTERVAL=every-build|daily`, defaulting to `every-build` so
  deploying the code alone cannot reduce replication frequency.
- A UTC daily success marker at `logs/last-r2-content-sync-date`.
- Independent execution of the existing local and R2 backup steps before the
  live-content cadence decision. `DAILY_R2_BACKUP` is not reused as a
  live-content control.
- A live upload whenever the marker is missing or does not contain today's UTC
  date.
- Automatic retry on every subsequent twice-hourly run until upload and all
  validation pass.
- Atomic marker replacement only after successful upload and verification.
- `--force-content-sync [source_dir]` for recovery or pre-maintenance use. It
  bypasses a same-day marker but still runs the complete validation gate.
- `--force-backup [source_dir]` remains separate and does not implicitly
  override the live-content cadence.
- Strict interval validation; any value other than `every-build` or `daily`
  exits before synchronization.

Daily verification compares the generated output with the live R2 namespace
after excluding `_backups/**` and the Worker-only `_headers` file:

1. Exact object count.
2. Exact aggregate byte size.
3. SHA-256 downloaded from R2 for each configured representative object.

The default representative set is:

```text
index.html
search-index.json
1aeo.com/index.html
```

The list is configurable with `R2_CONTENT_VERIFY_PATHS`. A missing, empty,
absolute, or parent-traversing representative path fails verification. Missing
`jq` or `sha256sum`, an R2 listing failure, a source/remote count or size
mismatch, a read failure, or a hash mismatch prevents the success marker.

`scripts/audit-cfassets-stage4.js` provides the bounded 24-hour log gate. It
correlates `cfassets-stage2-job-summary.tsv`, `cfassets-shadow-summary.tsv`,
and `cfassets-promotion-summary.tsv` starting with the first Stage 4 cron job.
For each execution it requires:

- One successful scheduled job inside the 1,800-second cadence.
- One unique immutable candidate verified inside that job.
- One successful promotion of exactly that candidate version inside the same
  job.
- Sequential counters and approximately 1,800 seconds between cron starts.
- At least 48 executions and at least 86,400 elapsed seconds after the first
  promotion when `--require-complete` is used.

It emits only bounded aggregate JSON and does not add request logging.

## Failure behavior

| Condition | Daily marker | Next scheduled run | Production serving |
|---|---|---|---|
| Today's marker exists | Unchanged | Skip live R2 sync | Workers remains active |
| Upload succeeds and verification passes | Atomically set to today's UTC date | Skip until the next UTC day | Workers remains active |
| Upload fails | Not written for today | Retry live R2 sync | Workers and DO continue |
| Count or byte comparison fails | Not written for today | Retry live R2 sync | Workers and DO continue |
| Representative read or hash fails | Not written for today | Retry live R2 sync | Workers and DO continue |
| Invalid interval | Not written | Fail before sync until configuration is fixed | Existing Worker version remains active |
| Manual force succeeds | Set to today's UTC date | Resume normal cadence | Workers remains active |

The orchestrator continues reporting an R2 child failure separately. A
healthy verified Worker candidate is not replaced with an unverified version,
and an R2 failure does not redirect normal production traffic to R2.

## Test evidence

The canonical `pnpm test` suite includes deterministic Stage 5 behavior tests
that prove:

- A due daily run uploads, compares count/bytes, hashes every representative
  object, and writes today's UTC marker.
- A later same-day run performs no live sync or verification.
- Manual force bypasses the marker and still verifies.
- Upload failure propagates its status and writes no marker.
- Size mismatch and representative hash mismatch write no marker.
- A subsequent cron-style invocation retries and recovers.
- `every-build` mode ignores a daily marker and preserves the previous upload
  behavior without adding the daily verification work.
- Invalid interval values fail before synchronization.
- The Stage 4 audit accepts exact healthy candidate/promotion pairs, reports an
  insufficient time window as incomplete, and rejects mismatched versions,
  missed scheduler slots, and failed promotions.

At preparation time all 18 Node tests and every `tests/test-*.sh` behavioral
suite passed. The Stage 4 audit reported four aligned scheduled jobs, four
verified candidates, four successful exact-version promotions, no errors, and
a maximum whole-job duration of 1,434 seconds. The gate correctly remained
incomplete because only 6,392 seconds had elapsed.

## Safe deployment before the checkpoint

The preparation commit may be deployed to `hostedopen` before the checkpoint
only with `R2_CONTENT_SYNC_INTERVAL` absent or explicitly set to
`every-build`. The first scheduled run on that commit must demonstrate that:

- Workers upload, verification, and exact-version promotion still succeed.
- DO and R2 both still synchronize.
- R2 logs show `R2 live content synchronization is due (every-build)`.
- No `last-r2-content-sync-date` marker is required or written by compatibility
  mode.
- Pages purge and the whole-job summary still succeed inside the cadence.

This is a code-readiness deployment, not Stage 5 activation.

## 24-hour activation procedure

At or after `2026-07-29T02:56:35Z`:

1. Run `pnpm audit:cfassets-stage4 -- --started
   2026-07-28T02:45:01Z --minimum-jobs 48 --minimum-elapsed-seconds 86400
   --require-complete` against the production summaries.
2. Confirm all Stage 4 jobs and promotions since activation have zero status,
   unique matching version IDs, continuous scheduler slots, and durations no
   greater than 1,800 seconds.
3. Confirm the current Cloudflare deployment contains only the latest verified
   version at 100%.
4. Re-run production root, search index, nested HTML, `/search`, redirect,
   custom 404, cache/security-header, browser, and `GPTBot/1.0` checks. Confirm
   production remains indexable and static responses do not enter Worker code.
5. Confirm no new Pages purge 405 or other purge-control failure occurred.
6. Compare current generated-output, DO, and private R2 object counts, bytes,
   and representative SHA-256 values.
7. Confirm at least one local, DO, and R2 daily backup cycle completed and that
   no retention setting changed.
8. Review Workers request/invocation and current Cloudflare usage for an
   unexpected static-request or billing regression.
9. If every check passes, set only
   `R2_CONTENT_SYNC_INTERVAL=daily` in the mode-controlled host
   `config.env`. Do not change `R2_ENABLED`, `DAILY_R2_BACKUP`, DO, Pages,
   purge, route, DNS, or retention settings.
10. Run one explicit `--force-content-sync` against the current generated
    output. Require exact count/bytes and all representative hashes to pass,
    then confirm the marker contains today's UTC date.
11. Observe the next scheduled job. It must skip only the R2 live-content sync
    while Workers, DO, independent backup checks, promotion, Pages purge, and
    the whole-job summary continue normally.
12. Record exact evidence and the activation timestamp in this file and push
    it to `origin/main` as `1aeo <github@1aeo.com>`.

If any acceptance check fails, leave `R2_CONTENT_SYNC_INTERVAL=every-build`,
record the bounded failure, and continue Stage 4 without changing R2 cadence.

## Stage 5 rollback

Rollback is configuration-only:

1. Set `R2_CONTENT_SYNC_INTERVAL=every-build`.
2. Run `scripts/allium-deploy-upload-r2.sh --force-content-sync
   "$OUTPUT_DIR"`.
3. Require upload and representative verification to pass.
4. Confirm the next scheduled job again reports an every-build R2 sync.

The daily marker can remain in place because `every-build` mode ignores it.
Do not delete R2 content, backups, Pages, Worker versions, or DO objects during
this rollback.

## Path from Stage 5 to completion

After Stage 5 activates, continue the existing production soak through the
seven-day mark. Then complete the remaining plan in this order:

1. **Stage 6 — Permanent serving path.** Pass the seven-day health gate, stop
   Pages deployment and purge work, move `metrics.1aeo.com` from the temporary
   Worker route to a Worker Custom Domain, detach the Pages custom domain only
   after full production verification, keep the last Pages deployment dormant
   through the chosen 14–30-day rollback window, and make previous Worker
   version deployment the normal rollback. DO remains every-build and R2
   remains daily.
2. **Stage 7 — Security and explicit cleanup.** Revoke the temporary token
   that was posted in chat, issue a fresh least-privilege automation token,
   retain it only in the mode-`600` host credential file, remove only the
   enumerated staging Worker/deployment/directories after read-only target
   confirmation, add bounded deployment-log rotation, and update operating and
   disaster-recovery documentation. No bucket, backup collection, or broad
   directory deletion is authorized.
3. **Billing validation.** Compare one complete post-migration Cloudflare and
   DigitalOcean billing cycle with the June invoices. Record actual Workers,
   R2 Class A/Class B, R2 storage growth, DO storage, and DO bandwidth rather
   than relying only on the forecast.
4. **Stage 8 — Other projects.** Only after Allium is stable and its billing is
   understood, inventory and migrate non-Allium projects in priority order.
5. **Retention review under separate approval.** Inventory backup age, count,
   size, growth, and restore value; test restores from DO and R2; define RPO and
   RTO; then propose retention changes. Do not delete or shorten retention
   without explicit approval.

The Allium migration itself is complete when the permanent Worker Custom
Domain is healthy, Pages/purge are retired after their rollback window, DO and
R2 redundancy operate at their intended cadence, temporary credentials and
explicit experiment artifacts are cleaned up safely, recovery documentation
is current, and the first full billing-cycle comparison is recorded.
