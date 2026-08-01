# Workers Static Assets reliability remediation

## Status

The post-Stage-5 reliability remediation was activated at
`2026-08-01T09:57:20Z` from commit `efc650d547f04b66a1e039e7411a504594cd8d9a`.
Production routing, the active Worker deployment, Pages, DigitalOcean, R2,
backup cadence, and retention were not changed during activation.

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

## Fresh validation gates

Activation reset only `logs/cfassets-shadow-consecutive-successes` to zero and
wrote `logs/cfassets-remediation-start-utc`. Existing historical summaries were
not truncated or rewritten.

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

No Pages project deletion, backup deletion, or retention reduction is part of
this remediation or its validation.
