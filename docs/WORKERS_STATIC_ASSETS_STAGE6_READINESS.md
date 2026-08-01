# Workers Static Assets Stage 6 readiness

## Status

Stage 6 tooling is implemented but dormant. It must not change production
until both independent gates pass:

1. The remediation smoke and full 24-hour audits pass with at least 10 and 48
   clean scheduled jobs respectively.
2. The original seven-day production boundary,
   `2026-08-04T02:56:35Z`, has passed.

Two initial jobs used unique immutable Worker preview URLs, promoted the exact
verified version, completed inside 1,800 seconds, and passed the subsequent
production, mirror, rollback, R2, hash, AI-indexing, and active-version audit.
That segment was then invalidated when `origin/main` advanced during a running
job and the promotion freshness guard correctly refused the stale checkout.
The authoritative clean-window marker restarted at
`2026-08-01T11:26:48Z` with a counter of zero. The failed row and earlier
evidence remain in the compact summaries but are outside the new audit window.
The count advances only through normal scheduled jobs; it is not accelerated
with synthetic uploads.

The current Cloudflare token can read DNS, Worker routes, and Worker Custom
Domains, but the Pages domains endpoint returns HTTP 403. Add account-level
**Cloudflare Pages / Edit** (called Pages Write by the API) to the existing
short-lived credential before Stage 6. Do not put the token in Git, this file,
or chat. A successful Pages `GET` proves API access but cannot itself prove the
destructive delete permission; the reviewed token setting remains required.

## Codebase and controls

All Stage 6 changes are in `1aeo/allium-deploy`:

- `scripts/run-stage6-worker-domain-cutover.sh` implements read-only preflight
  and the explicitly confirmed live transition.
- `scripts/run-cfassets-remediation-audit.sh` can reuse a deployment lock held
  by the Stage 6 caller, preventing a deadlock while retaining stable audit
  inputs.
- `scripts/allium-deploy-update.sh` has one
  `PAGES_ROLLBACK_MAINTENANCE_ENABLED` gate for both schema-triggered Pages
  deployments and the Pages purge loop.
- `config.env.example` documents that the gate stays `true` through the route
  soak and becomes `false` only after the Worker Custom Domain passes the full
  health gate.
- `tests/test-stage6-cutover.sh` covers safe input and date gates, exact
  control-plane shape, stale-safe atomic configuration, reviewed mutation
  ordering, and route/CNAME rollback paths.

The new runtime setting defaults to `true`, so deploying the code cannot retire
Pages or change current behavior. Production `config.env` must contain exactly
one explicit `PAGES_ROLLBACK_MAINTENANCE_ENABLED=true` line before cutover.

## Read-only preflight

Run from the current clean hostedopen checkout:

```bash
scripts/run-stage6-worker-domain-cutover.sh --preflight
```

Preflight never sends a mutating API request. It requires and checks:

- `SITE_URL` is exactly the HTTPS production root.
- Safe, exact zone, hostname, Worker, Pages project, CNAME target, and route
  pattern values.
- A clean checkout exactly matching `origin/main`.
- The seven-day boundary.
- The complete post-remediation 10-build and 24-hour acceptance audit.
- Exactly one proxied production CNAME to the Pages hostname and no second DNS
  record for the production name.
- The zone route set contains exactly one route:
  `metrics.1aeo.com/*` to the approved Worker. Any additional route requires a
  separate review before cutover because it could obscure Custom Domain proof.
- No existing Worker Custom Domain for the hostname.
- Exactly one production-domain association on the approved Pages project.
- Exactly one explicit, enabled Pages rollback-maintenance setting.

The known pre-cutover control-plane shape is:

- Proxied CNAME `metrics.1aeo.com -> 1aeo-metrics.pages.dev`.
- Worker route `metrics.1aeo.com/* -> 1aeo-metrics-assets-stage2`.
- No Worker Custom Domain for `metrics.1aeo.com`.
- Pages retains `metrics.1aeo.com` plus its direct `pages.dev` address.

Any missing, duplicated, stale, already-migrated, or unexpected object fails
closed before mutation.

## Reviewed live sequence

Live execution requires both the command mode and an exact hostname
confirmation:

```bash
STAGE6_CONFIRM_CUTOVER=metrics.1aeo.com \
  scripts/run-stage6-worker-domain-cutover.sh --execute
```

The tool acquires the same deployment lock as the twice-hourly job and then
re-runs the complete acceptance audit while holding that lock. It performs this
sequence:

1. Re-resolve the account and zone and repeat the exact control-plane checks.
2. Write a mode-`600`, local, ignored JSON snapshot containing the exact DNS,
   route, Worker-domain, Pages-domain, checkout, and direct rollback state.
3. Delete only the resolved Pages CNAME record. A Worker Custom Domain cannot
   be attached while that CNAME exists.
4. Attach `metrics.1aeo.com` to the approved Worker through the account Worker
   Domains API. Keep the broad Worker route during DNS/certificate convergence.
5. Repeatedly confirm the exact domain object and run the complete health audit
   while the route still protects production. Because a route takes precedence
   over a Custom Domain, this step proves continuity, not yet the new origin.
6. Delete only the exact resolved broad route.
7. Require three consecutive complete audits with the route absent and the
   exact Worker Custom Domain present. These checks prove the Custom Domain is
   now the serving origin. They include root `200`, search `302`, missing-path
   `404`, GPTBot `200`, generated-output hashes, DO mirror hashes, direct Pages
   rollback hashes, daily R2 marker, and the exact active Worker version at
   100%.
8. Detach only `metrics.1aeo.com` from the approved Pages project, leaving the
   direct Pages deployment and project intact.
9. Repeat the full health audit.
10. Atomically change the one Pages rollback-maintenance setting from `true` to
    `false`, preserving `config.env` permissions and every other value. Future
    scheduled jobs continue Worker upload/verification/promotion, DO every-build
    mirroring, R2 daily replication, backups, and verification, but skip Pages
    schema deployment and the approximately 29,000-URL purge loop.
11. Write a compact local completion marker identifying the domain, Worker, and
    pre-cutover snapshot.

No R2, DigitalOcean, backup, retention, Worker-version, or AI-crawler policy is
changed.

## Failure behavior and rollback

Every mutation uses object IDs selected from the exact preflight state:

- If CNAME deletion succeeds but domain attachment fails, the tool recreates
  the exact proxied Pages CNAME with bounded retries. The Worker route was never
  removed.
- If attachment succeeds but continuity fails before route deletion, the tool
  detaches that exact new Worker domain and restores the Pages CNAME.
- If any check fails after route deletion, the tool recreates the exact broad
  Worker route immediately. The Worker Custom Domain remains available for
  diagnosis, and production continues through the known Worker version.
- Promotion remains a separate every-build fail-closed process; Stage 6 does
  not deploy or promote a Worker version.
- Pages maintenance is disabled only after route-free Custom Domain health,
  Pages detachment, and another complete audit.

Automatic rollback deliberately prefers the smallest availability-restoring
change. It does not delete the Pages project, Pages deployment, Worker, Worker
versions, mirrors, buckets, backups, or retained objects.

## After successful Stage 6

Keep the final direct Pages deployment dormant for the selected 14–30-day
rollback window. During that period:

- Normal rollback is the previous known-good Worker version.
- The direct Pages URL remains available for explicit disaster-recovery checks,
  but receives no production hostname traffic and no recurring purge work.
- Do not archive or delete the Pages project until the rollback window is
  separately accepted.
- Do not begin backup deletion or retention reduction.

Stage 7 then rotates the exposed short-lived Cloudflare token, removes only the
enumerated experiment artifacts after resolving each target, finishes recovery
documentation, and compares a complete post-migration billing cycle. Stage 8
begins non-Allium work only after those Allium gates are complete.

## Cloudflare references

- [Worker Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)
- [Attach Worker Domain API](https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/update/)
- [Create Worker Route API](https://developers.cloudflare.com/api/resources/workers/subresources/routes/methods/create/)
- [Delete Worker Route API](https://developers.cloudflare.com/api/resources/workers/subresources/routes/methods/delete/)
- [Delete DNS Record API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/delete/)
- [Detach Pages Domain API](https://developers.cloudflare.com/api/resources/pages/subresources/projects/subresources/domains/methods/delete/)
