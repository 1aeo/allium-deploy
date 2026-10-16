# Workers Static Assets Stage 5 activation result

**Activated UTC:** 2026-07-29T06:27:59Z

**Status:** Passed. R2 live-content replication is daily. Workers Static
Assets remains production, DigitalOcean remains an every-build mirror, daily
backup behavior is unchanged, and Pages remains the current rollback target.

## Gated evidence

- The read-only 24-hour audit passed after the formal checkpoint with at least
  48 complete candidate, promotion, production, mirror, and backup checks.
- Audit log SHA-256: `df1e6d7a260aaf8e203ce25a3ca9c58eb44e20dc9b1e360d36f84275f0c7b816`.
- Only `R2_CONTENT_SYNC_INTERVAL` changed, from `every-build` to `daily`.
- A forced R2 live sync completed count, byte, and representative-hash
  verification before writing the UTC marker `2026-07-29`.
- Force-sync log SHA-256: `aaf349c92d778e387e539728a432ae6348e993ab6b53181b6774473d3068c48c`.
- The following normal cron job completed successfully after activation:

  `2026-07-29T06:45:01Z	2026-07-29T06:57:44Z	0	763	true	69`

- That job skipped only R2 live content. DO mirroring, Workers candidate
  upload and preview verification, exact-version promotion, the retained Pages
  rollback purge, and the whole-job success record all completed.
- Post-job production root, search index, search redirect, custom 404, GPTBot
  access, and representative hashes passed.
- No route, DNS, Pages, purge, backup, or retention setting changed.

## Rollback

Set `R2_CONTENT_SYNC_INTERVAL=every-build`, force and verify one R2 content
sync, and confirm the following normal job performs an every-build R2 sync.
No object or backup deletion is part of rollback.

**Activation runner checkout before evidence commit:** `7791a3b25468a030a24433cb8e4aa076d9cf1afc`.
