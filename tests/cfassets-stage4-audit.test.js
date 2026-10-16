import assert from 'node:assert/strict';
import test from 'node:test';

import { auditStage4 } from '../scripts/audit-cfassets-stage4.js';

const JOB_HEADER = 'started_utc\tfinished_utc\texit_status\ttotal_duration_seconds\tcadence_ok\tshadow_counter';
const SHADOW_HEADER = 'timestamp_utc\tversion_id\tduration_seconds\tfile_count\tbyte_count\tpreview_url\tconsecutive_successes';
const PROMOTION_HEADER = 'timestamp_utc\tversion_id\texit_status';
const VERSION_1 = '11111111-1111-4111-8111-111111111111';
const VERSION_2 = '22222222-2222-4222-8222-222222222222';

function fixture() {
  return {
    jobsTsv: [
      JOB_HEADER,
      '2026-07-28T02:45:01Z\t2026-07-28T02:59:01Z\t0\t840\ttrue\t13',
      '2026-07-28T03:15:01Z\t2026-07-28T03:29:01Z\t0\t840\ttrue\t14',
    ].join('\n'),
    shadowTsv: [
      SHADOW_HEADER,
      `2026-07-28T02:56:30Z\t${VERSION_1}\t480\t29473\t4451771979\thttps://preview.example.workers.dev\t13`,
      `2026-07-28T03:26:30Z\t${VERSION_2}\t480\t29467\t4451749218\thttps://preview.example.workers.dev\t14`,
    ].join('\n'),
    promotionsTsv: [
      PROMOTION_HEADER,
      `2026-07-28T02:56:35Z\t${VERSION_1}\t0`,
      `2026-07-28T03:26:35Z\t${VERSION_2}\t0`,
    ].join('\n'),
    startedUtc: '2026-07-28T02:45:01Z',
    nowUtc: '2026-07-28T03:56:35Z',
    minimumJobs: 2,
    minimumElapsedSeconds: 3600,
  };
}

test('accepts a complete Stage 4 window with exact candidate promotions', () => {
  const report = auditStage4(fixture());
  assert.equal(report.ok, true, report.errors.join('\n'));
  assert.equal(report.progress.complete, true);
  assert.equal(report.progress.jobs, 2);
  assert.equal(report.progress.successfulPromotions, 2);
});

test('reports an otherwise healthy window as incomplete before the time gate', () => {
  const input = fixture();
  input.nowUtc = '2026-07-28T03:26:34Z';
  const report = auditStage4(input);
  assert.equal(report.ok, true, report.errors.join('\n'));
  assert.equal(report.progress.complete, false);
});

test('rejects a promotion that does not match the verified candidate', () => {
  const input = fixture();
  input.promotionsTsv = input.promotionsTsv.replace(VERSION_2, '33333333-3333-4333-8333-333333333333');
  const report = auditStage4(input);
  assert.equal(report.ok, false);
  assert.match(report.errors.join('\n'), /promoted version does not match/);
});

test('rejects a missed scheduler slot and failed promotion', () => {
  const input = fixture();
  input.jobsTsv = input.jobsTsv.replace('2026-07-28T03:15:01Z', '2026-07-28T03:45:01Z')
    .replace('2026-07-28T03:29:01Z', '2026-07-28T03:59:01Z');
  input.shadowTsv = input.shadowTsv.replace('2026-07-28T03:26:30Z', '2026-07-28T03:56:30Z');
  input.promotionsTsv = input.promotionsTsv.replace('2026-07-28T03:26:35Z', '2026-07-28T03:56:35Z')
    .replace(`${VERSION_2}\t0`, `${VERSION_2}\t1`);
  const report = auditStage4(input);
  assert.equal(report.ok, false);
  assert.match(report.errors.join('\n'), /scheduled-start spacing is 3600s/);
  assert.match(report.errors.join('\n'), /promotion exit status is 1/);
});
