import assert from 'node:assert/strict';
import test from 'node:test';

import { auditSoak } from '../scripts/audit-cfassets-soak.js';

const SHADOW_HEADER = 'timestamp_utc\tversion_id\tduration_seconds\tfile_count\tbyte_count\tpreview_url\tconsecutive_successes';
const JOB_HEADER = 'started_utc\tfinished_utc\texit_status\ttotal_duration_seconds\tcadence_ok\tshadow_counter';
function shadowRow(timestamp, version, duration, files, bytes, counter) {
  const preview = `https://${version.slice(0, 8)}-allium-stage2-worker.example.workers.dev`;
  return [timestamp, version, duration, files, bytes, preview, counter].join('\t');
}

function jobRow(started, finished, status, duration, cadence, counter) {
  return [started, finished, status, duration, cadence, counter].join('\t');
}

function validFixture() {
  return {
    shadowTsv: [
      SHADOW_HEADER,
      shadowRow('2026-07-26T19:54:56Z', '11111111-1111-4111-8111-111111111111', 345, 29675, 4656928482, 1),
      shadowRow('2026-07-26T20:27:17Z', '22222222-2222-4222-8222-222222222222', 485, 29669, 4656765442, 2),
      shadowRow('2026-07-26T20:56:28Z', '33333333-3333-4333-8333-333333333333', 464, 29759, 4628451832, 3),
    ].join('\n'),
    jobTsv: [
      JOB_HEADER,
      jobRow('2026-07-26T19:45:01Z', '2026-07-26T19:57:14Z', 0, 733, true, 1),
      jobRow('2026-07-26T20:15:01Z', '2026-07-26T20:29:38Z', 0, 877, true, 2),
      jobRow('2026-07-26T20:45:01Z', '2026-07-26T21:02:21Z', 0, 1040, true, 3),
    ].join('\n'),
    counter: '3',
    target: 3,
  };
}

test('accepts a complete sequential scheduled segment', () => {
  const report = auditSoak(validFixture());
  assert.equal(report.ok, true, report.errors.join('\n'));
  assert.deepEqual(report.progress, { current: 3, target: 3, complete: true });
  assert.equal(report.currentSegment.shadowRows, 3);
  assert.equal(report.currentSegment.jobRows, 3);
  assert.equal(report.currentSegment.uniqueVersionedPreviewUrls, 3);
  assert.deepEqual(report.currentSegment.totalJobDurationSeconds, { min: 733, max: 1040 });
});

test('defaults the formal Stage 2 gate to ten builds', () => {
  const fixture = validFixture();
  delete fixture.target;
  const report = auditSoak(fixture);
  assert.equal(report.ok, true, report.errors.join('\n'));
  assert.deepEqual(report.progress, { current: 3, target: 10, complete: false });
});

test('audits only the current suffix after an earlier reset', () => {
  const fixture = validFixture();
  const shadowLines = fixture.shadowTsv.split('\n');
  const jobLines = fixture.jobTsv.split('\n');
  const report = auditSoak({
    ...fixture,
    counter: '2',
    target: 100,
    shadowTsv: [
      ...shadowLines.slice(0, 3),
      shadowRow('2026-07-26T21:24:00Z', '44444444-4444-4444-8444-444444444444', 400, 29750, 4628000000, 1),
      shadowRow('2026-07-26T21:54:00Z', '55555555-5555-4555-8555-555555555555', 410, 29755, 4628100000, 2),
    ].join('\n'),
    jobTsv: [
      ...jobLines.slice(0, 3),
      jobRow('2026-07-26T20:45:01Z', '2026-07-26T20:46:01Z', 1, 60, true, 0),
      jobRow('2026-07-26T21:15:01Z', '2026-07-26T21:26:01Z', 0, 660, true, 1),
      jobRow('2026-07-26T21:45:01Z', '2026-07-26T21:56:01Z', 0, 660, true, 2),
    ].join('\n'),
  });
  assert.equal(report.ok, true, report.errors.join('\n'));
  assert.equal(report.currentSegment.firstStartedUtc, '2026-07-26T21:15:01Z');
  assert.equal(report.progress.complete, false);
});

test('rejects a missed scheduled slot', () => {
  const fixture = validFixture();
  fixture.jobTsv = fixture.jobTsv.replace('2026-07-26T20:45:01Z', '2026-07-26T21:15:01Z')
    .replace('2026-07-26T21:02:21Z', '2026-07-26T21:32:21Z');
  const report = auditSoak(fixture);
  assert.equal(report.ok, false);
  assert.match(report.errors.join('\n'), /scheduled-start spacing is 3600s/);
});

test('rejects a large unexplained prepared-byte discontinuity', () => {
  const fixture = validFixture();
  fixture.shadowTsv = fixture.shadowTsv.replace('4628451832', '3000000000');
  const report = auditSoak(fixture);
  assert.equal(report.ok, false);
  assert.match(report.errors.join('\n'), /byte-count delta .* exceeds 10%/);
});

test('rejects a whole-job failure even if a Worker row exists', () => {
  const fixture = validFixture();
  fixture.jobTsv = fixture.jobTsv.replace('\t0\t1040\ttrue\t3', '\t1\t1040\ttrue\t3');
  const report = auditSoak(fixture);
  assert.equal(report.ok, false);
  assert.match(report.errors.join('\n'), /exit status is 1/);
});

test('rejects a mutable preview alias in immutable-version evidence', () => {
  const fixture = validFixture();
  fixture.shadowTsv = fixture.shadowTsv.replace(
    'https://22222222-allium-stage2-worker.example.workers.dev',
    'https://allium-stage2-allium-stage2-worker.example.workers.dev',
  );
  const report = auditSoak(fixture);
  assert.equal(report.ok, false);
  assert.match(report.errors.join('\n'), /does not match the immutable Worker version prefix/);
});
